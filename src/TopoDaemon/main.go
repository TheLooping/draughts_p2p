package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	h "github.com/hashicorp/hyparview"
)

const (
	defaultSnapshotLimit      = 10
	defaultShuffleIntervalMs  = 30000
	defaultKeepaliveIntervalMs = 8000
	defaultJoinRetryMs        = 1200
)

type Config struct {
	PeerID              string   `json:"peer_id"`
	ListenAddr          string   `json:"listen_addr"`
	IPCSocket           string   `json:"ipc_socket"`
	PeerInfoDir         string   `json:"peer_info_dir"`
	SnapshotLimit       int      `json:"snapshot_limit"`
	ShuffleIntervalMs   int      `json:"shuffle_interval_ms"`
	KeepaliveIntervalMs int      `json:"keepalive_interval_ms"`
	JoinRetryMs         int      `json:"join_retry_ms"`
	Bootstrap           []string `json:"bootstrap"`
}

type PeerInfo struct {
	PeerID       string
	BindIP       string
	OverlayPort  int
	DraughtsPort int
	PubKey       string
	TopodAddr    string
}

func (p PeerInfo) DraughtsIP() string {
	if p.BindIP == "" || p.DraughtsPort == 0 {
		return ""
	}
	return p.BindIP
}

type SnapshotNeighbor struct {
	PeerID string `json:"peer_id"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	PubKey string `json:"pubkey"`
}

type SnapshotRecord struct {
	PeerID      string             `json:"peer_id"`
	Term        uint64             `json:"term"`
	TimestampMs int64              `json:"timestamp_ms"`
	Neighbors   []SnapshotNeighbor `json:"neighbors"`
}

type wireMessage struct {
	Kind     string         `json:"kind"`
	From     string         `json:"from,omitempty"`
	To       string         `json:"to,omitempty"`
	Join     string         `json:"join,omitempty"`
	Origin   string         `json:"origin,omitempty"`
	TTL      int            `json:"ttl,omitempty"`
	Priority bool           `json:"priority,omitempty"`
	Active   []string       `json:"active,omitempty"`
	Passive  []string       `json:"passive,omitempty"`
	Snapshot *SnapshotRecord `json:"snapshot,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

type hvTransport struct {
	daemon *TopoDaemon
}

func (t *hvTransport) Send(m h.Message) (*h.NeighborRefuse, error) {
	req, err := t.daemon.encodeMembershipMessage(m)
	if err != nil {
		return nil, err
	}
	resp, err := t.daemon.exchangeOverlay(m.To().Addr(), req)
	if err != nil {
		return nil, err
	}
	if resp.Kind == "neighbor_refuse" {
		return h.NewNeighborRefuse(m.From(), m.To()), nil
	}
	return nil, nil
}

func (t *hvTransport) Failed(n h.Node) {
	t.daemon.logger.Printf("warn: overlay send failed, marking %s as failed", n.Addr())
}

func (t *hvTransport) Bootstrap() h.Node {
	return t.daemon.pickBootstrapNode()
}

type TopoDaemon struct {
	cfg          Config
	logger       *log.Logger
	selfNode     h.Node
	peersByID    map[string]PeerInfo
	peersByTopo  map[string]PeerInfo

	mu           sync.Mutex
	randMu       sync.Mutex
	rng          *rand.Rand
	hv           *h.Hyparview
	term         uint64
	history      map[string][]SnapshotRecord

	overlayLn    net.Listener
	ipcLn        net.Listener
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
}

func loadConfig(path string) (Config, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{}
	if err := json.Unmarshal(bs, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.SnapshotLimit <= 0 {
		cfg.SnapshotLimit = defaultSnapshotLimit
	}
	if cfg.ShuffleIntervalMs <= 0 {
		cfg.ShuffleIntervalMs = defaultShuffleIntervalMs
	}
	if cfg.KeepaliveIntervalMs <= 0 {
		cfg.KeepaliveIntervalMs = defaultKeepaliveIntervalMs
	}
	if cfg.JoinRetryMs <= 0 {
		cfg.JoinRetryMs = defaultJoinRetryMs
	}
	cfg.PeerID = strings.TrimSpace(cfg.PeerID)
	cfg.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	cfg.IPCSocket = strings.TrimSpace(cfg.IPCSocket)
	cfg.PeerInfoDir = strings.TrimSpace(cfg.PeerInfoDir)
	if cfg.PeerID == "" {
		return Config{}, errors.New("peer_id is required")
	}
	if cfg.ListenAddr == "" {
		return Config{}, errors.New("listen_addr is required")
	}
	if cfg.IPCSocket == "" {
		return Config{}, errors.New("ipc_socket is required")
	}
	if cfg.PeerInfoDir == "" {
		return Config{}, errors.New("peer_info_dir is required")
	}
	return cfg, nil
}

func parsePeerInfo(path string) (PeerInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return PeerInfo{}, err
	}
	defer f.Close()

	out := PeerInfo{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "peer_id":
			out.PeerID = val
		case "bind_ip":
			out.BindIP = val
		case "overlay_port":
			v, _ := strconv.Atoi(val)
			out.OverlayPort = v
		case "draughts_port":
			v, _ := strconv.Atoi(val)
			out.DraughtsPort = v
		case "pubkey":
			out.PubKey = val
		case "topod_addr":
			out.TopodAddr = val
		}
	}
	if err := s.Err(); err != nil {
		return PeerInfo{}, err
	}
	if out.PeerID == "" || out.BindIP == "" || out.DraughtsPort == 0 {
		return PeerInfo{}, fmt.Errorf("invalid peer info file: %s", path)
	}
	if out.TopodAddr == "" && out.OverlayPort > 0 {
		out.TopodAddr = fmt.Sprintf("%s:%d", out.BindIP, out.OverlayPort+2000)
	}
	return out, nil
}

func loadPeerInfoDir(dir string) (map[string]PeerInfo, map[string]PeerInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]PeerInfo)
	byTopo := make(map[string]PeerInfo)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		info, err := parsePeerInfo(path)
		if err != nil {
			continue
		}
		byID[info.PeerID] = info
		if info.TopodAddr != "" {
			byTopo[info.TopodAddr] = info
		}
	}
	if len(byID) == 0 {
		return nil, nil, fmt.Errorf("no peer info loaded from %s", dir)
	}
	return byID, byTopo, nil
}

func newTopoDaemon(cfg Config, peersByID map[string]PeerInfo, peersByTopo map[string]PeerInfo, logger *log.Logger) *TopoDaemon {
	d := &TopoDaemon{
		cfg:         cfg,
		logger:      logger,
		selfNode:    h.NewNode(cfg.ListenAddr),
		peersByID:   peersByID,
		peersByTopo: peersByTopo,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		history:     make(map[string][]SnapshotRecord),
		stopCh:      make(chan struct{}),
	}
	transport := &hvTransport{daemon: d}
	d.hv = h.CreateView(transport, d.selfNode, maxInt(32, len(peersByID)+8))
	d.hv.Active.Max = maxInt(3, minInt(8, len(peersByID)-1))
	d.hv.Passive.Max = maxInt(8, minInt(64, len(peersByID)*2))
	return d
}

func (d *TopoDaemon) Start() error {
	ln, err := net.Listen("tcp", d.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("overlay listen failed: %w", err)
	}
	d.overlayLn = ln

	if err := os.MkdirAll(filepath.Dir(d.cfg.IPCSocket), 0o755); err != nil {
		return fmt.Errorf("mkdir ipc dir failed: %w", err)
	}
	_ = os.Remove(d.cfg.IPCSocket)
	ipcLn, err := net.Listen("unix", d.cfg.IPCSocket)
	if err != nil {
		return fmt.Errorf("ipc listen failed: %w", err)
	}
	d.ipcLn = ipcLn

	d.wg.Add(5)
	go d.acceptOverlayLoop()
	go d.acceptIPCLoop()
	go d.bootstrapLoop()
	go d.shuffleLoop()
	go d.keepaliveLoop()

	return nil
}

func (d *TopoDaemon) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		if d.overlayLn != nil {
			_ = d.overlayLn.Close()
		}
		if d.ipcLn != nil {
			_ = d.ipcLn.Close()
		}
		_ = os.Remove(d.cfg.IPCSocket)
	})
	d.wg.Wait()
}

func (d *TopoDaemon) isStopping() bool {
	select {
	case <-d.stopCh:
		return true
	default:
		return false
	}
}

func (d *TopoDaemon) acceptOverlayLoop() {
	defer d.wg.Done()
	for {
		conn, err := d.overlayLn.Accept()
		if err != nil {
			if d.isStopping() {
				return
			}
			d.logger.Printf("warn: overlay accept error: %v", err)
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleOverlayConn(conn)
		}()
	}
}

func (d *TopoDaemon) handleOverlayConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)

	var req wireMessage
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(wireMessage{Kind: "err", Reason: "bad_request"})
		return
	}

	resp := d.handleOverlayMessage(req)
	_ = enc.Encode(resp)
}

func (d *TopoDaemon) handleOverlayMessage(req wireMessage) wireMessage {
	switch req.Kind {
	case "snapshot":
		if req.Snapshot != nil {
			d.storeSnapshot(*req.Snapshot)
		}
		return wireMessage{Kind: "ack", From: d.cfg.ListenAddr}
	default:
		msg, err := d.decodeMembershipMessage(req)
		if err != nil {
			return wireMessage{Kind: "err", Reason: "decode_failed"}
		}
		refuse := d.recvMembership(msg)
		if refuse != nil {
			return wireMessage{Kind: "neighbor_refuse", From: d.cfg.ListenAddr}
		}
		return wireMessage{Kind: "ack", From: d.cfg.ListenAddr}
	}
}

func (d *TopoDaemon) acceptIPCLoop() {
	defer d.wg.Done()
	for {
		conn, err := d.ipcLn.Accept()
		if err != nil {
			if d.isStopping() {
				return
			}
			d.logger.Printf("warn: ipc accept error: %v", err)
			continue
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleIPCConn(conn)
		}()
	}
}

func (d *TopoDaemon) handleIPCConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	resp := d.handleIPCRequest(line)
	_, _ = io.WriteString(conn, resp+"\n")
}

func parseKV(tokens []string) map[string]string {
	out := make(map[string]string)
	for _, tok := range tokens {
		idx := strings.IndexByte(tok, '=')
		if idx <= 0 || idx+1 >= len(tok) {
			continue
		}
		key := strings.TrimSpace(tok[:idx])
		val := strings.TrimSpace(tok[idx+1:])
		out[key] = val
	}
	return out
}

func (d *TopoDaemon) handleIPCRequest(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "ERR reason=empty_request"
	}
	cmd := strings.ToUpper(fields[0])
	kv := parseKV(fields[1:])

	switch cmd {
	case "STATE":
		term, active := d.getState()
		return fmt.Sprintf("OK term=%d active=%s", term, strings.Join(active, ","))

	case "PLAN":
		exclude := kv["exclude"]
		plan, reason, ok := d.planRoute(exclude)
		if !ok {
			return "ERR reason=" + reason
		}
		return fmt.Sprintf("OK term=%d nh_id=%s nh_ip=%s nh_port=%d nh_pub=%s nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
			plan.Term,
			plan.NH.PeerID, plan.NH.DraughtsIP(), plan.NH.DraughtsPort, plan.NH.PubKey,
			plan.NNH.PeerID, plan.NNH.IP, plan.NNH.Port, plan.NNH.PubKey)

	case "HISTORY":
		peerID := kv["peer"]
		if peerID == "" {
			return "ERR reason=missing_peer"
		}
		term, err := strconv.ParseUint(kv["term"], 10, 64)
		if err != nil {
			return "ERR reason=bad_term"
		}
		exclude := kv["exclude"]
		strict := kv["strict"] == "1" || strings.EqualFold(kv["strict"], "true")

		nnh, reason, found := d.lookupHistoryNeighbor(peerID, term, exclude, strict)
		if !found {
			if reason == "term_not_found" {
				return "NOT_FOUND reason=" + reason
			}
			return "ERR reason=" + reason
		}
		return fmt.Sprintf("OK term=%d nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
			term, nnh.PeerID, nnh.IP, nnh.Port, nnh.PubKey)

	default:
		return "ERR reason=unknown_command"
	}
}

type RoutePlan struct {
	Term uint64
	NH   PeerInfo
	NNH  SnapshotNeighbor
}

func (d *TopoDaemon) getState() (uint64, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	active := d.activePeerIDsLocked("")
	return d.term, active
}

func (d *TopoDaemon) planRoute(exclude string) (RoutePlan, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	nhCandidates := d.activePeerInfosLocked(exclude)
	if len(nhCandidates) == 0 {
		return RoutePlan{}, "no_active_neighbor", false
	}
	nh := nhCandidates[d.randIntn(len(nhCandidates))]

	hist := d.history[nh.PeerID]
	if len(hist) == 0 {
		return RoutePlan{}, "no_snapshot_for_nh", false
	}
	latest := hist[len(hist)-1]

	cands := filterSnapshotNeighbors(latest.Neighbors, d.cfg.PeerID, nh.PeerID, exclude)
	if len(cands) == 0 {
		return RoutePlan{}, "no_nnh_candidate", false
	}
	nnh := cands[d.randIntn(len(cands))]
	if nnh.IP == "" || nnh.Port == 0 || nnh.PubKey == "" {
		return RoutePlan{}, "invalid_nnh_record", false
	}

	if nh.DraughtsIP() == "" || nh.DraughtsPort == 0 || nh.PubKey == "" {
		return RoutePlan{}, "invalid_nh_record", false
	}

	return RoutePlan{Term: latest.Term, NH: nh, NNH: nnh}, "", true
}

func (d *TopoDaemon) lookupHistoryNeighbor(peerID string, term uint64, exclude string, strict bool) (SnapshotNeighbor, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	hist := d.history[peerID]
	if len(hist) == 0 {
		return SnapshotNeighbor{}, "term_not_found", false
	}

	var rec *SnapshotRecord
	for i := range hist {
		if hist[i].Term == term {
			rec = &hist[i]
			break
		}
	}
	if rec == nil {
		return SnapshotNeighbor{}, "term_not_found", false
	}

	cands := filterSnapshotNeighbors(rec.Neighbors, d.cfg.PeerID, peerID, exclude)
	if len(cands) == 0 {
		if strict {
			return SnapshotNeighbor{}, "no_nnh_candidate", false
		}
		fallback := d.activePeerInfosLocked(exclude)
		out := make([]SnapshotNeighbor, 0, len(fallback))
		for _, p := range fallback {
			if p.PeerID == peerID || p.PeerID == d.cfg.PeerID {
				continue
			}
			if p.DraughtsIP() == "" || p.DraughtsPort == 0 || p.PubKey == "" {
				continue
			}
			out = append(out, SnapshotNeighbor{
				PeerID: p.PeerID,
				IP:     p.DraughtsIP(),
				Port:   p.DraughtsPort,
				PubKey: p.PubKey,
			})
		}
		if len(out) == 0 {
			return SnapshotNeighbor{}, "no_nnh_candidate", false
		}
		return out[d.randIntn(len(out))], "", true
	}

	return cands[d.randIntn(len(cands))], "", true
}

func filterSnapshotNeighbors(list []SnapshotNeighbor, selfID string, ownerID string, exclude string) []SnapshotNeighbor {
	out := make([]SnapshotNeighbor, 0, len(list))
	for _, n := range list {
		if n.PeerID == "" || n.IP == "" || n.Port == 0 || n.PubKey == "" {
			continue
		}
		if n.PeerID == selfID || n.PeerID == ownerID {
			continue
		}
		if exclude != "" && n.PeerID == exclude {
			continue
		}
		out = append(out, n)
	}
	return out
}

func (d *TopoDaemon) randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	d.randMu.Lock()
	defer d.randMu.Unlock()
	return d.rng.Intn(n)
}

func (d *TopoDaemon) activePeerInfosLocked(exclude string) []PeerInfo {
	out := make([]PeerInfo, 0, len(d.hv.Active.Nodes))
	for _, n := range d.hv.Active.Nodes {
		info, ok := d.peersByTopo[n.Addr()]
		if !ok {
			continue
		}
		if exclude != "" && info.PeerID == exclude {
			continue
		}
		out = append(out, info)
	}
	return out
}

func (d *TopoDaemon) activePeerIDsLocked(exclude string) []string {
	items := d.activePeerInfosLocked(exclude)
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.PeerID)
	}
	sort.Strings(ids)
	return ids
}

func (d *TopoDaemon) activeAddrsLocked() []string {
	out := make([]string, 0, len(d.hv.Active.Nodes))
	for _, n := range d.hv.Active.Nodes {
		if n == nil || n.Addr() == "" {
			continue
		}
		out = append(out, n.Addr())
	}
	sort.Strings(out)
	return out
}

func (d *TopoDaemon) activeSignatureLocked() string {
	return strings.Join(d.activeAddrsLocked(), ",")
}

func (d *TopoDaemon) appendHistoryLocked(peerID string, rec SnapshotRecord) {
	list := d.history[peerID]
	if len(list) > 0 && list[len(list)-1].Term == rec.Term {
		list[len(list)-1] = rec
		d.history[peerID] = list
		return
	}
	list = append(list, rec)
	if len(list) > d.cfg.SnapshotLimit {
		list = list[len(list)-d.cfg.SnapshotLimit:]
	}
	d.history[peerID] = list
}

func (d *TopoDaemon) buildLocalSnapshotLocked() SnapshotRecord {
	neighbors := make([]SnapshotNeighbor, 0, len(d.hv.Active.Nodes))
	for _, n := range d.hv.Active.Nodes {
		if n == nil {
			continue
		}
		info, ok := d.peersByTopo[n.Addr()]
		if !ok {
			continue
		}
		neighbors = append(neighbors, SnapshotNeighbor{
			PeerID: info.PeerID,
			IP:     info.DraughtsIP(),
			Port:   info.DraughtsPort,
			PubKey: info.PubKey,
		})
	}
	sort.Slice(neighbors, func(i, j int) bool {
		return neighbors[i].PeerID < neighbors[j].PeerID
	})
	return SnapshotRecord{
		PeerID:      d.cfg.PeerID,
		Term:        d.term,
		TimestampMs: time.Now().UnixMilli(),
		Neighbors:   neighbors,
	}
}

func (d *TopoDaemon) storeSnapshot(rec SnapshotRecord) {
	if rec.PeerID == "" {
		return
	}
	if rec.Term == 0 {
		return
	}
	d.mu.Lock()
	d.appendHistoryLocked(rec.PeerID, rec)
	d.mu.Unlock()
}

func (d *TopoDaemon) recvMembership(msg h.Message) *h.NeighborRefuse {
	var refuse *h.NeighborRefuse
	changed, snapshot, targets := d.applyMutation(func() {
		refuse = d.hv.Recv(msg)
	})
	if changed {
		d.broadcastSnapshot(snapshot, targets)
	}
	return refuse
}

func (d *TopoDaemon) applyMutation(fn func()) (bool, SnapshotRecord, []string) {
	d.mu.Lock()
	before := d.activeSignatureLocked()
	fn()
	after := d.activeSignatureLocked()
	if before == after {
		d.mu.Unlock()
		return false, SnapshotRecord{}, nil
	}
	d.term++
	snapshot := d.buildLocalSnapshotLocked()
	d.appendHistoryLocked(d.cfg.PeerID, snapshot)
	targets := d.activeAddrsLocked()
	d.mu.Unlock()
	return true, snapshot, targets
}

func (d *TopoDaemon) broadcastSnapshot(snapshot SnapshotRecord, targets []string) {
	req := wireMessage{
		Kind:     "snapshot",
		From:     d.cfg.ListenAddr,
		Snapshot: &snapshot,
	}
	for _, addr := range targets {
		if addr == "" || addr == d.cfg.ListenAddr {
			continue
		}
		if _, err := d.exchangeOverlay(addr, req); err != nil {
			d.logger.Printf("warn: snapshot broadcast to %s failed: %v", addr, err)
		}
	}
}

func (d *TopoDaemon) bootstrapLoop() {
	defer d.wg.Done()
	t := time.NewTicker(time.Duration(d.cfg.JoinRetryMs) * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.mu.Lock()
			empty := d.hv.Active.IsEmpty()
			d.mu.Unlock()
			if !empty {
				continue
			}
			boot := d.pickBootstrapNode()
			if boot == nil {
				continue
			}
			changed, snapshot, targets := d.applyMutation(func() {
				d.hv.SendJoin(boot)
			})
			if changed {
				d.broadcastSnapshot(snapshot, targets)
			}
		}
	}
}

func (d *TopoDaemon) shuffleLoop() {
	defer d.wg.Done()
	t := time.NewTicker(time.Duration(d.cfg.ShuffleIntervalMs) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			changed, snapshot, targets := d.applyMutation(func() {
				d.hv.SendShuffle()
			})
			if changed {
				d.broadcastSnapshot(snapshot, targets)
			}
		}
	}
}

func (d *TopoDaemon) keepaliveLoop() {
	defer d.wg.Done()
	t := time.NewTicker(time.Duration(d.cfg.KeepaliveIntervalMs) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			changed, snapshot, targets := d.applyMutation(func() {
				d.hv.SendKeepalives()
				if !d.hv.Active.IsFull() {
					d.hv.PromotePassive()
				}
			})
			if changed {
				d.broadcastSnapshot(snapshot, targets)
			}
		}
	}
}

func (d *TopoDaemon) pickBootstrapNode() h.Node {
	candidates := make([]string, 0, len(d.cfg.Bootstrap))
	for _, addr := range d.cfg.Bootstrap {
		addr = strings.TrimSpace(addr)
		if addr == "" || addr == d.cfg.ListenAddr {
			continue
		}
		candidates = append(candidates, addr)
	}
	if len(candidates) == 0 {
		for addr := range d.peersByTopo {
			if addr == d.cfg.ListenAddr {
				continue
			}
			candidates = append(candidates, addr)
		}
		sort.Strings(candidates)
	}
	if len(candidates) == 0 {
		return nil
	}
	return h.NewNode(candidates[d.randIntn(len(candidates))])
}

func nodesToAddrs(ns []h.Node) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		if n == nil || n.Addr() == "" {
			continue
		}
		out = append(out, n.Addr())
	}
	return out
}

func addrsToNodes(addrs []string) []h.Node {
	out := make([]h.Node, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		out = append(out, h.NewNode(a))
	}
	return out
}

func (d *TopoDaemon) encodeMembershipMessage(m h.Message) (wireMessage, error) {
	base := wireMessage{
		From: m.From().Addr(),
		To:   m.To().Addr(),
	}
	switch v := m.(type) {
	case *h.JoinRequest:
		base.Kind = "join"
	case *h.ForwardJoinRequest:
		base.Kind = "forward_join"
		base.Join = v.Join.Addr()
		base.TTL = v.TTL
	case *h.DisconnectRequest:
		base.Kind = "disconnect"
	case *h.NeighborRequest:
		base.Kind = "neighbor"
		base.Priority = v.Priority
	case *h.ShuffleRequest:
		base.Kind = "shuffle"
		base.TTL = v.TTL
		base.Origin = ""
		if v.Origin != nil {
			base.Origin = v.Origin.Addr()
		}
		base.Active = nodesToAddrs(v.Active)
		base.Passive = nodesToAddrs(v.Passive)
	case *h.ShuffleReply:
		base.Kind = "shuffle_reply"
		base.Passive = nodesToAddrs(v.Passive)
	default:
		return wireMessage{}, fmt.Errorf("unsupported message type: %T", m)
	}
	return base, nil
}

func (d *TopoDaemon) decodeMembershipMessage(req wireMessage) (h.Message, error) {
	self := d.selfNode
	from := h.NewNode(req.From)
	switch req.Kind {
	case "join":
		return h.NewJoin(self, from), nil
	case "forward_join":
		if req.Join == "" {
			return nil, errors.New("missing join field")
		}
		return h.NewForwardJoin(self, from, h.NewNode(req.Join), req.TTL), nil
	case "disconnect":
		return h.NewDisconnect(self, from), nil
	case "neighbor":
		return h.NewNeighbor(self, from, req.Priority), nil
	case "shuffle":
		origin := req.Origin
		if origin == "" {
			origin = req.From
		}
		msg := h.NewShuffle(self, from, h.NewNode(origin), addrsToNodes(req.Active), addrsToNodes(req.Passive), req.TTL)
		msg.Origin = h.NewNode(origin)
		return msg, nil
	case "shuffle_reply":
		return h.NewShuffleReply(self, from, addrsToNodes(req.Passive)), nil
	default:
		return nil, fmt.Errorf("unknown kind: %s", req.Kind)
	}
}

func (d *TopoDaemon) exchangeOverlay(addr string, req wireMessage) (wireMessage, error) {
	var zero wireMessage
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return zero, err
	}

	var resp wireMessage
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			return wireMessage{Kind: "ack"}, nil
		}
		return zero, err
	}
	if resp.Kind == "err" {
		if resp.Reason == "" {
			resp.Reason = "remote_error"
		}
		return zero, errors.New(resp.Reason)
	}
	return resp, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to TopoDaemon json config")
	flag.Parse()
	if cfgPath == "" && flag.NArg() == 1 {
		cfgPath = flag.Arg(0)
	}
	if cfgPath == "" {
		fmt.Fprintf(os.Stderr, "usage: %s <config.json>\n", os.Args[0])
		os.Exit(2)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		os.Exit(2)
	}

	peersByID, peersByTopo, err := loadPeerInfoDir(cfg.PeerInfoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load peer info failed: %v\n", err)
		os.Exit(2)
	}
	if _, ok := peersByID[cfg.PeerID]; !ok {
		fmt.Fprintf(os.Stderr, "self peer_id %s not found in peer_info_dir\n", cfg.PeerID)
		os.Exit(2)
	}

	logger := log.New(os.Stdout, "[TopoDaemon " + cfg.PeerID + "] ", log.LstdFlags|log.Lmicroseconds)
	daemon := newTopoDaemon(cfg, peersByID, peersByTopo, logger)

	if err := daemon.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
		os.Exit(2)
	}
	logger.Printf("started listen=%s ipc=%s snapshot_limit=%d", cfg.ListenAddr, cfg.IPCSocket, cfg.SnapshotLimit)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Printf("stopping")
	daemon.Stop()
}
