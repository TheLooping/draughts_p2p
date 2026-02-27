package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
)

const (
	defaultSnapshotLimit        = 10
	defaultShuffleIntervalMs    = 30000
	defaultKeepaliveIntervalMs  = 8000
	defaultJoinRetryMs          = 1200
	defaultConnectTimeoutMs     = 1200
	defaultPeerReloadIntervalMs = 2000
	defaultActiveMin            = 3
	defaultActiveMax            = 5
	defaultPassiveMax           = 30
	defaultHistoryOwnerLimit    = 256
)

type tdLevel string

const (
	tdDebug tdLevel = "DEBUG"
	tdInfo  tdLevel = "INFO"
	tdWarn  tdLevel = "WARN"
	tdError tdLevel = "ERROR"
)

func tdLevelCN(level tdLevel) string {
	switch level {
	case tdDebug:
		return "调试"
	case tdInfo:
		return "信息"
	case tdWarn:
		return "警告"
	case tdError:
		return "错误"
	default:
		return "未知"
	}
}

func tdTs() string {
	return time.Now().Format("2006-01-02 15:04:05.000")
}

func tdLogf(level tdLevel, tag, format string, args ...any) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		tag = "General 通用"
	}
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s [%s %s] [%s] %s", tdTs(), string(level), tdLevelCN(level), tag, msg)
}

func tdInfof(tag, format string, args ...any) {
	tdLogf(tdInfo, tag, format, args...)
}

func tdWarnf(tag, format string, args ...any) {
	tdLogf(tdWarn, tag, format, args...)
}

func tdErrorf(tag, format string, args ...any) {
	tdLogf(tdError, tag, format, args...)
}

type Config struct {
	PeerID               string   `json:"peer_id"`
	ListenAddr           string   `json:"listen_addr"`
	IPCSocket            string   `json:"ipc_socket"`
	PeerInfoDir          string   `json:"peer_info_dir"`
	SnapshotLimit        int      `json:"snapshot_limit"`
	ShuffleIntervalMs    int      `json:"shuffle_interval_ms"`
	KeepaliveIntervalMs  int      `json:"keepalive_interval_ms"`
	JoinRetryMs          int      `json:"join_retry_ms"`
	Bootstrap            []string `json:"bootstrap"`
	ActiveMin            int      `json:"active_min"`
	ActiveMax            int      `json:"active_max"`
	PassiveMax           int      `json:"passive_max"`
	HistoryFile          string   `json:"history_file"`
	ConnectTimeoutMs     int      `json:"connect_timeout_ms"`
	PeerReloadIntervalMs int      `json:"peer_reload_interval_ms"`
	HistoryOwnerLimit    int      `json:"history_owner_limit"`
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	cfg.applyDefaults()
	if strings.TrimSpace(cfg.PeerID) == "" {
		return cfg, errors.New("peer_id is required")
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		return cfg, errors.New("listen_addr is required")
	}
	if strings.TrimSpace(cfg.IPCSocket) == "" {
		return cfg, errors.New("ipc_socket is required")
	}
	if strings.TrimSpace(cfg.PeerInfoDir) == "" {
		return cfg, errors.New("peer_info_dir is required")
	}

	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return cfg, fmt.Errorf("invalid listen_addr %q: %w", cfg.ListenAddr, err)
	}

	for i := range cfg.Bootstrap {
		cfg.Bootstrap[i] = strings.TrimSpace(cfg.Bootstrap[i])
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.SnapshotLimit <= 0 {
		c.SnapshotLimit = defaultSnapshotLimit
	}
	if c.ShuffleIntervalMs <= 0 {
		c.ShuffleIntervalMs = defaultShuffleIntervalMs
	}
	if c.KeepaliveIntervalMs <= 0 {
		c.KeepaliveIntervalMs = defaultKeepaliveIntervalMs
	}
	if c.JoinRetryMs <= 0 {
		c.JoinRetryMs = defaultJoinRetryMs
	}
	if c.ActiveMin <= 0 {
		c.ActiveMin = defaultActiveMin
	}
	if c.ActiveMax <= 0 {
		c.ActiveMax = defaultActiveMax
	}
	if c.ActiveMin > c.ActiveMax {
		c.ActiveMin = c.ActiveMax
	}
	if c.PassiveMax <= 0 {
		c.PassiveMax = max(defaultPassiveMax, c.ActiveMax*4)
	}
	if c.ConnectTimeoutMs <= 0 {
		c.ConnectTimeoutMs = defaultConnectTimeoutMs
	}
	if c.PeerReloadIntervalMs <= 0 {
		c.PeerReloadIntervalMs = defaultPeerReloadIntervalMs
	}
	if c.HistoryOwnerLimit <= 0 {
		c.HistoryOwnerLimit = defaultHistoryOwnerLimit
	}

	if strings.TrimSpace(c.HistoryFile) == "" {
		socketDir := filepath.Dir(c.IPCSocket)
		c.HistoryFile = filepath.Join(socketDir, c.PeerID+".history.jsonl")
	}
}

type PeerDescriptor struct {
	PeerID       string `json:"peer_id"`
	IP           string `json:"ip"`
	OverlayPort  uint16 `json:"overlay_port"`
	DraughtsPort uint16 `json:"draughts_port"`
	PubKey       string `json:"pubkey"`
	TopodAddr    string `json:"topod_addr,omitempty"`
}

func (p PeerDescriptor) ValidForRoute() bool {
	return strings.TrimSpace(p.PeerID) != "" &&
		strings.TrimSpace(p.IP) != "" &&
		p.DraughtsPort != 0 &&
		strings.TrimSpace(p.PubKey) != ""
}

func (p PeerDescriptor) ValidForOverlay() bool {
	return strings.TrimSpace(p.PeerID) != "" && strings.TrimSpace(p.TopodAddr) != ""
}

func (p PeerDescriptor) Clone() PeerDescriptor {
	return PeerDescriptor{
		PeerID:       strings.TrimSpace(p.PeerID),
		IP:           strings.TrimSpace(p.IP),
		OverlayPort:  p.OverlayPort,
		DraughtsPort: p.DraughtsPort,
		PubKey:       strings.TrimSpace(p.PubKey),
		TopodAddr:    strings.TrimSpace(p.TopodAddr),
	}
}

func samePeer(a, b PeerDescriptor) bool {
	return a.PeerID == b.PeerID &&
		a.IP == b.IP &&
		a.OverlayPort == b.OverlayPort &&
		a.DraughtsPort == b.DraughtsPort &&
		a.PubKey == b.PubKey &&
		a.TopodAddr == b.TopodAddr
}

type NeighborSnapshot struct {
	OwnerPeerID string           `json:"owner_peer_id"`
	Term        uint64           `json:"term"`
	Active      []PeerDescriptor `json:"active"`
	TimestampMs int64            `json:"timestamp_ms"`
}

func clonePeers(in []PeerDescriptor) []PeerDescriptor {
	out := make([]PeerDescriptor, 0, len(in))
	for _, p := range in {
		p = p.Clone()
		if p.PeerID == "" {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PeerID < out[j].PeerID
	})
	return out
}

func peersEqual(a, b []PeerDescriptor) bool {
	if len(a) != len(b) {
		return false
	}
	aa := clonePeers(a)
	bb := clonePeers(b)
	for i := 0; i < len(aa); i++ {
		if !samePeer(aa[i], bb[i]) {
			return false
		}
	}
	return true
}

type snapshotRing struct {
	limit  int
	order  []uint64
	byTerm map[uint64]NeighborSnapshot
}

func newSnapshotRing(limit int) *snapshotRing {
	if limit <= 0 {
		limit = 1
	}
	return &snapshotRing{limit: limit, byTerm: make(map[uint64]NeighborSnapshot)}
}

func (r *snapshotRing) Put(s NeighborSnapshot) {
	if s.Term == 0 {
		return
	}
	if _, ok := r.byTerm[s.Term]; !ok {
		r.order = append(r.order, s.Term)
	}
	r.byTerm[s.Term] = NeighborSnapshot{
		OwnerPeerID: s.OwnerPeerID,
		Term:        s.Term,
		Active:      clonePeers(s.Active),
		TimestampMs: s.TimestampMs,
	}
	sort.Slice(r.order, func(i, j int) bool { return r.order[i] < r.order[j] })
	for len(r.order) > r.limit {
		t := r.order[0]
		r.order = r.order[1:]
		delete(r.byTerm, t)
	}
}

func (r *snapshotRing) Get(term uint64) (NeighborSnapshot, bool) {
	s, ok := r.byTerm[term]
	if !ok {
		return NeighborSnapshot{}, false
	}
	s.Active = clonePeers(s.Active)
	return s, true
}

func (r *snapshotRing) Latest() (NeighborSnapshot, bool) {
	if len(r.order) == 0 {
		return NeighborSnapshot{}, false
	}
	return r.Get(r.order[len(r.order)-1])
}

type persistedRecord struct {
	Scope       string           `json:"scope"`
	OwnerPeerID string           `json:"owner_peer_id"`
	Term        uint64           `json:"term"`
	Active      []PeerDescriptor `json:"active"`
	TimestampMs int64            `json:"timestamp_ms"`
}

type historyStore struct {
	path string
	mu   sync.Mutex
}

func newHistoryStore(path string) (*historyStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("history path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create history dir: %w", err)
	}
	return &historyStore{path: path}, nil
}

func (s *historyStore) Append(scope string, snap NeighborSnapshot) error {
	if snap.OwnerPeerID == "" || snap.Term == 0 {
		return nil
	}
	rec := persistedRecord{
		Scope:       scope,
		OwnerPeerID: snap.OwnerPeerID,
		Term:        snap.Term,
		Active:      clonePeers(snap.Active),
		TimestampMs: snap.TimestampMs,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func (s *historyStore) LoadAll() ([]persistedRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	out := make([]persistedRecord, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec persistedRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.OwnerPeerID == "" || rec.Term == 0 {
			continue
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *historyStore) Lookup(owner string, term uint64) (*NeighborSnapshot, error) {
	if owner == "" || term == 0 {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var found *NeighborSnapshot
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec persistedRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.OwnerPeerID != owner || rec.Term != term {
			continue
		}
		snap := NeighborSnapshot{
			OwnerPeerID: rec.OwnerPeerID,
			Term:        rec.Term,
			Active:      clonePeers(rec.Active),
			TimestampMs: rec.TimestampMs,
		}
		found = &snap
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

type overlayMessage struct {
	Type     string           `json:"type"`
	From     *PeerDescriptor  `json:"from,omitempty"`
	Term     uint64           `json:"term,omitempty"`
	Active   []PeerDescriptor `json:"active,omitempty"`
	Peers    []PeerDescriptor `json:"peers,omitempty"`
	Accepted bool             `json:"accepted,omitempty"`
	Reason   string           `json:"reason,omitempty"`
	Priority string           `json:"priority,omitempty"`
}

type joinTarget struct {
	peerID string
	addr   string
}

type daemon struct {
	cfg   Config
	self  PeerDescriptor
	store *historyStore

	mu              sync.RWMutex
	term            uint64
	active          map[string]PeerDescriptor
	passive         map[string]PeerDescriptor
	directory       map[string]PeerDescriptor
	selfHistory     *snapshotRing
	neighborHistory map[string]*snapshotRing
	historyMeta     map[string]int64

	randMu sync.Mutex
	rnd    *rand.Rand

	ctx    context.Context
	cancel context.CancelFunc

	wg              sync.WaitGroup
	overlayListener net.Listener
	ipcListener     net.Listener

	snapshotCh chan struct{}
}

func newDaemon(cfg Config) (*daemon, error) {
	selfPath := filepath.Join(cfg.PeerInfoDir, cfg.PeerID+".info")
	self, err := parsePeerInfo(selfPath)
	if err != nil {
		return nil, fmt.Errorf("load self peer info: %w", err)
	}
	if self.PeerID == "" {
		self.PeerID = cfg.PeerID
	}
	if self.TopodAddr == "" {
		self.TopodAddr = cfg.ListenAddr
	}

	store, err := newHistoryStore(cfg.HistoryFile)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &daemon{
		cfg:             cfg,
		self:            self.Clone(),
		store:           store,
		term:            1,
		active:          make(map[string]PeerDescriptor),
		passive:         make(map[string]PeerDescriptor),
		directory:       make(map[string]PeerDescriptor),
		selfHistory:     newSnapshotRing(cfg.SnapshotLimit),
		neighborHistory: make(map[string]*snapshotRing),
		historyMeta:     make(map[string]int64),
		rnd:             rand.New(rand.NewSource(time.Now().UnixNano())),
		ctx:             ctx,
		cancel:          cancel,
		snapshotCh:      make(chan struct{}, 1),
	}

	d.refreshDirectory()
	if err := d.loadPersistedCache(); err != nil {
		return nil, fmt.Errorf("load history cache: %w", err)
	}

	// Ensure term starts from cached self history.
	d.mu.Lock()
	if snap, ok := d.selfHistory.Latest(); ok && snap.Term >= d.term {
		d.term = snap.Term
	}
	if _, ok := d.selfHistory.Get(d.term); !ok {
		snap := d.buildSelfSnapshotLocked(d.term)
		d.selfHistory.Put(snap)
		d.historyMeta[d.self.PeerID] = nowMs()
		if err := d.store.Append("self", snap); err != nil {
			tdWarnf("History 持久化", "append initial self snapshot failed [err=%v]", err)
		}
	}
	d.mu.Unlock()

	return d, nil
}

func parsePeerInfo(path string) (PeerDescriptor, error) {
	kv, err := parseKVFile(path)
	if err != nil {
		return PeerDescriptor{}, err
	}

	out := PeerDescriptor{
		PeerID:    strings.TrimSpace(kv["peer_id"]),
		IP:        strings.TrimSpace(kv["bind_ip"]),
		PubKey:    strings.TrimSpace(kv["pubkey"]),
		TopodAddr: strings.TrimSpace(kv["topod_addr"]),
	}

	if v := strings.TrimSpace(kv["overlay_port"]); v != "" {
		p, err := strconv.Atoi(v)
		if err == nil && p > 0 && p <= 65535 {
			out.OverlayPort = uint16(p)
		}
	}
	if v := strings.TrimSpace(kv["draughts_port"]); v != "" {
		p, err := strconv.Atoi(v)
		if err == nil && p > 0 && p <= 65535 {
			out.DraughtsPort = uint16(p)
		}
	}

	if out.TopodAddr == "" && out.IP != "" && out.OverlayPort != 0 {
		out.TopodAddr = net.JoinHostPort(out.IP, strconv.Itoa(int(out.OverlayPort+2000)))
	}

	if out.PeerID == "" {
		return out, fmt.Errorf("peer_id missing in %s", path)
	}
	return out, nil
}

func parseKVFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pos := strings.Index(line, "=")
		if pos < 0 {
			continue
		}
		key := strings.TrimSpace(line[:pos])
		val := strings.TrimSpace(line[pos+1:])
		out[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *daemon) loadPersistedCache() error {
	recs, err := d.store.LoadAll()
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, rec := range recs {
		snap := NeighborSnapshot{
			OwnerPeerID: rec.OwnerPeerID,
			Term:        rec.Term,
			Active:      clonePeers(rec.Active),
			TimestampMs: rec.TimestampMs,
		}
		if snap.OwnerPeerID == d.self.PeerID {
			d.selfHistory.Put(snap)
			if snap.Term > d.term {
				d.term = snap.Term
			}
		} else {
			ring := d.ensureNeighborRingLocked(snap.OwnerPeerID)
			ring.Put(snap)
		}
		d.historyMeta[snap.OwnerPeerID] = max64(d.historyMeta[snap.OwnerPeerID], snap.TimestampMs)
	}

	return nil
}

func (d *daemon) ensureNeighborRingLocked(owner string) *snapshotRing {
	ring := d.neighborHistory[owner]
	if ring == nil {
		ring = newSnapshotRing(d.cfg.SnapshotLimit)
		d.neighborHistory[owner] = ring
	}
	return ring
}

func (d *daemon) refreshDirectory() {
	entries, err := os.ReadDir(d.cfg.PeerInfoDir)
	if err != nil {
		tdWarnf("PeerDir 节点目录", "read peer_info_dir failed [dir=%s] [err=%v]", d.cfg.PeerInfoDir, err)
		return
	}

	next := make(map[string]PeerDescriptor)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".info") {
			continue
		}
		path := filepath.Join(d.cfg.PeerInfoDir, name)
		pd, err := parsePeerInfo(path)
		if err != nil {
			tdWarnf("PeerDir 节点目录", "parse peer info failed [file=%s] [err=%v]", path, err)
			continue
		}
		if pd.PeerID == "" {
			continue
		}
		next[pd.PeerID] = pd
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Keep learned runtime addresses where files are missing topod_addr.
	for id, old := range d.directory {
		if cur, ok := next[id]; ok {
			if cur.TopodAddr == "" && old.TopodAddr != "" {
				cur.TopodAddr = old.TopodAddr
			}
			next[id] = cur
		}
	}

	d.directory = next
	d.directory[d.self.PeerID] = d.self.Clone()
}

func (d *daemon) start() error {
	tdInfof("Lifecycle 生命周期", "TopoDaemon start [peer=%s] [listen=%s] [ipc=%s]", d.self.PeerID, d.cfg.ListenAddr, d.cfg.IPCSocket)

	if err := os.MkdirAll(filepath.Dir(d.cfg.IPCSocket), 0o755); err != nil {
		return fmt.Errorf("create ipc socket dir: %w", err)
	}
	_ = os.Remove(d.cfg.IPCSocket)

	overlayLn, err := net.Listen("tcp", d.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen overlay: %w", err)
	}
	ipcLn, err := net.Listen("unix", d.cfg.IPCSocket)
	if err != nil {
		overlayLn.Close()
		return fmt.Errorf("listen ipc: %w", err)
	}

	d.overlayListener = overlayLn
	d.ipcListener = ipcLn

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serveOverlay()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serveIPC()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.bootstrapLoop()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.keepaliveLoop()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.shuffleLoop()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.directoryReloadLoop()
	}()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.snapshotBroadcastLoop()
	}()

	d.triggerSnapshotBroadcast()
	return nil
}

func (d *daemon) stop(ctx context.Context) {
	d.cancel()
	if d.overlayListener != nil {
		_ = d.overlayListener.Close()
	}
	if d.ipcListener != nil {
		_ = d.ipcListener.Close()
	}
	_ = os.Remove(d.cfg.IPCSocket)

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		tdWarnf("Lifecycle 生命周期", "shutdown timeout (graceful stop timed out)")
	}
}

func (d *daemon) serveOverlay() {
	for {
		conn, err := d.overlayListener.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return
		}

		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			d.handleOverlayConn(c)
		}(conn)
	}
}

func (d *daemon) handleOverlayConn(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * d.ioTimeout()))

	msg, err := readOverlayMessage(conn)
	if err != nil {
		return
	}
	msg.Type = strings.ToLower(strings.TrimSpace(msg.Type))

	switch msg.Type {
	case "join":
		resp := d.handleJoin(msg)
		_ = writeOverlayMessage(conn, resp)
	case "snapshot":
		d.handleSnapshot(msg)
		_ = writeOverlayMessage(conn, overlayMessage{Type: "ack", Accepted: true})
	case "ping":
		if msg.From != nil {
			d.learnPeer(*msg.From)
		}
		_ = writeOverlayMessage(conn, overlayMessage{Type: "pong", Accepted: true, From: ptrPeer(d.self)})
	case "shuffle":
		resp := d.handleShuffle(msg)
		_ = writeOverlayMessage(conn, resp)
	case "disconnect":
		d.handleDisconnect(msg)
		_ = writeOverlayMessage(conn, overlayMessage{Type: "ack", Accepted: true})
	default:
		_ = writeOverlayMessage(conn, overlayMessage{Type: "err", Accepted: false, Reason: "unknown_type"})
	}
}

func (d *daemon) handleJoin(msg overlayMessage) overlayMessage {
	if msg.From == nil {
		return overlayMessage{Type: "join_ack", Accepted: false, Reason: "missing_from"}
	}

	from := msg.From.Clone()
	if from.TopodAddr == "" {
		from.TopodAddr = msg.From.TopodAddr
	}

	priority := strings.ToLower(strings.TrimSpace(msg.Priority))
	highPriority := priority != "low"

	var (
		accepted bool
		changed  bool
		demoted  *PeerDescriptor
		hints    []PeerDescriptor
	)

	d.mu.Lock()
	d.learnPeerLocked(from)

	if existing, ok := d.active[from.PeerID]; ok {
		accepted = true
		if !samePeer(existing, from) {
			d.active[from.PeerID] = from
			changed = true
		}
	} else {
		if len(d.active) >= d.cfg.ActiveMax {
			if highPriority {
				victim, ok := d.pickRandomActiveLocked(from.PeerID)
				if ok {
					delete(d.active, victim.PeerID)
					d.addPassiveLocked(victim)
					vv := victim
					demoted = &vv
				}
			}
		}

		if len(d.active) < d.cfg.ActiveMax {
			d.active[from.PeerID] = from
			delete(d.passive, from.PeerID)
			accepted = true
			changed = true
		}
	}

	if changed {
		d.advanceTermLocked("join:" + from.PeerID)
	}

	hints = d.samplePeersLocked(8, from.PeerID)
	d.mu.Unlock()

	if demoted != nil && demoted.TopodAddr != "" {
		go d.sendDisconnect(*demoted)
	}
	if changed {
		d.triggerSnapshotBroadcast()
	}

	if accepted {
		tdInfof("Overlay 邻居", "join accepted [from=%s] [active_size=%d]", from.PeerID, d.activeSize())
	}

	return overlayMessage{
		Type:     "join_ack",
		Accepted: accepted,
		Reason:   ternary(!accepted, "active_full", ""),
		From:     ptrPeer(d.self),
		Peers:    hints,
	}
}

func (d *daemon) handleSnapshot(msg overlayMessage) {
	if msg.From == nil || msg.Term == 0 {
		return
	}

	from := msg.From.Clone()
	if from.TopodAddr == "" {
		from.TopodAddr = msg.From.TopodAddr
	}

	d.mu.Lock()
	d.learnPeerLocked(from)
	for _, p := range msg.Active {
		d.learnPeerLocked(p)
	}

	ring := d.ensureNeighborRingLocked(from.PeerID)
	incoming := NeighborSnapshot{
		OwnerPeerID: from.PeerID,
		Term:        msg.Term,
		Active:      clonePeers(msg.Active),
		TimestampMs: nowMs(),
	}

	if old, ok := ring.Get(msg.Term); ok && peersEqual(old.Active, incoming.Active) {
		d.historyMeta[from.PeerID] = nowMs()
		d.mu.Unlock()
		return
	}

	ring.Put(incoming)
	d.historyMeta[from.PeerID] = nowMs()
	d.gcNeighborHistoryLocked()
	d.mu.Unlock()

	if err := d.store.Append("twohop", incoming); err != nil {
		tdWarnf("History 持久化", "persist twohop snapshot failed [owner=%s] [term=%d] [err=%v]", from.PeerID, msg.Term, err)
	}
}

func (d *daemon) handleShuffle(msg overlayMessage) overlayMessage {
	if msg.From == nil {
		return overlayMessage{Type: "shuffle_ack", Accepted: false, Reason: "missing_from"}
	}

	from := msg.From.Clone()
	d.mu.Lock()
	d.learnPeerLocked(from)
	for _, p := range msg.Peers {
		d.addPassiveLocked(p)
	}
	peers := d.samplePassiveLocked(8, from.PeerID)
	d.mu.Unlock()

	return overlayMessage{Type: "shuffle_ack", Accepted: true, From: ptrPeer(d.self), Peers: peers}
}

func (d *daemon) handleDisconnect(msg overlayMessage) {
	if msg.From == nil {
		return
	}
	peerID := strings.TrimSpace(msg.From.PeerID)
	if peerID == "" {
		return
	}

	changed := false
	d.mu.Lock()
	if old, ok := d.active[peerID]; ok {
		delete(d.active, peerID)
		d.addPassiveLocked(old)
		d.advanceTermLocked("disconnect:" + peerID)
		changed = true
	}
	d.mu.Unlock()

	if changed {
		d.triggerSnapshotBroadcast()
	}
}

func (d *daemon) sendDisconnect(peer PeerDescriptor) {
	addr := d.peerDialAddr(peer)
	if addr == "" {
		return
	}
	msg := overlayMessage{Type: "disconnect", From: ptrPeer(d.self)}
	_ = d.sendOverlayOneWay(addr, msg)
}

func (d *daemon) bootstrapLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.JoinRetryMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.healConnectivity()
		}
	}
}

func (d *daemon) keepaliveLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.KeepaliveIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.checkActivePeers()
		}
	}
}

func (d *daemon) shuffleLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.ShuffleIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.runShuffleOnce()
		}
	}
}

func (d *daemon) directoryReloadLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.PeerReloadIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.refreshDirectory()
		}
	}
}

func (d *daemon) snapshotBroadcastLoop() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.snapshotCh:
			d.broadcastSelfSnapshot()
		}
	}
}

func (d *daemon) triggerSnapshotBroadcast() {
	select {
	case d.snapshotCh <- struct{}{}:
	default:
	}
}

func (d *daemon) healConnectivity() {
	for i := 0; i < d.cfg.ActiveMin; i++ {
		if d.activeSize() >= d.cfg.ActiveMin {
			return
		}
		if !d.joinOneTarget() {
			return
		}
	}
}

func (d *daemon) joinOneTarget() bool {
	targets := d.collectJoinTargets()
	if len(targets) == 0 {
		return false
	}

	d.shuffleJoinTargets(targets)

	for _, target := range targets {
		if target.addr == "" {
			continue
		}
		ok := d.requestJoin(target.addr, "high")
		if ok {
			return true
		}
	}
	return false
}

func (d *daemon) collectJoinTargets() []joinTarget {
	d.mu.RLock()
	defer d.mu.RUnlock()

	seenAddr := make(map[string]struct{})
	out := make([]joinTarget, 0)

	add := func(peerID, addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seenAddr[addr]; ok {
			return
		}
		if peerID != "" {
			if peerID == d.self.PeerID {
				return
			}
			if _, active := d.active[peerID]; active {
				return
			}
		}
		seenAddr[addr] = struct{}{}
		out = append(out, joinTarget{peerID: peerID, addr: addr})
	}

	for _, p := range d.passive {
		add(p.PeerID, d.peerDialAddr(p))
	}
	for _, addr := range d.cfg.Bootstrap {
		add("", strings.TrimSpace(addr))
	}
	for _, p := range d.directory {
		add(p.PeerID, d.peerDialAddr(p))
	}

	return out
}

func (d *daemon) shuffleJoinTargets(items []joinTarget) {
	d.randMu.Lock()
	defer d.randMu.Unlock()
	d.rnd.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})
}

func (d *daemon) requestJoin(addr, priority string) bool {
	req := overlayMessage{
		Type:     "join",
		From:     ptrPeer(d.self),
		Priority: priority,
	}

	resp, err := d.sendOverlayRequest(addr, req)
	if err != nil {
		return false
	}
	if !resp.Accepted {
		if len(resp.Peers) > 0 {
			d.mu.Lock()
			for _, p := range resp.Peers {
				d.addPassiveLocked(p)
			}
			d.mu.Unlock()
		}
		return false
	}

	if resp.From == nil {
		return false
	}

	remote := resp.From.Clone()
	if remote.TopodAddr == "" {
		remote.TopodAddr = addr
	}

	changed := false
	d.mu.Lock()
	d.learnPeerLocked(remote)
	if old, ok := d.active[remote.PeerID]; ok {
		if !samePeer(old, remote) {
			d.active[remote.PeerID] = remote
			changed = true
		}
	} else {
		if len(d.active) >= d.cfg.ActiveMax {
			d.mu.Unlock()
			return false
		}
		d.active[remote.PeerID] = remote
		delete(d.passive, remote.PeerID)
		changed = true
	}

	for _, p := range resp.Peers {
		d.addPassiveLocked(p)
	}

	if changed {
		d.advanceTermLocked("join_ok:" + remote.PeerID)
	}
	d.mu.Unlock()

	if changed {
		d.triggerSnapshotBroadcast()
	}

	return true
}

func (d *daemon) runShuffleOnce() {
	d.mu.RLock()
	active := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		active = append(active, p.Clone())
	}
	passive := make([]PeerDescriptor, 0, len(d.passive))
	for _, p := range d.passive {
		passive = append(passive, p.Clone())
	}
	d.mu.RUnlock()

	if len(active) == 0 || len(passive) == 0 {
		return
	}

	nh, ok := d.pickRandomPeer(active)
	if !ok {
		return
	}

	d.randMu.Lock()
	d.rnd.Shuffle(len(passive), func(i, j int) {
		passive[i], passive[j] = passive[j], passive[i]
	})
	d.randMu.Unlock()

	if len(passive) > 8 {
		passive = passive[:8]
	}

	addr := d.peerDialAddr(nh)
	if addr == "" {
		return
	}

	req := overlayMessage{Type: "shuffle", From: ptrPeer(d.self), Peers: passive}
	resp, err := d.sendOverlayRequest(addr, req)
	if err != nil {
		return
	}
	if !resp.Accepted {
		return
	}

	if len(resp.Peers) > 0 {
		d.mu.Lock()
		for _, p := range resp.Peers {
			d.addPassiveLocked(p)
		}
		d.mu.Unlock()
	}
}

func (d *daemon) checkActivePeers() {
	d.mu.RLock()
	active := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		active = append(active, p.Clone())
	}
	d.mu.RUnlock()

	for _, p := range active {
		if !d.pingPeer(p) {
			changed := false
			d.mu.Lock()
			if old, ok := d.active[p.PeerID]; ok {
				delete(d.active, p.PeerID)
				d.addPassiveLocked(old)
				d.advanceTermLocked("ping_timeout:" + p.PeerID)
				changed = true
			}
			d.mu.Unlock()
			if changed {
				d.triggerSnapshotBroadcast()
			}
		}
	}
}

func (d *daemon) pingPeer(peer PeerDescriptor) bool {
	addr := d.peerDialAddr(peer)
	if addr == "" {
		return false
	}
	req := overlayMessage{Type: "ping", From: ptrPeer(d.self)}
	resp, err := d.sendOverlayRequest(addr, req)
	if err != nil {
		return false
	}
	return strings.EqualFold(resp.Type, "pong") || resp.Accepted
}

func (d *daemon) broadcastSelfSnapshot() {
	d.mu.RLock()
	snap := d.buildSelfSnapshotLocked(d.term)
	targets := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		targets = append(targets, p.Clone())
	}
	d.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	msg := overlayMessage{Type: "snapshot", From: ptrPeer(d.self), Term: snap.Term, Active: snap.Active}

	for _, p := range targets {
		addr := d.peerDialAddr(p)
		if addr == "" {
			continue
		}
		go func(a string) {
			_ = d.sendOverlayOneWay(a, msg)
		}(addr)
	}
}

func (d *daemon) peerDialAddr(p PeerDescriptor) string {
	addr := strings.TrimSpace(p.TopodAddr)
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "0.0.0.0" {
		if p.IP != "" {
			return net.JoinHostPort(p.IP, port)
		}
	}
	return addr
}

func (d *daemon) sendOverlayRequest(addr string, msg overlayMessage) (overlayMessage, error) {
	var resp overlayMessage

	conn, err := d.dial(addr)
	if err != nil {
		return resp, err
	}
	defer conn.Close()

	if err := writeOverlayMessage(conn, msg); err != nil {
		return resp, err
	}
	resp, err = readOverlayMessage(conn)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (d *daemon) sendOverlayOneWay(addr string, msg overlayMessage) error {
	conn, err := d.dial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(d.ioTimeout()))
	if err := writeOverlayMessage(conn, msg); err != nil {
		return err
	}
	return nil
}

func (d *daemon) dial(addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.ioTimeout()}
	conn, err := dialer.DialContext(d.ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(2 * d.ioTimeout()))
	return conn, nil
}

func (d *daemon) ioTimeout() time.Duration {
	return time.Duration(d.cfg.ConnectTimeoutMs) * time.Millisecond
}

func (d *daemon) learnPeer(p PeerDescriptor) {
	d.mu.Lock()
	d.learnPeerLocked(p)
	d.mu.Unlock()
}

func (d *daemon) learnPeerLocked(p PeerDescriptor) {
	p = p.Clone()
	if p.PeerID == "" || p.PeerID == d.self.PeerID {
		return
	}
	if p.TopodAddr == "" {
		if old, ok := d.directory[p.PeerID]; ok {
			p.TopodAddr = old.TopodAddr
		}
	}
	d.directory[p.PeerID] = p
}

func (d *daemon) addPassiveLocked(p PeerDescriptor) {
	p = p.Clone()
	if p.PeerID == "" || p.PeerID == d.self.PeerID {
		return
	}
	if _, active := d.active[p.PeerID]; active {
		return
	}

	if old, ok := d.passive[p.PeerID]; ok {
		if old.TopodAddr != "" && p.TopodAddr == "" {
			p.TopodAddr = old.TopodAddr
		}
	}

	d.passive[p.PeerID] = p
	d.learnPeerLocked(p)

	for len(d.passive) > d.cfg.PassiveMax {
		victim, ok := d.pickRandomPassiveLocked("")
		if !ok {
			break
		}
		delete(d.passive, victim.PeerID)
	}
}

func (d *daemon) pickRandomActiveLocked(exclude string) (PeerDescriptor, bool) {
	candidates := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		if exclude != "" && p.PeerID == exclude {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		return PeerDescriptor{}, false
	}
	return d.pickRandomPeer(candidates)
}

func (d *daemon) pickRandomPassiveLocked(exclude string) (PeerDescriptor, bool) {
	candidates := make([]PeerDescriptor, 0, len(d.passive))
	for _, p := range d.passive {
		if exclude != "" && p.PeerID == exclude {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		return PeerDescriptor{}, false
	}
	return d.pickRandomPeer(candidates)
}

func (d *daemon) samplePeersLocked(limit int, excludeIDs ...string) []PeerDescriptor {
	exclude := make(map[string]struct{}, len(excludeIDs)+1)
	exclude[d.self.PeerID] = struct{}{}
	for _, id := range excludeIDs {
		if id != "" {
			exclude[id] = struct{}{}
		}
	}

	all := make([]PeerDescriptor, 0, len(d.active)+len(d.passive))
	for _, p := range d.active {
		if _, ok := exclude[p.PeerID]; ok {
			continue
		}
		all = append(all, p.Clone())
	}
	for _, p := range d.passive {
		if _, ok := exclude[p.PeerID]; ok {
			continue
		}
		all = append(all, p.Clone())
	}

	d.randMu.Lock()
	d.rnd.Shuffle(len(all), func(i, j int) {
		all[i], all[j] = all[j], all[i]
	})
	d.randMu.Unlock()

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

func (d *daemon) samplePassiveLocked(limit int, excludeIDs ...string) []PeerDescriptor {
	exclude := make(map[string]struct{}, len(excludeIDs)+1)
	exclude[d.self.PeerID] = struct{}{}
	for _, id := range excludeIDs {
		if id != "" {
			exclude[id] = struct{}{}
		}
	}

	all := make([]PeerDescriptor, 0, len(d.passive))
	for _, p := range d.passive {
		if _, ok := exclude[p.PeerID]; ok {
			continue
		}
		all = append(all, p.Clone())
	}

	d.randMu.Lock()
	d.rnd.Shuffle(len(all), func(i, j int) {
		all[i], all[j] = all[j], all[i]
	})
	d.randMu.Unlock()

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

func (d *daemon) advanceTermLocked(reason string) {
	d.term++
	snap := d.buildSelfSnapshotLocked(d.term)
	d.selfHistory.Put(snap)
	d.historyMeta[d.self.PeerID] = nowMs()
	if err := d.store.Append("self", snap); err != nil {
		tdWarnf("History 持久化", "persist self snapshot failed [term=%d] [err=%v]", snap.Term, err)
	}
	d.gcNeighborHistoryLocked()

	activeIDs := make([]string, 0, len(snap.Active))
	for _, p := range snap.Active {
		activeIDs = append(activeIDs, p.PeerID)
	}
	tdInfof("Overlay 邻居", "ACTIVE_CHANGED [term=%d] [reason=%s] [neighbors=%s]", d.term, reason, formatNodeSet(activeIDs))
}

func (d *daemon) buildSelfSnapshotLocked(term uint64) NeighborSnapshot {
	active := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		active = append(active, p.Clone())
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].PeerID < active[j].PeerID
	})
	return NeighborSnapshot{
		OwnerPeerID: d.self.PeerID,
		Term:        term,
		Active:      active,
		TimestampMs: nowMs(),
	}
}

func (d *daemon) gcNeighborHistoryLocked() {
	if len(d.neighborHistory) <= d.cfg.HistoryOwnerLimit {
		return
	}

	protected := make(map[string]struct{}, len(d.active)+len(d.passive)+1)
	protected[d.self.PeerID] = struct{}{}
	for id := range d.active {
		protected[id] = struct{}{}
	}
	for id := range d.passive {
		protected[id] = struct{}{}
	}

	candidates := make([]string, 0, len(d.neighborHistory))
	for owner := range d.neighborHistory {
		if _, keep := protected[owner]; keep {
			continue
		}
		candidates = append(candidates, owner)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return d.historyMeta[candidates[i]] < d.historyMeta[candidates[j]]
	})

	for len(d.neighborHistory) > d.cfg.HistoryOwnerLimit && len(candidates) > 0 {
		victim := candidates[0]
		candidates = candidates[1:]
		delete(d.neighborHistory, victim)
		delete(d.historyMeta, victim)
	}
}

func (d *daemon) activeSize() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.active)
}

func (d *daemon) pickRandomPeer(peers []PeerDescriptor) (PeerDescriptor, bool) {
	if len(peers) == 0 {
		return PeerDescriptor{}, false
	}
	d.randMu.Lock()
	idx := d.rnd.Intn(len(peers))
	d.randMu.Unlock()
	return peers[idx].Clone(), true
}

func readOverlayMessage(r io.Reader) (overlayMessage, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil {
		return overlayMessage{}, err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return overlayMessage{}, io.EOF
	}
	var msg overlayMessage
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return overlayMessage{}, err
	}
	return msg, nil
}

func writeOverlayMessage(w io.Writer, msg overlayMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func ptrPeer(p PeerDescriptor) *PeerDescriptor {
	pp := p.Clone()
	return &pp
}

func (d *daemon) serveIPC() {
	for {
		conn, err := d.ipcListener.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return
		}

		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			d.handleIPCConn(c)
		}(conn)
	}
}

func (d *daemon) handleIPCConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * d.ioTimeout()))

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		_, _ = io.WriteString(conn, "ERR reason=empty_command\n")
		return
	}

	resp := d.processIPC(line)
	_, _ = io.WriteString(conn, resp+"\n")
}

func (d *daemon) processIPC(line string) string {
	cmd, kv := parseCommand(line)

	switch cmd {
	case "STATE":
		return d.handleIPCState()
	case "PLAN":
		return d.handleIPCPlan(strings.TrimSpace(kv["exclude"]))
	case "HISTORY", "PICK":
		peer := strings.TrimSpace(kv["peer"])
		termStr := strings.TrimSpace(kv["term"])
		if peer == "" || termStr == "" {
			tdWarnf("IPC 调用", "invalid request [%s] [peer=%q] [term=%q] [reason=missing_peer_or_term]", cmd, peer, termStr)
			return "ERR reason=missing_peer_or_term"
		}
		term, err := strconv.ParseUint(termStr, 10, 64)
		if err != nil || term == 0 {
			tdWarnf("IPC 调用", "invalid request [%s] [peer=%q] [term=%q] [reason=invalid_term]", cmd, peer, termStr)
			return "ERR reason=invalid_term"
		}
		exclude := strings.TrimSpace(kv["exclude"])
		strict := parseBool01(kv["strict"])
		return d.handleIPCHistory(peer, term, exclude, strict)
	default:
		tdWarnf("IPC 调用", "unknown command [raw=%q]", line)
		return "ERR reason=unknown_command"
	}
}

func parseCommand(line string) (string, map[string]string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return "", map[string]string{}
	}
	cmd := strings.ToUpper(strings.TrimSpace(fields[0]))
	kv := make(map[string]string)
	for _, tok := range fields[1:] {
		pos := strings.Index(tok, "=")
		if pos <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(tok[:pos]))
		val := strings.TrimSpace(tok[pos+1:])
		kv[key] = val
	}
	return cmd, kv
}

func parseBool01(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "1" || s == "true" || s == "yes"
}

func (d *daemon) handleIPCState() string {
	d.mu.RLock()
	term := d.term
	activeIDs := make([]string, 0, len(d.active))
	for id := range d.active {
		activeIDs = append(activeIDs, id)
	}
	d.mu.RUnlock()

	sort.Strings(activeIDs)
	tdInfof("IPC 调用", "STATE result [term=%d] [neighbors=%s]", term, formatNodeSet(activeIDs))
	return fmt.Sprintf("OK term=%d active=%s", term, strings.Join(activeIDs, ","))
}

func (d *daemon) handleIPCPlan(exclude string) string {
	tdInfof("IPC 调用", "PLAN request [exclude=%q]", exclude)

	type nhEntry struct {
		peer       PeerDescriptor
		latestSnap *NeighborSnapshot
	}

	d.mu.RLock()
	selfID := d.self.PeerID
	localTerm := d.term

	nhs := make([]nhEntry, 0, len(d.active))
	for _, p := range d.active {
		if p.PeerID == "" || p.PeerID == exclude {
			continue
		}
		entry := nhEntry{peer: p.Clone()}
		if ring := d.neighborHistory[p.PeerID]; ring != nil {
			if snap, ok := ring.Latest(); ok {
				snapCopy := snap
				entry.latestSnap = &snapCopy
			}
		}
		nhs = append(nhs, entry)
	}

	localActive := make([]PeerDescriptor, 0, len(d.active))
	for _, p := range d.active {
		localActive = append(localActive, p.Clone())
	}
	d.mu.RUnlock()

	if len(nhs) == 0 {
		return "NOT_FOUND reason=no_active_neighbor"
	}

	d.randMu.Lock()
	d.rnd.Shuffle(len(nhs), func(i, j int) {
		nhs[i], nhs[j] = nhs[j], nhs[i]
	})
	d.randMu.Unlock()

	for _, item := range nhs {
		if item.latestSnap == nil {
			continue
		}

		nnh, ok := pickCandidate(item.latestSnap.Active, map[string]struct{}{
			selfID:           {},
			item.peer.PeerID: {},
			exclude:          {},
		}, d)
		if !ok {
			continue
		}

		if !item.peer.ValidForRoute() || !nnh.ValidForRoute() {
			continue
		}

		term := item.latestSnap.Term
		if term == 0 {
			term = localTerm
		}
		if term == 0 {
			term = 1
		}

		tdInfof(
			"IPC 调用",
			"PLAN result [exclude=%q] [term=%d] [nh=%s] [nh_neighbors=%s] [nnh=%s] [source=history]",
			exclude,
			term,
			item.peer.PeerID,
			formatNodeSet(peerIDs(item.latestSnap.Active)),
			nnh.PeerID,
		)
		return formatPlanResponse(term, item.peer, nnh)
	}

	// Fallback: pick NNH from our local active view and synthesize history for NH.
	for _, item := range nhs {
		nnh, ok := pickCandidate(localActive, map[string]struct{}{
			selfID:           {},
			item.peer.PeerID: {},
			exclude:          {},
		}, d)
		if !ok {
			continue
		}
		if !item.peer.ValidForRoute() || !nnh.ValidForRoute() {
			continue
		}

		term := localTerm
		if term == 0 {
			term = 1
		}

		synthetic := NeighborSnapshot{
			OwnerPeerID: item.peer.PeerID,
			Term:        term,
			Active:      filterPeers(localActive, map[string]struct{}{item.peer.PeerID: {}, selfID: {}}),
			TimestampMs: nowMs(),
		}
		d.storeNeighborSnapshot(synthetic, true)

		tdInfof(
			"IPC 调用",
			"PLAN result [exclude=%q] [term=%d] [nh=%s] [nh_neighbors=%s] [nnh=%s] [source=fallback_local_active]",
			exclude,
			term,
			item.peer.PeerID,
			formatNodeSet(peerIDs(synthetic.Active)),
			nnh.PeerID,
		)
		return formatPlanResponse(term, item.peer, nnh)
	}

	tdWarnf("IPC 调用", "PLAN result [exclude=%q] [status=NOT_FOUND] [reason=no_nnh_candidate]", exclude)
	return "NOT_FOUND reason=no_nnh_candidate"
}

func (d *daemon) handleIPCHistory(peerID string, term uint64, exclude string, strict bool) string {
	tdInfof("IPC 调用", "HISTORY request [peer=%s] [term=%d] [exclude=%q] [strict=%t]", peerID, term, exclude, strict)

	if peerID == "" || term == 0 {
		tdWarnf("IPC 调用", "HISTORY result [peer=%s] [term=%d] [status=ERR] [reason=invalid_args]", peerID, term)
		return "ERR reason=invalid_args"
	}

	selfID := d.self.PeerID
	var (
		snapFound bool
		snap      NeighborSnapshot
		localAct  []PeerDescriptor
	)

	d.mu.RLock()
	if ring := d.neighborHistory[peerID]; ring != nil {
		if s, ok := ring.Get(term); ok {
			snap = s
			snapFound = true
		}
	}
	if !strict {
		localAct = make([]PeerDescriptor, 0, len(d.active))
		for _, p := range d.active {
			localAct = append(localAct, p.Clone())
		}
	}
	d.mu.RUnlock()

	if !snapFound {
		persisted, err := d.store.Lookup(peerID, term)
		if err != nil {
			tdWarnf("History 查询", "lookup failed [peer=%s] [term=%d] [err=%v]", peerID, term, err)
		} else if persisted != nil {
			snap = *persisted
			snapFound = true
			d.storeNeighborSnapshot(snap, false)
		}
	}

	if snapFound {
		nnh, ok := pickCandidate(snap.Active, map[string]struct{}{
			selfID:  {},
			peerID:  {},
			exclude: {},
		}, d)
		if ok && nnh.ValidForRoute() {
			tdInfof(
				"IPC 调用",
				"HISTORY result [peer=%s] [term=%d] [nnh=%s] [snapshot_neighbors=%s] [source=snapshot]",
				peerID,
				term,
				nnh.PeerID,
				formatNodeSet(peerIDs(snap.Active)),
			)
			return formatHistoryResponse(nnh)
		}
	}

	if strict {
		tdWarnf(
			"IPC 调用",
			"HISTORY result [peer=%s] [term=%d] [status=NOT_FOUND] [reason=no_candidate_in_snapshot] [snapshot_neighbors=%s]",
			peerID,
			term,
			formatNodeSet(peerIDs(snap.Active)),
		)
		return "NOT_FOUND reason=no_candidate_in_snapshot"
	}

	nnh, ok := pickCandidate(localAct, map[string]struct{}{
		selfID:  {},
		peerID:  {},
		exclude: {},
	}, d)
	if !ok || !nnh.ValidForRoute() {
		tdWarnf(
			"IPC 调用",
			"HISTORY result [peer=%s] [term=%d] [status=NOT_FOUND] [reason=no_fallback_candidate] [local_active=%s]",
			peerID,
			term,
			formatNodeSet(peerIDs(localAct)),
		)
		return "NOT_FOUND reason=no_fallback_candidate"
	}
	tdInfof(
		"IPC 调用",
		"HISTORY result [peer=%s] [term=%d] [nnh=%s] [local_active=%s] [source=fallback_local_active]",
		peerID,
		term,
		nnh.PeerID,
		formatNodeSet(peerIDs(localAct)),
	)
	return formatHistoryResponse(nnh)
}

func (d *daemon) storeNeighborSnapshot(snap NeighborSnapshot, persist bool) {
	if snap.OwnerPeerID == "" || snap.Term == 0 {
		return
	}
	snap.Active = clonePeers(snap.Active)
	if snap.TimestampMs == 0 {
		snap.TimestampMs = nowMs()
	}

	changed := false

	d.mu.Lock()
	ring := d.ensureNeighborRingLocked(snap.OwnerPeerID)
	old, ok := ring.Get(snap.Term)
	if !ok || !peersEqual(old.Active, snap.Active) {
		ring.Put(snap)
		d.historyMeta[snap.OwnerPeerID] = nowMs()
		d.gcNeighborHistoryLocked()
		changed = true
	}
	d.mu.Unlock()

	if persist && changed {
		if err := d.store.Append("twohop", snap); err != nil {
			tdWarnf("History 持久化", "persist snapshot failed [peer=%s] [term=%d] [err=%v]", snap.OwnerPeerID, snap.Term, err)
		}
	}
}

func pickCandidate(peers []PeerDescriptor, exclude map[string]struct{}, d *daemon) (PeerDescriptor, bool) {
	cands := filterPeers(peers, exclude)
	if len(cands) == 0 {
		return PeerDescriptor{}, false
	}
	return d.pickRandomPeer(cands)
}

func filterPeers(peers []PeerDescriptor, exclude map[string]struct{}) []PeerDescriptor {
	out := make([]PeerDescriptor, 0, len(peers))
	seen := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		p = p.Clone()
		if p.PeerID == "" {
			continue
		}
		if _, skip := exclude[p.PeerID]; skip {
			continue
		}
		if _, dup := seen[p.PeerID]; dup {
			continue
		}
		seen[p.PeerID] = struct{}{}
		out = append(out, p)
	}
	return out
}

func formatPlanResponse(term uint64, nh, nnh PeerDescriptor) string {
	return fmt.Sprintf(
		"OK term=%d nh_id=%s nh_ip=%s nh_port=%d nh_pub=%s nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
		term,
		nh.PeerID, nh.IP, nh.DraughtsPort, nh.PubKey,
		nnh.PeerID, nnh.IP, nnh.DraughtsPort, nnh.PubKey,
	)
}

func formatHistoryResponse(nnh PeerDescriptor) string {
	return fmt.Sprintf(
		"OK nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
		nnh.PeerID, nnh.IP, nnh.DraughtsPort, nnh.PubKey,
	)
}

func peerIDs(peers []PeerDescriptor) []string {
	ids := make([]string, 0, len(peers))
	seen := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		id := strings.TrimSpace(p.PeerID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func formatNodeSet(ids []string) string {
	if len(ids) == 0 {
		return "{}"
	}
	cp := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		cp = append(cp, id)
	}
	sort.Strings(cp)
	if len(cp) == 0 {
		return "{}"
	}
	return "{" + strings.Join(cp, ",") + "}"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config/topod/nodeX.json>\n", os.Args[0])
		os.Exit(2)
	}

	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		tdErrorf("Config 配置", "load config failed [err=%v]", err)
		os.Exit(2)
	}

	d, err := newDaemon(cfg)
	if err != nil {
		tdErrorf("Bootstrap 启动", "init daemon failed [err=%v]", err)
		os.Exit(2)
	}

	if err := d.start(); err != nil {
		tdErrorf("Bootstrap 启动", "start failed [err=%v]", err)
		os.Exit(2)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-sigCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	d.stop(shutdownCtx)
}
