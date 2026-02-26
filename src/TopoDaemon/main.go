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
	defaultSnapshotLimit       = 10
	defaultShuffleIntervalMs   = 30000
	defaultKeepaliveIntervalMs = 8000
	defaultJoinRetryMs         = 1200

	lockWaitWarnDuration      = 200 * time.Millisecond
	lockHoldWarnDuration      = 800 * time.Millisecond
	slowOperationWarnDuration = 1500 * time.Millisecond
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
	Kind     string          `json:"kind"`
	From     string          `json:"from,omitempty"`
	To       string          `json:"to,omitempty"`
	Join     string          `json:"join,omitempty"`
	Origin   string          `json:"origin,omitempty"`
	TTL      int             `json:"ttl,omitempty"`
	Priority bool            `json:"priority,omitempty"`
	Active   []string        `json:"active,omitempty"`
	Passive  []string        `json:"passive,omitempty"`
	Snapshot *SnapshotRecord `json:"snapshot,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

func summarizeMessage(m h.Message) string {
	if m == nil {
		return "nil"
	}
	return fmt.Sprintf("kind=%s from=%s to=%s", m.Type(), m.From().Addr(), m.To().Addr())
}

func summarizeWireMessage(w wireMessage) string {
	summary := fmt.Sprintf("kind=%s from=%s to=%s", w.Kind, w.From, w.To)
	if w.Join != "" {
		summary += " join=" + w.Join
	}
	if w.Origin != "" {
		summary += " origin=" + w.Origin
	}
	if w.TTL != 0 {
		summary += fmt.Sprintf(" ttl=%d", w.TTL)
	}
	if len(w.Active) > 0 {
		summary += fmt.Sprintf(" active=%d", len(w.Active))
	}
	if len(w.Passive) > 0 {
		summary += fmt.Sprintf(" passive=%d", len(w.Passive))
	}
	if w.Snapshot != nil {
		summary += fmt.Sprintf(" snapshot(peer=%s term=%d n=%d)", w.Snapshot.PeerID, w.Snapshot.Term, len(w.Snapshot.Neighbors))
	}
	if w.Reason != "" {
		summary += " reason=" + w.Reason
	}
	return summary
}

type hvTransport struct {
	daemon *TopoDaemon
}

func (t *hvTransport) Send(m h.Message) (*h.NeighborRefuse, error) {
	start := time.Now()
	t.daemon.logger.Printf("info: [overlay] 准备发送成员消息 %s", summarizeMessage(m))
	req, err := t.daemon.encodeMembershipMessage(m)
	if err != nil {
		t.daemon.logger.Printf("warn: [overlay] 成员消息编码失败 %s err=%v", summarizeMessage(m), err)
		return nil, err
	}
	resp, err := t.daemon.exchangeOverlay(m.To().Addr(), req)
	if err != nil {
		t.daemon.logger.Printf("warn: [overlay] 成员消息发送失败 %s err=%v elapsed=%s", summarizeMessage(m), err, time.Since(start))
		return nil, err
	}
	if resp.Kind == "neighbor_refuse" {
		t.daemon.logger.Printf("info: [overlay] 对端拒绝邻居请求 %s elapsed=%s", summarizeMessage(m), time.Since(start))
		return h.NewNeighborRefuse(m.From(), m.To()), nil
	}
	cost := time.Since(start)
	if cost >= slowOperationWarnDuration {
		t.daemon.logger.Printf("warn: [overlay] 成员消息发送耗时较久 %s elapsed=%s", summarizeMessage(m), cost)
	}
	return nil, nil
}

func (t *hvTransport) Failed(n h.Node) {
	t.daemon.logger.Printf("warn: [overlay] 发送失败，已标记节点失效 addr=%s", n.Addr())
}

func (t *hvTransport) Bootstrap() h.Node {
	t.daemon.logger.Printf("info: [bootstrap] Hyparview 请求选择引导节点")
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

func (d *TopoDaemon) lockWithTrace(scene string) time.Time {
	waitStart := time.Now()
	d.mu.Lock()
	waitCost := time.Since(waitStart)
	if waitCost >= lockWaitWarnDuration {
		d.logger.Printf("warn: [锁] 获取互斥锁等待较久 scene=%s wait=%s", scene, waitCost)
	}
	return time.Now()
}

func (d *TopoDaemon) unlockWithTrace(scene string, holdStart time.Time) {
	holdCost := time.Since(holdStart)
	if holdCost >= lockHoldWarnDuration {
		d.logger.Printf("warn: [锁] 持有互斥锁时长较久 scene=%s hold=%s", scene, holdCost)
	}
	d.mu.Unlock()
}

func (d *TopoDaemon) lockState(scene string) func() {
	holdStart := d.lockWithTrace(scene)
	return func() {
		d.unlockWithTrace(scene, holdStart)
	}
}

func (d *TopoDaemon) viewStatsLocked() string {
	return fmt.Sprintf("active=%d passive=%d term=%d", d.hv.Active.Size(), d.hv.Passive.Size(), d.term)
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

func loadPeerInfoDir(dir string, logger *log.Logger) (map[string]PeerInfo, map[string]PeerInfo, error) {
	if logger != nil {
		logger.Printf("info: [启动] 开始加载 peer 目录 dir=%s", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]PeerInfo)
	byTopo := make(map[string]PeerInfo)
	skipped := 0
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		info, err := parsePeerInfo(path)
		if err != nil {
			skipped++
			if logger != nil {
				logger.Printf("warn: [启动] 跳过无效 peer 文件 path=%s err=%v", path, err)
			}
			continue
		}
		byID[info.PeerID] = info
		if info.TopodAddr != "" {
			byTopo[info.TopodAddr] = info
		}
		if logger != nil {
			logger.Printf("info: [启动] 已加载 peer peer_id=%s topod=%s draughts=%s:%d",
				info.PeerID, info.TopodAddr, info.DraughtsIP(), info.DraughtsPort)
		}
	}
	if len(byID) == 0 {
		return nil, nil, fmt.Errorf("no peer info loaded from %s", dir)
	}
	if logger != nil {
		logger.Printf("info: [启动] peer 目录加载完成 valid=%d topod=%d skipped=%d", len(byID), len(byTopo), skipped)
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
	d.logger.Printf("info: [启动] TopoDaemon 初始化完成 peer_id=%s listen=%s peers=%d peers_with_topod=%d active_max=%d passive_max=%d",
		cfg.PeerID, cfg.ListenAddr, len(peersByID), len(peersByTopo), d.hv.Active.Max, d.hv.Passive.Max)
	return d
}

func (d *TopoDaemon) Start() error {
	d.logger.Printf("info: [启动] 开始监听 overlay=%s ipc=%s", d.cfg.ListenAddr, d.cfg.IPCSocket)
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
	d.logger.Printf("info: [启动] 后台循环已启动: overlay_accept/ipc_accept/bootstrap/shuffle/keepalive")

	return nil
}

func (d *TopoDaemon) Stop() {
	d.logger.Printf("info: [停止] 收到停止请求，开始关闭监听与后台循环")
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
	d.logger.Printf("info: [停止] TopoDaemon 已完成停止")
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
	d.logger.Printf("info: [overlay] 接收循环已启动")
	for {
		conn, err := d.overlayLn.Accept()
		if err != nil {
			if d.isStopping() {
				d.logger.Printf("info: [overlay] 接收循环退出（正在停止）")
				return
			}
			d.logger.Printf("warn: [overlay] accept 失败 err=%v", err)
			continue
		}
		d.logger.Printf("info: [overlay] 接收到连接 remote=%s", conn.RemoteAddr())
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleOverlayConn(conn)
		}()
	}
}

func (d *TopoDaemon) handleOverlayConn(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)

	var req wireMessage
	if err := dec.Decode(&req); err != nil {
		d.logger.Printf("warn: [overlay] 解析请求失败 remote=%s err=%v", remote, err)
		_ = enc.Encode(wireMessage{Kind: "err", Reason: "bad_request"})
		return
	}
	d.logger.Printf("info: [overlay] 收到请求 remote=%s %s", remote, summarizeWireMessage(req))

	resp := d.handleOverlayMessage(req)
	if err := enc.Encode(resp); err != nil {
		d.logger.Printf("warn: [overlay] 写回响应失败 remote=%s err=%v", remote, err)
		return
	}
	cost := time.Since(start)
	if cost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [overlay] 请求处理耗时较久 remote=%s elapsed=%s req={%s} resp={%s}",
			remote, cost, summarizeWireMessage(req), summarizeWireMessage(resp))
	} else {
		d.logger.Printf("info: [overlay] 请求处理完成 remote=%s elapsed=%s resp={%s}", remote, cost, summarizeWireMessage(resp))
	}
}

func (d *TopoDaemon) handleOverlayMessage(req wireMessage) wireMessage {
	start := time.Now()
	switch req.Kind {
	case "snapshot":
		if req.Snapshot != nil {
			d.logger.Printf("info: [快照] 收到快照 peer=%s term=%d neighbors=%d",
				req.Snapshot.PeerID, req.Snapshot.Term, len(req.Snapshot.Neighbors))
			d.storeSnapshot(*req.Snapshot)
		} else {
			d.logger.Printf("warn: [快照] 收到空快照请求")
		}
		if cost := time.Since(start); cost >= slowOperationWarnDuration {
			d.logger.Printf("warn: [快照] 处理快照耗时较久 elapsed=%s", cost)
		}
		return wireMessage{Kind: "ack", From: d.cfg.ListenAddr}
	default:
		msg, err := d.decodeMembershipMessage(req)
		if err != nil {
			d.logger.Printf("warn: [overlay] 成员消息解码失败 req={%s} err=%v", summarizeWireMessage(req), err)
			return wireMessage{Kind: "err", Reason: "decode_failed"}
		}
		d.logger.Printf("info: [overlay] 处理成员消息 %s", summarizeMessage(msg))
		refuse := d.recvMembership(msg)
		if refuse != nil {
			d.logger.Printf("info: [overlay] 成员消息被拒绝 %s", summarizeMessage(msg))
			return wireMessage{Kind: "neighbor_refuse", From: d.cfg.ListenAddr}
		}
		if cost := time.Since(start); cost >= slowOperationWarnDuration {
			d.logger.Printf("warn: [overlay] 成员消息处理耗时较久 elapsed=%s message={%s}", cost, summarizeMessage(msg))
		}
		return wireMessage{Kind: "ack", From: d.cfg.ListenAddr}
	}
}

func (d *TopoDaemon) acceptIPCLoop() {
	defer d.wg.Done()
	d.logger.Printf("info: [IPC] 接收循环已启动 socket=%s", d.cfg.IPCSocket)
	for {
		conn, err := d.ipcLn.Accept()
		if err != nil {
			if d.isStopping() {
				d.logger.Printf("info: [IPC] 接收循环退出（正在停止）")
				return
			}
			d.logger.Printf("warn: [IPC] accept 失败 err=%v", err)
			continue
		}
		d.logger.Printf("info: [IPC] 收到连接 remote=%s", conn.RemoteAddr())
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleIPCConn(conn)
		}()
	}
}

func (d *TopoDaemon) handleIPCConn(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		d.logger.Printf("warn: [IPC] 读取请求失败 remote=%s err=%v", remote, err)
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		d.logger.Printf("warn: [IPC] 空请求 remote=%s", remote)
		return
	}
	d.logger.Printf("info: [IPC] 收到请求 remote=%s req=%q", remote, line)
	resp := d.handleIPCRequest(line)
	if _, err := io.WriteString(conn, resp+"\n"); err != nil {
		d.logger.Printf("warn: [IPC] 发送响应失败 remote=%s err=%v", remote, err)
		return
	}
	cost := time.Since(start)
	if cost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [IPC] 请求处理耗时较久 remote=%s elapsed=%s req=%q resp=%q", remote, cost, line, resp)
	} else {
		d.logger.Printf("info: [IPC] 请求处理完成 remote=%s elapsed=%s resp=%q", remote, cost, resp)
	}
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
	start := time.Now()
	fields := strings.Fields(line)
	if len(fields) == 0 {
		d.logger.Printf("warn: [IPC] 请求为空白行")
		return "ERR reason=empty_request"
	}
	cmd := strings.ToUpper(fields[0])
	kv := parseKV(fields[1:])
	d.logger.Printf("info: [IPC] 开始处理命令 cmd=%s kv=%v", cmd, kv)

	var resp string
	switch cmd {
	case "STATE":
		term, active := d.getState()
		resp = fmt.Sprintf("OK term=%d active=%s", term, strings.Join(active, ","))

	case "PLAN":
		exclude := kv["exclude"]
		plan, reason, ok := d.planRoute(exclude)
		if !ok {
			resp = "ERR reason=" + reason
			break
		}
		resp = fmt.Sprintf("OK term=%d nh_id=%s nh_ip=%s nh_port=%d nh_pub=%s nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
			plan.Term,
			plan.NH.PeerID, plan.NH.DraughtsIP(), plan.NH.DraughtsPort, plan.NH.PubKey,
			plan.NNH.PeerID, plan.NNH.IP, plan.NNH.Port, plan.NNH.PubKey)

	case "HISTORY":
		peerID := kv["peer"]
		if peerID == "" {
			resp = "ERR reason=missing_peer"
			break
		}
		term, err := strconv.ParseUint(kv["term"], 10, 64)
		if err != nil {
			resp = "ERR reason=bad_term"
			break
		}
		exclude := kv["exclude"]
		strict := kv["strict"] == "1" || strings.EqualFold(kv["strict"], "true")

		nnh, reason, found := d.lookupHistoryNeighbor(peerID, term, exclude, strict)
		if !found {
			if reason == "term_not_found" {
				resp = "NOT_FOUND reason=" + reason
				break
			}
			resp = "ERR reason=" + reason
			break
		}
		resp = fmt.Sprintf("OK term=%d nnh_id=%s nnh_ip=%s nnh_port=%d nnh_pub=%s",
			term, nnh.PeerID, nnh.IP, nnh.Port, nnh.PubKey)

	default:
		resp = "ERR reason=unknown_command"
	}

	cost := time.Since(start)
	if strings.HasPrefix(resp, "ERR") || strings.HasPrefix(resp, "NOT_FOUND") {
		d.logger.Printf("warn: [IPC] 命令处理结果 cmd=%s elapsed=%s resp=%q", cmd, cost, resp)
	} else if cost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [IPC] 命令处理耗时较久 cmd=%s elapsed=%s resp=%q", cmd, cost, resp)
	} else {
		d.logger.Printf("info: [IPC] 命令处理成功 cmd=%s elapsed=%s", cmd, cost)
	}
	return resp
}

type RoutePlan struct {
	Term uint64
	NH   PeerInfo
	NNH  SnapshotNeighbor
}

func (d *TopoDaemon) getState() (uint64, []string) {
	unlock := d.lockState("getState")
	defer unlock()
	active := d.activePeerIDsLocked("")
	d.logger.Printf("info: [状态] 查询 active=%d term=%d", len(active), d.term)
	return d.term, active
}

func (d *TopoDaemon) planRoute(exclude string) (RoutePlan, string, bool) {
	start := time.Now()
	unlock := d.lockState("planRoute")
	defer unlock()
	d.logger.Printf("info: [路由规划] 开始 PLAN exclude=%q %s", exclude, d.viewStatsLocked())

	nhCandidates := d.activePeerInfosLocked(exclude)
	if len(nhCandidates) == 0 {
		d.logger.Printf("warn: [路由规划] 失败: 无可用一跳邻居 exclude=%q", exclude)
		return RoutePlan{}, "no_active_neighbor", false
	}
	nh := nhCandidates[d.randIntn(len(nhCandidates))]
	d.logger.Printf("info: [路由规划] 选择一跳 nh=%s topod=%s draughts=%s:%d 候选=%d",
		nh.PeerID, nh.TopodAddr, nh.DraughtsIP(), nh.DraughtsPort, len(nhCandidates))

	hist := d.history[nh.PeerID]
	if len(hist) == 0 {
		d.logger.Printf("warn: [路由规划] 失败: 一跳节点无历史快照 nh=%s", nh.PeerID)
		return RoutePlan{}, "no_snapshot_for_nh", false
	}
	latest := hist[len(hist)-1]
	d.logger.Printf("info: [路由规划] 使用一跳最新快照 nh=%s term=%d neighbors=%d hist_len=%d",
		nh.PeerID, latest.Term, len(latest.Neighbors), len(hist))

	cands := filterSnapshotNeighbors(latest.Neighbors, d.cfg.PeerID, nh.PeerID, exclude)
	if len(cands) == 0 {
		d.logger.Printf("warn: [路由规划] 失败: 一跳快照内无可用二跳 nh=%s term=%d", nh.PeerID, latest.Term)
		return RoutePlan{}, "no_nnh_candidate", false
	}
	nnh := cands[d.randIntn(len(cands))]
	if nnh.IP == "" || nnh.Port == 0 || nnh.PubKey == "" {
		d.logger.Printf("warn: [路由规划] 失败: 二跳记录字段非法 nnh=%+v", nnh)
		return RoutePlan{}, "invalid_nnh_record", false
	}

	if nh.DraughtsIP() == "" || nh.DraughtsPort == 0 || nh.PubKey == "" {
		d.logger.Printf("warn: [路由规划] 失败: 一跳记录字段非法 nh=%+v", nh)
		return RoutePlan{}, "invalid_nh_record", false
	}

	cost := time.Since(start)
	if cost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [路由规划] PLAN 成功但耗时较久 elapsed=%s nh=%s nnh=%s term=%d",
			cost, nh.PeerID, nnh.PeerID, latest.Term)
	} else {
		d.logger.Printf("info: [路由规划] PLAN 成功 elapsed=%s nh=%s nnh=%s term=%d",
			cost, nh.PeerID, nnh.PeerID, latest.Term)
	}
	return RoutePlan{Term: latest.Term, NH: nh, NNH: nnh}, "", true
}

func (d *TopoDaemon) lookupHistoryNeighbor(peerID string, term uint64, exclude string, strict bool) (SnapshotNeighbor, string, bool) {
	start := time.Now()
	unlock := d.lockState("lookupHistoryNeighbor")
	defer unlock()
	d.logger.Printf("info: [历史查询] 开始 peer=%s term=%d exclude=%q strict=%v", peerID, term, exclude, strict)

	hist := d.history[peerID]
	if len(hist) == 0 {
		d.logger.Printf("warn: [历史查询] 未命中: peer=%s 无历史记录", peerID)
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
		d.logger.Printf("warn: [历史查询] 未命中: peer=%s 无 term=%d 快照", peerID, term)
		return SnapshotNeighbor{}, "term_not_found", false
	}

	cands := filterSnapshotNeighbors(rec.Neighbors, d.cfg.PeerID, peerID, exclude)
	if len(cands) == 0 {
		if strict {
			d.logger.Printf("warn: [历史查询] 严格模式无二跳候选 peer=%s term=%d", peerID, term)
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
			d.logger.Printf("warn: [历史查询] 回退到 active 仍无候选 peer=%s term=%d", peerID, term)
			return SnapshotNeighbor{}, "no_nnh_candidate", false
		}
		pick := out[d.randIntn(len(out))]
		d.logger.Printf("info: [历史查询] 回退成功 peer=%s term=%d nnh=%s candidates=%d elapsed=%s",
			peerID, term, pick.PeerID, len(out), time.Since(start))
		return pick, "", true
	}

	pick := cands[d.randIntn(len(cands))]
	d.logger.Printf("info: [历史查询] 命中快照 peer=%s term=%d nnh=%s candidates=%d elapsed=%s",
		peerID, term, pick.PeerID, len(cands), time.Since(start))
	return pick, "", true
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
		d.logger.Printf("warn: [快照] 忽略快照: peer_id 为空")
		return
	}
	if rec.Term == 0 {
		d.logger.Printf("warn: [快照] 忽略快照: term=0 peer=%s", rec.PeerID)
		return
	}
	unlock := d.lockState("storeSnapshot")
	defer unlock()
	before := len(d.history[rec.PeerID])
	d.appendHistoryLocked(rec.PeerID, rec)
	after := len(d.history[rec.PeerID])
	d.logger.Printf("info: [快照] 已存储 peer=%s term=%d neighbors=%d history_len=%d->%d",
		rec.PeerID, rec.Term, len(rec.Neighbors), before, after)
}

func (d *TopoDaemon) recvMembership(msg h.Message) *h.NeighborRefuse {
	start := time.Now()
	d.logger.Printf("info: [拓扑变更] 收到成员消息，准备应用 %s", summarizeMessage(msg))
	var refuse *h.NeighborRefuse
	changed, snapshot, targets := d.applyMutation(func() {
		refuse = d.hv.Recv(msg)
	})
	if changed {
		d.logger.Printf("info: [拓扑变更] 视图发生变化，广播快照 term=%d targets=%d", snapshot.Term, len(targets))
		d.broadcastSnapshot(snapshot, targets)
	} else {
		d.logger.Printf("info: [拓扑变更] 视图未变化，不广播快照")
	}
	if refuse != nil {
		d.logger.Printf("info: [拓扑变更] 处理完成：返回 neighbor_refuse elapsed=%s", time.Since(start))
	} else {
		d.logger.Printf("info: [拓扑变更] 处理完成：返回 ack elapsed=%s", time.Since(start))
	}
	return refuse
}

func (d *TopoDaemon) applyMutation(fn func()) (bool, SnapshotRecord, []string) {
	start := time.Now()
	unlock := d.lockState("applyMutation")
	defer unlock()

	before := d.activeSignatureLocked()
	beforeStats := d.viewStatsLocked()
	d.logger.Printf("info: [拓扑变更] applyMutation 开始 before=%q %s", before, beforeStats)
	fnStart := time.Now()
	fn()
	fnCost := time.Since(fnStart)
	if fnCost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [拓扑变更] 变更函数执行耗时较久 elapsed=%s", fnCost)
	}
	after := d.activeSignatureLocked()
	if before == after {
		d.logger.Printf("info: [拓扑变更] active 视图未变化 after=%q elapsed=%s", after, time.Since(start))
		return false, SnapshotRecord{}, nil
	}
	d.term++
	snapshot := d.buildLocalSnapshotLocked()
	d.appendHistoryLocked(d.cfg.PeerID, snapshot)
	targets := d.activeAddrsLocked()
	d.logger.Printf("info: [拓扑变更] active 视图已变化 before=%q after=%q term=%d targets=%d elapsed=%s",
		before, after, d.term, len(targets), time.Since(start))
	return true, snapshot, targets
}

func (d *TopoDaemon) broadcastSnapshot(snapshot SnapshotRecord, targets []string) {
	start := time.Now()
	req := wireMessage{
		Kind:     "snapshot",
		From:     d.cfg.ListenAddr,
		Snapshot: &snapshot,
	}
	d.logger.Printf("info: [快照广播] 开始广播 from=%s term=%d neighbors=%d targets=%d",
		snapshot.PeerID, snapshot.Term, len(snapshot.Neighbors), len(targets))
	okCount := 0
	failCount := 0
	for _, addr := range targets {
		if addr == "" || addr == d.cfg.ListenAddr {
			continue
		}
		oneStart := time.Now()
		if _, err := d.exchangeOverlay(addr, req); err != nil {
			failCount++
			d.logger.Printf("warn: [快照广播] 发送失败 to=%s term=%d err=%v elapsed=%s", addr, snapshot.Term, err, time.Since(oneStart))
		} else {
			okCount++
			d.logger.Printf("info: [快照广播] 发送成功 to=%s term=%d elapsed=%s", addr, snapshot.Term, time.Since(oneStart))
		}
	}
	totalCost := time.Since(start)
	if totalCost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [快照广播] 完成但耗时较久 term=%d success=%d fail=%d elapsed=%s",
			snapshot.Term, okCount, failCount, totalCost)
	} else {
		d.logger.Printf("info: [快照广播] 完成 term=%d success=%d fail=%d elapsed=%s",
			snapshot.Term, okCount, failCount, totalCost)
	}
}

func (d *TopoDaemon) bootstrapLoop() {
	defer d.wg.Done()
	t := time.NewTicker(time.Duration(d.cfg.JoinRetryMs) * time.Millisecond)
	defer t.Stop()
	d.logger.Printf("info: [bootstrap] 循环已启动 interval=%dms", d.cfg.JoinRetryMs)

	for {
		select {
		case <-d.stopCh:
			d.logger.Printf("info: [bootstrap] 循环退出")
			return
		case <-t.C:
			unlock := d.lockState("bootstrapLoop.checkEmpty")
			empty := d.hv.Active.IsEmpty()
			state := d.viewStatsLocked()
			unlock()
			d.logger.Printf("info: [bootstrap] 定时触发 active_empty=%v %s", empty, state)
			if !empty {
				continue
			}
			boot := d.pickBootstrapNode()
			if boot == nil {
				d.logger.Printf("warn: [bootstrap] 无可用引导节点，跳过本轮")
				continue
			}
			d.logger.Printf("info: [bootstrap] 选择引导节点=%s，发送 Join", boot.Addr())
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
	d.logger.Printf("info: [shuffle] 循环已启动 interval=%dms", d.cfg.ShuffleIntervalMs)
	for {
		select {
		case <-d.stopCh:
			d.logger.Printf("info: [shuffle] 循环退出")
			return
		case <-t.C:
			d.logger.Printf("info: [shuffle] 定时触发，准备发送 Shuffle")
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
	d.logger.Printf("info: [keepalive] 循环已启动 interval=%dms", d.cfg.KeepaliveIntervalMs)
	for {
		select {
		case <-d.stopCh:
			d.logger.Printf("info: [keepalive] 循环退出")
			return
		case <-t.C:
			d.logger.Printf("info: [keepalive] 定时触发，开始发送 keepalive 并尝试提升被动邻居")
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
		d.logger.Printf("warn: [bootstrap] 候选列表为空")
		return nil
	}
	pick := candidates[d.randIntn(len(candidates))]
	d.logger.Printf("info: [bootstrap] 候选=%d，选中=%s", len(candidates), pick)
	return h.NewNode(pick)
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
	d.logger.Printf("info: [编码] 成员消息编码完成 %s => %s", summarizeMessage(m), summarizeWireMessage(base))
	return base, nil
}

func (d *TopoDaemon) decodeMembershipMessage(req wireMessage) (h.Message, error) {
	self := d.selfNode
	from := h.NewNode(req.From)
	var msg h.Message
	switch req.Kind {
	case "join":
		msg = h.NewJoin(self, from)
	case "forward_join":
		if req.Join == "" {
			return nil, errors.New("missing join field")
		}
		msg = h.NewForwardJoin(self, from, h.NewNode(req.Join), req.TTL)
	case "disconnect":
		msg = h.NewDisconnect(self, from)
	case "neighbor":
		msg = h.NewNeighbor(self, from, req.Priority)
	case "shuffle":
		origin := req.Origin
		if origin == "" {
			origin = req.From
		}
		msg1 := h.NewShuffle(self, from, h.NewNode(origin), addrsToNodes(req.Active), addrsToNodes(req.Passive), req.TTL)
		msg1.Origin = h.NewNode(origin)
		msg = msg1
	case "shuffle_reply":
		msg = h.NewShuffleReply(self, from, addrsToNodes(req.Passive))
	default:
		return nil, fmt.Errorf("unknown kind: %s", req.Kind)
	}
	d.logger.Printf("info: [解码] 成员消息解码完成 req={%s} => %s", summarizeWireMessage(req), summarizeMessage(msg))
	return msg, nil
}

func (d *TopoDaemon) exchangeOverlay(addr string, req wireMessage) (wireMessage, error) {
	var zero wireMessage
	start := time.Now()
	d.logger.Printf("info: [overlay] 开始交换 to=%s req={%s}", addr, summarizeWireMessage(req))

	dialStart := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		d.logger.Printf("warn: [overlay] 连接失败 to=%s err=%v elapsed=%s", addr, err, time.Since(dialStart))
		return zero, err
	}
	dialCost := time.Since(dialStart)
	d.logger.Printf("info: [overlay] 连接成功 to=%s elapsed=%s", addr, dialCost)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	encodeStart := time.Now()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		d.logger.Printf("warn: [overlay] 请求写入失败 to=%s err=%v elapsed=%s", addr, err, time.Since(encodeStart))
		return zero, err
	}
	d.logger.Printf("info: [overlay] 请求写入成功 to=%s elapsed=%s", addr, time.Since(encodeStart))

	var resp wireMessage
	decodeStart := time.Now()
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			d.logger.Printf("info: [overlay] 对端提前关闭连接，按 ack 处理 to=%s elapsed=%s", addr, time.Since(decodeStart))
			return wireMessage{Kind: "ack"}, nil
		}
		d.logger.Printf("warn: [overlay] 响应读取失败 to=%s err=%v elapsed=%s", addr, err, time.Since(decodeStart))
		return zero, err
	}
	d.logger.Printf("info: [overlay] 响应读取成功 to=%s elapsed=%s resp={%s}",
		addr, time.Since(decodeStart), summarizeWireMessage(resp))
	if resp.Kind == "err" {
		if resp.Reason == "" {
			resp.Reason = "remote_error"
		}
		d.logger.Printf("warn: [overlay] 对端返回错误 to=%s reason=%s total_elapsed=%s", addr, resp.Reason, time.Since(start))
		return zero, errors.New(resp.Reason)
	}
	totalCost := time.Since(start)
	if totalCost >= slowOperationWarnDuration {
		d.logger.Printf("warn: [overlay] 交换完成但耗时较久 to=%s elapsed=%s req={%s} resp={%s}",
			addr, totalCost, summarizeWireMessage(req), summarizeWireMessage(resp))
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

	logger := log.New(os.Stdout, "[TopoDaemon "+cfg.PeerID+"] ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("info: [启动] 读取配置成功 config=%s listen=%s ipc=%s peer_info_dir=%s snapshot_limit=%d shuffle_ms=%d keepalive_ms=%d join_retry_ms=%d bootstrap=%v",
		cfgPath, cfg.ListenAddr, cfg.IPCSocket, cfg.PeerInfoDir, cfg.SnapshotLimit,
		cfg.ShuffleIntervalMs, cfg.KeepaliveIntervalMs, cfg.JoinRetryMs, cfg.Bootstrap)

	peersByID, peersByTopo, err := loadPeerInfoDir(cfg.PeerInfoDir, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load peer info failed: %v\n", err)
		os.Exit(2)
	}
	if _, ok := peersByID[cfg.PeerID]; !ok {
		fmt.Fprintf(os.Stderr, "self peer_id %s not found in peer_info_dir\n", cfg.PeerID)
		os.Exit(2)
	}
	daemon := newTopoDaemon(cfg, peersByID, peersByTopo, logger)

	if err := daemon.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
		os.Exit(2)
	}
	logger.Printf("info: [启动] 完成 listen=%s ipc=%s snapshot_limit=%d", cfg.ListenAddr, cfg.IPCSocket, cfg.SnapshotLimit)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Printf("info: [停止] 收到系统信号，准备退出")
	daemon.Stop()
}
