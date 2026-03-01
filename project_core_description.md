# draughts_p2p 项目核心描述文件（接口/结构/调用关系版）

## 1. 文档目的与边界
- 目的：用“接口 + 数据结构 + 调用关系”描述项目全貌，便于系统实现章节写作。
- 边界：只保留模块职责、函数接口、协议语义、流程关系；不展开具体算法实现与代码细节。
- 代码范围：
  - `src/ChatCore/*`（C++）
  - `src/TopoDaemon/main.go`（Go）
  - `scripts/*`（配置生成、批量起停、清理、辅助采集）

## 2. 系统总体结构
- 进程与职责：
  - `TopoDaemon`：邻居与局部拓扑维护层（HyParView 风格）
  - `ChatCore`：报文与业务执行层（Draughts packet 处理、CLI、会话）
- 三条通信通道：
  - TopoDaemon <-> TopoDaemon：TCP（overlay，JSON 行协议）
  - ChatCore <-> ChatCore：UDP（固定长度 `DraughtsPacket`）
  - ChatCore <-> TopoDaemon：Unix Domain Socket（文本行 IPC）

## 3. ChatCore（C++）核心信息

### 3.1 入口与运行框架
- 文件：`src/ChatCore/main.cpp`
- 入口：
  - `int main(int argc, char** argv)`
- 启动关系：
  - 读取配置 `load_config`
  - 加载/创建节点身份密钥 `Sm2KeyPair`
  - 构造并启动 `DraughtsNode`
  - 构造并启动 `DraughtsApp`
  - 可选启动 `Cli` 线程
  - `boost::asio::io_context` 驱动异步收发与定时任务

### 3.2 配置对象
- 文件：`src/ChatCore/config.hpp`, `config.cpp`
- 核心结构：
  - `struct Config`
- 关键字段分组：
  - 节点身份与端口：`peer_id`, `bind_ip`, `overlay_port`, `draughts_port`
  - IPC：`topod_ipc_socket`, `topod_timeout_ms`
  - 目录文件：`peer_info_dir`, `self_info_file`, `active_neighbors_file`, `identity_key_file`
  - 路由参数：`ciplc_a/b/c/epsilon/x0`
  - 协议参数：`magic_num`, `session_ttl_ms`, `outnode_ttl_ms`
- 加载接口：
  - `bool load_config(const std::string& path, Config& out, std::string& err)`

### 3.3 网络包与协议结构
- 文件：`src/ChatCore/draughts_packet.hpp`
- 核心结构：
  - `struct DraughtsParams`
    - `pk_pph_tmp`, `pk_init_tmp`
    - `addr_nnh`, `c_addr_real_receiver`, `c_addr_real_sender`
    - `topo_term`, `x`, `magic_num`
  - `struct DraughtsPacket`
    - `pk_ph_tmp`, `params`, `session_id`, `c_data`
- 常量：
  - `kPacketSize = 1280`, `kPkSize = 64`, `kAddrSize = 6`, `kSessionIdSize = 16`

### 3.4 TopoDaemon IPC 客户端（ChatCore 侧）
- 文件：`src/ChatCore/topod_client.hpp`, `topod_client.cpp`
- 核心结构：
  - `TopodClient::HopInfo`
  - `TopodClient::RoutePlan`
  - `TopodClient::StateView`
  - `TopodClient::TwoHopView`
- 对外接口：
  - `bool enabled() const`
  - `bool pick_route(const std::string& exclude_peer_id, RoutePlan& out) const`（PLAN）
  - `bool pick_history_nnh(const std::string& nh_peer_id, uint64_t term, const std::string& exclude_peer_id, bool strict, HopInfo& out) const`（HISTORY）
  - `bool query_state(StateView& out) const`（STATE）
  - `bool query_twohop(TwoHopView& out) const`（TWOHOP）
- 传输方式：
  - Unix Domain Socket（`AF_UNIX + SOCK_STREAM`）
  - 文本行请求/响应（单行）

### 3.5 拓扑缓存与目录管理（DraughtsNode）
- 文件：`src/ChatCore/node.hpp`, `node.cpp`
- 核心类：
  - `class DraughtsNode`
- 关键状态：
  - `active_neighbors_`：当前 active 邻居
  - `directory_`：节点目录（peer_id -> descriptor）
  - `twohop_`：两跳缓存（NH -> NNH 集合）
  - `topod_term_`：最近同步 term
- 对外接口（CLI/上层调用）：
  - `bool start()`, `void stop()`
  - `void cmd_show_id()`, `cmd_show_neighbors()`, `cmd_show_twohop()`, `cmd_show_peers()`
  - `lookup_peer*`, `is_active_neighbor`, `is_twohop_neighbor`
  - `cache_twohop_neighbor(nh, nnh)`
- 内部核心接口：
  - `sync_active_neighbors_from_topod()`
  - `sync_twohop_from_topod()`
  - `prune_twohop_cache()`
  - `update_active_neighbors_file(force)`
  - `load_peer_directory()`
- 行为概述：
  - 周期性拉取 STATE 更新 active view
  - `twohop` CLI 命令触发即时拉取 TWOHOP
  - 维护本地目录映射供 UDP 路由/密钥检索

### 3.6 报文业务引擎（DraughtsApp）
- 文件：`src/ChatCore/draughts_app.hpp`, `draughts_app.cpp`
- 核心类：
  - `class DraughtsApp`
- 核心内部结构：
  - `InboxItem`：CLI 展示消息项
  - `InitiatorSession`：发起方会话（session_id -> 临时密钥/目标）
  - `ResponderValue`：响应方缓存条目
  - `ResponderLru`：`LRU + 哈希索引` 的响应缓存
- 对外接口（CLI触发）：
  - `cmd_send(dest, text)`
  - `cmd_send_session(session_hex, text)`
  - `cmd_reply(session_hex, text)`
  - `cmd_inbox()`, `cmd_requests()`
- 核心运行接口：
  - `start()/stop()`
  - `do_receive()/on_datagram()`
  - `handle_random_walk()`
  - `handle_exit_packet()`
- 路由协作接口：
  - `pick_nh_nnh(..., topo_term, exclude)` -> PLAN
  - `pick_nnh_for_peer_id(..., topo_term, strict)` -> HISTORY
- 会话生命周期：
  - 生成 `session_id`
  - `initiator_sessions_` 维护请求会话
  - `responder_lru_` 维护待回复会话
  - `prune_sessions()` 定期清理过期

### 3.7 CLI 命令分发
- 文件：`src/ChatCore/cli.hpp`, `cli.cpp`
- 核心类：
  - `class Cli`
- 命令路由：
  - `id/neighbors/twohop/peers` -> `DraughtsNode`
  - `send/send_session/reply/inbox/requests` -> `DraughtsApp`
  - `quit` -> 停止 `node + app`
- 调度方式：
  - CLI 线程读取输入
  - 通过 `boost::asio::post` 切换到 `io_context` 线程执行业务

### 3.8 其他支撑模块
- `crypto/Crypto.h`：
  - `AesCtr::Transform*`
  - `Sm2KeyPair`（密钥生成、加载、ECDH、KDF）
- `cipher.hpp/cpp`：
  - `CommutativeCipher::Transform*`（封装 AES-CTR 对称变换）
- `ciplc.hpp/cpp`：
  - `Ciplc::step_and_decide(std::mt19937&)`
- `protocol.hpp/cpp`：
  - `proto::PeerDescriptor` TLV 编解码
- `tlv.hpp/cpp`：
  - TLV 基础读写
- `app_packet.hpp/cpp`：
  - 另一套 `AppPacket` TLV 编解码（兼容/扩展用途）
- `logger`/`console`：
  - 文件日志与线程安全控制台输出

## 4. TopoDaemon（Go）核心信息

### 4.1 入口与生命周期
- 文件：`src/TopoDaemon/main.go`
- 入口：
  - `func main()`
- 启动链：
  - `loadConfig` -> `newDaemon` -> `start`
  - 启动 goroutine：
    - `serveOverlay`
    - `serveIPC`
    - `bootstrapLoop`
    - `keepaliveLoop`
    - `shuffleLoop`
    - `directoryReloadLoop`
    - `snapshotBroadcastLoop`
- 停机：
  - `stop(ctx)` 关闭 listener + 等待 goroutine

### 4.2 核心数据结构
- `type Config`：
  - overlay / ipc 地址、active/passive 阈值、定时参数、history 参数等
- `type PeerDescriptor`：
  - `PeerID`, `IP`, `OverlayPort`, `DraughtsPort`, `PubKey`, `TopodAddr`
- `type NeighborSnapshot`：
  - `OwnerPeerID`, `Term`, `Active[]`, `TimestampMs`
- `type snapshotRing`：
  - 按 `term` 保留固定窗口快照
- `type historyStore`：
  - JSONL 持久化（self / twohop）
- `type daemon`：
  - 运行时总状态：`term`, `active`, `passive`, `directory`, `selfHistory`, `neighborHistory`, `historyMeta`

### 4.3 Overlay（TopoDaemon 间）接口
- 协议消息：`overlayMessage`
  - `join`, `snapshot`, `ping`, `shuffle`, `disconnect` 等
- 关键处理接口：
  - `handleJoin`
  - `handleSnapshot`
  - `handleShuffle`
  - `handleDisconnect`
- 关键维护接口：
  - `advanceTermLocked(reason)`：邻居变化触发 term 递增
  - `broadcastSelfSnapshot()`：向 active 广播 self snapshot
  - `gcNeighborHistoryLocked()`：历史快照按容量淘汰

### 4.4 IPC 服务（ChatCore 调用）
- 入口：
  - `serveIPC` -> `handleIPCConn` -> `processIPC`
- 支持命令：
  - `STATE` -> `handleIPCState`
  - `TWOHOP` -> `handleIPCTwoHop`
  - `PLAN` -> `handleIPCPlan`
  - `HISTORY`/`PICK` -> `handleIPCHistory`
- 响应语义：
  - 成功：`OK ...`
  - 未命中：`NOT_FOUND reason=...`
  - 异常：`ERR reason=...`

### 4.5 PLAN/HISTORY 规则（接口语义）
- PLAN：
  - 优先使用 NH 最新快照选 NNH
  - 若历史不可用，fallback 到本地 active 并可合成快照
- HISTORY：
  - 优先按 `(peer, term)` 查快照（内存/持久化）
  - `strict=1` 时只接受快照候选
  - `strict=0` 可 fallback 到本地 active

## 5. 进程协作接口（IPC 文本协议）

### 5.1 请求命令
- `STATE`
- `TWOHOP`
- `PLAN [exclude=<peer_id>]`
- `HISTORY peer=<peer_id> term=<uint64> [exclude=<peer_id>] [strict=0|1]`

### 5.2 典型响应格式
- `STATE`：
  - `OK term=<t> active=<id1,id2,...>`
- `TWOHOP`：
  - `OK term=<t> active=<...> twohop=<nh1>nnh1,nnh2;<nh2>...`
- `PLAN`：
  - `OK term=<t> nh_id=... nh_ip=... nh_port=... nh_pub=... nnh_id=... nnh_ip=... nnh_port=... nnh_pub=...`
- `HISTORY`：
  - `OK nnh_id=... nnh_ip=... nnh_port=... nnh_pub=...`

## 6. 核心调用关系（论文可直接引用）

### 6.1 启动链
1. `ChatCore main`
2. `DraughtsNode::start`（目录加载 + STATE 同步）
3. `DraughtsApp::start`（UDP 绑定 + 异步接收 + 会话清理定时）
4. `Cli::run`（命令驱动）

### 6.2 请求发送链（CLI `send`）
1. `Cli::run` -> `DraughtsApp::cmd_send`
2. `send_request_with_session`
3. `pick_nh_nnh` -> `TopodClient::pick_route` -> IPC `PLAN`
4. 填写 `topo_term/x` 与地址字段并加密封装
5. `send_packet_to` 走 UDP

### 6.3 中继链（随机游走/退出）
1. `on_datagram`
2. 非退出包：`handle_random_walk`
3. 根据 `x` 与状态选择 continue/outnode
4. 继续阶段调用 `pick_nnh_for_peer_id` -> IPC `HISTORY`
5. 更新字段后继续转发或切换到退出路径

### 6.4 交付与回复链
1. 退出包：`handle_exit_packet`
2. 请求到达 responder：写入 `ResponderLru`，投递 CLI
3. CLI `reply`：`cmd_reply` 读取缓存并构造回复包
4. 回程在中继层按响应流程转发
5. initiator 收到回复后通过会话密钥解密并入 inbox

### 6.5 two-hop 可观测链
1. CLI `twohop` -> `DraughtsNode::cmd_show_twohop`
2. 先 `sync_active_neighbors_from_topod`（STATE）
3. 再 `sync_twohop_from_topod`（TWOHOP）
4. 输出 NH -> NNH 缓存视图

## 7. 脚本与工程流程（实现支持层）

### 7.1 构建与运行脚本
- `scripts/build_topod.sh`：Go 构建 `TopoDaemon`
- `scripts/run_hyparview_stack.sh`：按配置批量启动 `TopoDaemon + ChatCore`
- `scripts/run_nodes.sh`：仅批量启动 ChatCore
- `scripts/stop_nodes.sh`：按 pid 文件停进程
- `scripts/clean_experiment.sh`：停进程并清理运行产物

### 7.2 配置生成脚本
- `scripts/gen_configs.py`：
  - 生成 `config/generated/*.conf`（ChatCore）
  - 生成 `config/topod/*.json`（TopoDaemon）
  - 生成密钥、peer info、拓扑邻接、bootstrap 信息

### 7.3 实验辅助脚本
- `scripts/topology_collector.py`：汇总邻居状态，输出矩阵
- `scripts/send_neighbors.py`：将邻居文件周期上报给 collector

## 8. 文件清单索引（核心）
- ChatCore：
  - `main.cpp`, `config.*`, `node.*`, `draughts_app.*`, `topod_client.*`, `cli.*`
  - `draughts_packet.hpp`, `crypto/Crypto.*`, `cipher.*`, `ciplc.*`, `protocol.*`, `tlv.*`
- TopoDaemon：
  - `src/TopoDaemon/main.go`
- 脚本：
  - `scripts/gen_configs.py`, `run_hyparview_stack.sh`, `stop_nodes.sh`, `clean_experiment.sh`, `build_topod.sh`

## 9. 使用说明（面向论文写作）
- 本文件可直接作为“实现章节的代码事实基线”。
- 写作时建议：
  - 章节 5.3 中优先引用“接口职责 + 数据流 + 调用链”
  - 将算法机理（已在第 3/4 章展开）简述为“调用结果如何被实现层消费”
  - 重点展开实现特有部分：进程协作、状态缓存、容错 fallback、会话与日志可观测性。

