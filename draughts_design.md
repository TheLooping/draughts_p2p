# draughts 设计说明（基于当前代码实现）

本文档仅基于当前仓库实现梳理，不回溯历史版本。

- 报文与业务执行层：`src/ChatCore/`（C++）
- 邻居与局部拓扑维护层：`src/TopoDaemon/`（Go）

目标不是逐行代码解释，而是从架构、模块职责、交互协议、时序与约束角度说明“系统为什么这样工作”。

## 1. 总体设计视角

系统采用双层解耦：

- 邻居与局部拓扑维护层（TopoDaemon）
  - 维护活跃/被动邻居
  - 维护邻居快照历史（term 版本化）
  - 对本地 ChatCore 提供路由选择接口（PLAN/HISTORY/STATE）
- 报文与业务执行层（ChatCore）
  - 封装/解封 `DraughtsPacket`
  - 按随机游走 + 出网投递规则转发 UDP 数据包
  - 完成请求与回复的数据加密与会话管理

这种分层把“拓扑演化”和“数据转发”分开：

- TopoDaemon 可以独立改变邻居集合与路由策略；
- ChatCore 只依赖本地 IPC 获取 NH/NNH，不直接维护 overlay 邻居维护逻辑。

## 2. 组件职责

### 2.1 ChatCore（C++）

- `main.cpp`
  - 加载配置、初始化日志/控制台、加载身份私钥
  - 启动 `DraughtsNode` + `DraughtsApp`
- `DraughtsNode`
  - 维护节点目录（`peer_info_dir`）
  - 每秒通过 TopoDaemon `STATE` 同步活跃邻居
  - 提供 endpoint/pubkey 查询能力（给 `DraughtsApp`）
- `DraughtsApp`
  - 处理 UDP 收发与包状态机
  - `send/send_session/reply/inbox/requests` CLI 行为
  - 维护 initiator/responder 会话缓存
- `TopodClient`
  - Unix Socket 行协议客户端：`PLAN`、`HISTORY`、`STATE`
- `crypto/* + cipher.*`
  - P-256 ECDH（OpenSSL EC）
  - HKDF-SHA256 派生 AES-CTR Key/IV
  - Commutative transform（当前实现映射到 AES-CTR）

### 2.2 TopoDaemon（Go）

- Overlay 服务（TCP + JSON 单行消息）
  - `join/join_ack`
  - `snapshot/ack`
  - `ping/pong`
  - `shuffle/shuffle_ack`
  - `disconnect/ack`
- IPC 服务（Unix Socket + 文本命令）
  - `STATE`
  - `PLAN`
  - `HISTORY`
- 邻居状态
  - `active`: 当前活跃邻居
  - `passive`: 备用邻居
  - `directory`: 已知节点目录
- 历史状态
  - `selfHistory`: 自身 active 快照 ring
  - `neighborHistory`: 其他节点快照 ring
  - `history.jsonl`: 持久化（断点恢复）

## 3. 邻居与局部拓扑维护层设计（TopoDaemon）

### 3.1 邻居维护机制

- `bootstrapLoop`：周期尝试补足 `active_min`
- `keepaliveLoop`：`ping` 检活，超时从 active 降级到 passive
- `shuffleLoop`：与活跃邻居交换 passive 样本
- `directoryReloadLoop`：定期重载 `peer_info_dir`
- `snapshotBroadcastLoop`：active 变化后异步广播 snapshot

active 变化会触发：

1. `term` 递增；
2. 生成新的 self snapshot；
3. 写入内存 ring + 持久化；
4. 对 active 邻居广播 snapshot。

### 3.2 term 与快照历史

每个快照具有：

- `owner_peer_id`
- `term`
- `active[]`
- `timestamp_ms`

历史用途：

- `PLAN`：优先利用 NH 的最近快照挑选 NNH
- `HISTORY(peer,term)`：在指定 NH 的指定历史视图中选 NNH

若快照不存在或不可用，可按 strict 参数决定是否回退到本地 active。

### 3.3 IPC 决策接口语义

- `STATE`
  - 返回当前 `term` 与本节点 active 列表
- `PLAN [exclude=peer]`
  - 目标：产出一次随机游走起步所需 `(term, NH, NNH)`
  - 先用历史快照选 NNH；失败时回退本地 active
- `HISTORY peer=<nh> term=<t> [exclude=peer] [strict=0|1]`
  - 目标：在“指定 NH + 指定 term”的上下文挑 NNH
  - strict=1 时不回退本地 active

## 4. 报文与业务执行层设计（ChatCore）

### 4.1 数据包结构

`DraughtsPacket` 固定 1280 字节：

- `pk_ph_tmp[64]`
- `params`（170 字节）
  - `pk_pph_tmp[64]`
  - `pk_init_tmp[64]`
  - `addr_nnh[6]`
  - `c_addr_real_receiver[6]`
  - `c_addr_real_sender[6]`
  - `topo_term[8]`
  - `x[8]`
  - `magic_num[8]`
- `session_id[16]`
- `c_data[1030]`

关键语义：

- `pk_ph_tmp`：当前 hop 解包 `params` 所需临时公钥
- `pk_pph_tmp`：上一层 hop 公钥（用于后续 peel）
- `pk_init_tmp`：发起方会话临时公钥（端到端 payload + sender 地址相关）
- `addr_nnh`：当前包头部中的“下一跳地址”字段
- `c_addr_real_receiver`：被分层保护的真实接收方地址
- `c_addr_real_sender`：被分层保护的真实发送方地址（回复链路依赖）
- `x`：随机游走/阶段控制变量

### 4.2 `x` 的状态机语义

- `x > 0`：请求阶段随机游走
- `x == 0`：到达 outnode，准备出口投递
- `x == -1`：exit 投递/交付阶段
  - responder 收到请求
  - initiator 收到回复
- `x == -2`：回复引导包（response bootstrap）
- `x < 0 且 != -1/-2`：回复路径第一跳继续标记（随后转为正数继续流程）

### 4.3 随机游走决策（请求）

请求阶段使用 CIPLC 更新 `x` 并决定继续或出网：

- 初始 `x = ciplc_x0`
- 每跳执行 `step_and_decide`
- 初始阶段强制至少继续一次（即使概率结果为停止）
- 停止时进入 outnode 分支（`x -> 0`）

该机制让路径长度受随机过程控制，而不是固定跳数。

## 5. 请求-响应时序（核心）

### 5.1 请求发起（Initiator CLI `send`）

1. 解析目标（`peer_id` 或 `ip:port`）并加载 responder 公钥。
2. 创建会话：`session_id + init_tmp_keypair`。
3. 调 `PLAN` 取得 `(NH, NNH, term)`。
4. 构造包：
   - `pk_ph_tmp = ph_tmp.pub`
   - `pk_pph_tmp = ph_tmp.pub`
   - `pk_init_tmp = init_tmp.pub`
   - `c_addr_real_receiver` 先后叠加对 NH、NNH 的地址层
   - `c_addr_real_sender` 用 `init_tmp + responder_pub` 加密
   - `c_data` 用 `init_tmp + responder_pub` 加密
   - `x = ciplc_x0, topo_term = term`
5. 用 `ph_tmp + NH_pub` 加密 `params`，发给 NH。

### 5.2 中继转发

每一跳先用 `identity + pk_ph_tmp` 解开 `params`，再按 `x` 分支：

- 继续随机游走：
  - 从 `addr_nnh` 得到 NH
  - 通过 `HISTORY` 挑 NNH
  - peel + rewrap `c_addr_real_receiver`
  - 更新 `pk_ph_tmp/pk_pph_tmp/addr_nnh`
  - 重新加密 `params` 后转发
- 转出网阶段：
  - 选 outnode
  - `x = 0`
  - 请求流还会对 `c_addr_real_sender` 增加一层（面向后续回程）

### 5.3 出网投递到 responder

outnode 处理 `x==0`：

1. peel `c_addr_real_receiver`；
2. 得到 responder 真实 UDP 地址；
3. 标记 `x=-1`，`pk_ph_tmp` 置为 exit 标志；
4. 直接发往 responder。

### 5.4 responder 收到请求并回包

responder 处理 `exit + x==-1`：

1. 用 `identity + pk_init_tmp` 解 `c_data`，得到请求文本；
2. 解 `c_addr_real_sender` 得到 initiator 地址线索；
3. 缓存 `ResponderValue`（`addr_ph/pk_pph_tmp/pk_init_tmp/addr_nnh/topo_term/...`）。

CLI `reply` 时：

1. 取对应 `session_id` 的缓存；
2. 构造 `x=-2` 的 exit 包（response bootstrap）；
3. `c_data` 用 `identity + pk_init_tmp` 加密回复文本；
4. 发回当初 outnode（`addr_ph`）。

### 5.5 回复回程

收到 `x==-2` 的节点进入 response bootstrap：

1. 用 `addr_nnh` 定位 NH；
2. 通过 `HISTORY` 为该 NH 选 NNH；
3. 给 `c_addr_real_receiver` 追加一层并设置负 `x`；
4. 重新加密后发往 NH。

后续回复沿随机游走回程逻辑转发；当 outnode 再次出网后会形成 `x==-1` 的 exit 包回到 initiator。

initiator 命中本地会话后，用 `init_tmp + responder_pub` 解出回复并投递到 inbox。

## 6. 模块交互关系

### 6.1 Node 与 App 的协同边界

- `DraughtsNode` 不做包转发，只提供“谁是谁”的目录查询与活跃邻居同步。
- `DraughtsApp` 不维护拓扑，只在需要时请求 `PLAN/HISTORY`。

### 6.2 TopodClient 的角色

`TopodClient` 是 ChatCore 与 TopoDaemon 的唯一控制接口：

- 无 `topod_ipc_socket` 时当前实现直接视为不可运行（已移除静态拓扑兼容主路径）。

## 7. 数据与协议视角

### 7.1 Overlay 协议（TopoDaemon 之间）

- 传输：TCP
- 编码：单行 JSON
- 核心消息：`join/snapshot/ping/shuffle/disconnect`

### 7.2 本地 IPC 协议（ChatCore -> TopoDaemon）

- 传输：Unix Domain Socket（stream）
- 编码：单行文本
- 返回：`OK ...` / `NOT_FOUND ...` / `ERR ...`

### 7.3 会话与缓存

- initiator 会话：`session_id -> init_tmp/responder信息`，按 `session_ttl_ms` 清理。
- responder 缓存：LRU + 可重复会话项，支持一问多答或延迟回复。

## 8. 可观测性与故障处理

- ChatCore：文件日志 + CLI 可视命令（`neighbors/inbox/requests/...`）
- TopoDaemon：统一结构化日志（含 IPC/Overlay/History 标签）

常见保护策略：

- magic 不匹配丢包
- 包长非 1280 丢包
- 缺失 pubkey/端口/NNH 时丢包
- `HISTORY strict=1` 失败后，调用侧可降级 strict=0 再试

## 9. 当前实现边界与注意事项

- `load_static_topology()` 与 `twohop_` 静态路径仍在代码中，但主流程已依赖 TopoDaemon `PLAN/HISTORY`。
- `app_packet.*`（TLV 应用层包）当前未接入主收发链路，现网主路径使用 `DraughtsPacket`。
- 配置项 `outnode_ttl_ms` 在当前主流程未实际参与决策。
- 系统主要面向“同构实验节点 + 可信本地环境”场景，未实现独立的拓扑维护接口鉴权。

## 10. 推荐阅读顺序

1. `README.md`（运行入口）
2. `exp/hyparview_10_nodes_cli_request_reply_test.md`（可复现实验）
3. `src/TopoDaemon/main.go`（邻居与局部拓扑维护层）
4. `src/ChatCore/draughts_app.cpp`（报文与业务执行层状态机）
5. `src/ChatCore/draughts_packet.hpp`（包结构）
