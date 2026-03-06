# draughts_p2p

`draughts_p2p` 是一个 C++/Go 混合实现的 P2P 请求-响应原型系统：

- C++ `draughts_node`（ChatCore）负责数据包处理、匿名转发、加密封装、CLI 交互。
- Go `TopoDaemon` 负责 HyParView 风格邻居维护、邻居历史快照、本地路由决策（PLAN/HISTORY/STATE）。

当前实现以“邻居与局部拓扑维护层（TopoDaemon）+ 报文与业务执行层（ChatCore）”分层协作为核心：

- 邻居与局部拓扑维护层给出 `(NH, NNH, term)` 路由建议。
- 报文与业务执行层按 `DraughtsPacket` 固定包结构执行随机游走、出网节点投递、请求-回复回程。

## 1. 仓库结构

- `src/ChatCore/`：C++ 主程序、协议包、加密、CLI。
- `src/TopoDaemon/`：Go 拓扑守护进程（overlay + 本地 IPC）。
- `scripts/`：构建、配置生成、批量起停、清理脚本。
- `config/generated/`：ChatCore 配置（由 `gen_configs.py` 生成）。
- `config/topod/`：TopoDaemon 配置（由 `gen_configs.py` 生成）。
- `peers/`、`keys/`、`run/`、`logs/`：运行时产物目录。
- `exp/`：实验指导文档（你已将实验文档迁移到这里）。

## 2. 依赖

Ubuntu 常用依赖：

```bash
./scripts/install_deps.sh
```

此外需要 Go（`src/TopoDaemon/go.mod` 目前是 `go 1.22`）。

## 3. 编译

构建 ChatCore（C++）：

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
cd ..
```

构建 TopoDaemon（Go）：

```bash
./scripts/build_topod.sh ./build/TopoDaemon
```

说明：

- CMake 目标名为 `draughts_node`。
- 构建后会额外复制一份到 `build/ChatCore`（便于旧脚本/命令兼容）。

## 4. 快速实验（推荐 10 节点：8 中继 + 2 CLI）

完整步骤见：

- `exp/hyparview_10_nodes_cli_request_reply_test.md`

典型流程（根目录执行）：

```bash
./scripts/clean_experiment.sh

./scripts/gen_configs.py \
  --count 10 \
  --cli-nodes 9,10 \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000 \
  --log-level info

ONLY_8=$(seq 1 8 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh \
  --only "$ONLY_8" \
  --interval 0.1 \
  --topod-delay 1
```

随后分别开两个终端启动 `node9`、`node10`（CLI 节点）：

```bash
# 终端 A
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node9.json ) > run/node9.topod.out 2>&1 &
echo "$! config/topod/node9.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node9.conf
```

```bash
# 终端 B
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node10.json ) > run/node10.topod.out 2>&1 &
echo "$! config/topod/node10.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node10.conf
```

CLI 验证：

- 在 `node9`：`send node10 hello`
- 在 `node10`：`inbox`、`requests`、`reply <session_hex> ack`
- 回到 `node9`：`inbox`

## 5. 运行时接口

### 5.1 ChatCore CLI

- `id`：节点 ID 与端口信息
- `neighbors`：当前活跃邻居（来自 TopoDaemon STATE）
- `peers`：已知节点目录
- `inbox`：请求/回复收件箱
- `requests`：待回复会话
- `send <peer_id|ip:port> <text>`：发请求
- `send_session <session_hex> <text>`：同会话继续发送
- `reply <session_hex> <text>`：回复
- `quit`

### 5.2 TopoDaemon IPC（Unix Socket）

`ChatCore` 通过 `topod_ipc_socket` 请求：

- `STATE`：返回当前 `term` 与 `active` 邻居列表
- `PLAN [exclude=peer]`：返回 `term + NH + NNH`
- `HISTORY peer=<nh> term=<t> [exclude=peer] [strict=0|1]`：按指定 NH 历史快照选 NNH

## 6. 配置关系（最关键字段）

ChatCore（`config/generated/nodeX.conf`）：

- `peer_id`、`bind_ip`、`draughts_port`
- `peer_info_dir`（读取全网节点描述）
- `identity_key_file`（EC 私钥）
- `topod_ipc_socket`（本地 IPC）
- `ciplc_*`（随机游走概率参数）
- `magic_num`（包魔数）

TopoDaemon（`config/topod/nodeX.json`）：

- `peer_id`、`listen_addr`（overlay TCP）
- `ipc_socket`（给 ChatCore 的 Unix Socket）
- `peer_info_dir`
- `active_min`/`active_max`/`passive_max`
- `bootstrap`（初始可加入目标）

`gen_configs.py` 多机部署常用参数：

- `--bind-ip-map`：按节点索引范围分配不同 `bind_ip`，例如  
  `1-14:192.168.150.115,15-22:192.168.150.114,23-30:192.168.150.113`
- `--log-level warn`：降低大规模部署下的日志细节

## 7. 其他实验文档（`exp/`）

- `exp/hyparview_6_nodes_no_cli_debug.md`
- `exp/hyparview_10_nodes_cli_request_reply_test.md`
- `exp/hyparview_50_nodes_test.md`
- `exp/lan_3_servers_no_cli_deploy.md`

## 8. 深入设计

系统设计、模块交互、数据包结构、请求-响应时序详见：

- `draughts_design.md`
