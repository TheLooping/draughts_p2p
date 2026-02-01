# draughts_p2p（SM2 / HyParView / Draughts）

本项目是 **Draughts 匿名路由协议** 在去中心化 P2P 覆盖网络上的 C++17 原型实现，包含：

- **静态拓扑**：基于 **UDP/IPv4** 的预生成邻接关系（不再考虑动态加入）。
- **两跳邻居同步**：用于局部 NNH 选择。
- **Draughts 随机游走路由**：带 **CIPLC** 路径长度控制。
- **匿名请求/响应**：使用 **SM2-ECDH + HKDF + AES-CTR XOR**。
- CLI 交互；内部日志写入文件。

这是实验性原型，不适合直接用于对抗性互联网环境。

---

## 编译

依赖：
- C++17 编译器
- Boost 头文件（Boost.System 头文件即可）
- OpenSSL（libcrypto，OpenSSL 1.1.1+）

构建命令（每条单独执行）：
```bash
mkdir -p build
```
```bash
cd build
```
```bash
cmake ..
```
```bash
cmake --build . -j
```

可执行文件：`./build/draughts_node`

---

## 运行（本地示例）

编辑 `config/default.conf`，并使用配置文件路径启动：
```bash
./build/draughts_node ./config/default.conf
```

多节点实验常用配置：
- `cli_enabled`（true/false）：是否开启 CLI。
- `active_neighbors_file`：当前 active 邻居列表 JSON（覆盖写、退出时删除）。
- `self_info_file`：节点自信息文件（地址/端口/公钥），供外部查询。
- `peer_info_dir`：自信息文件目录，CLI 可用于解析 `peer_id`。
- `identity_key_file`：SM2 私钥文件（PEM）。
- `static_topology`：是否启用静态拓扑（推荐 true）。
- `topology_dir`：拓扑文件目录（每节点 `.neighbors`）。

### 实验：单机 36 节点（CLI 为 node10/node20）

清理旧文件：
```bash
./scripts/clean_experiment.sh
```

生成配置 + 密钥 + 拓扑：
```bash
./scripts/gen_configs.py --count 36 --cli-nodes 10,20 --active-min 3 --active-max 5 --neighbor-set-k 5 --bind-ip 127.0.0.1
```

启动中继节点（每 1 秒一个）：
```bash
./scripts/run_nodes.sh --skip node10,node20 --interval 1
```

启动 CLI 节点（终端 A）：
```bash
./build/draughts_node config/generated/node10.conf
```

启动 CLI 节点（终端 B）：
```bash
./build/draughts_node config/generated/node20.conf
```

启动拓扑收集器：
```bash
./scripts/topology_collector.py --bind 0.0.0.0 --port 9000
```

启动邻居上报：
```bash
./scripts/send_neighbors.py --dir neighbors --host 127.0.0.1 --port 9000 --interval 2
```

停止所有后台中继节点：
```bash
./scripts/stop_nodes.sh
```

示例：本地 3 节点配置

终端 A（`config/a.conf`）：
```ini
peer_id = A
bind_ip = 127.0.0.1
overlay_port = 4000
draughts_port = 5000
```

终端 B（`config/b.conf`）：
```ini
peer_id = B
bind_ip = 127.0.0.1
overlay_port = 4001
draughts_port = 5001
bootstraps = 127.0.0.1:4000:5000
```

终端 C（`config/c.conf`）：
```ini
peer_id = C
bind_ip = 127.0.0.1
overlay_port = 4002
draughts_port = 5002
bootstraps = 127.0.0.1:4000:5000
```

说明：
- `overlay_port` 用于 HyParView 维护通信。
- `draughts_port` 用于 Draughts 数据通信。
- `bootstraps` 使用 `ipv4:overlay_port:draughts_port`。

---

## CLI 命令

```
help                             显示帮助
id                               显示本地 peer id / endpoint
neighbors                        显示 active 邻居
send <peer_id|ipv4:port> <text>  发送请求
inbox                            查看收件箱
requests                         查看待响应会话
reply <session_hex> <text>       回复请求
quit                             退出
```

---

## Draughts 数据包结构（1280 字节）

```
PK_PH_tmp (64) | PK_PPH_tmp (64) | PK_Init_tmp (64) | ADDR_NNH (6) |
C_ADDR_Resp (6) | C_ADDR_Init (6) | x (8) | magic (8) | session_id (16) | C_Data (1038)
```

- `ADDR_NNH` / `C_ADDR_Resp` / `C_ADDR_Init` 为 **IPv4(4 字节) + 端口(2 字节)**。
- `PK_PH_tmp` 为逐跳公钥，仅在三段“退出”阶段为 **0xEE..EE**。
- `C_Data` 使用 `PK_Init_tmp` 与 responder/initiator 密钥端到端加密。

---

## 偏差与简化说明

- **Out node / responder 逻辑** 以 `doc/Initiator.png`、`doc/node.png` 为准。
- 原型中 `C_ADDR_*` 在逐跳解密后对当前节点可见；真实系统可增加链路加密。
- CIPLC 使用论文中的混沌函数并逐跳更新 `x` 以控制转发概率。

---

## 日志

内部日志写入 `log_file`（默认 `draughts.log`），CLI 只输出用户交互信息。
