# draughts_p2p（HyParView Overlay / Draughts / C++17）

本项目是 **Draughts 匿名路由协议** 在 **动态 HyParView Overlay** 上的 C++17 原型实现，特点：

- **动态 HyParView Overlay**：active/passive view、JOIN/forward JOIN、PING/PONG、VIEW_UPDATE、目录与 TTL。
- **两跳缓存**：基于 VIEW_UPDATE 的两跳节点信息缓存（含完整 descriptor + TTL）。
- **Draughts 随机游走路由**：带 CIPLC 路径长度控制。
- **UDP 双端口**：overlay 控制面与业务面分离。
- CLI 交互；日志写入文件。

这是实验性原型，不适合直接用于对抗性互联网环境。

---

## 四层架构

**Layer 1：IO 层（UDP + 定时器）**
- 仅负责 UDP 收发与定时器触发。
- 不解析 JOIN / VIEW_UPDATE，不管理邻居。

**Layer 2：HyParView Overlay 层**
- 维护 active / passive view。
- 实现 JOIN / 转发 JOIN（带 TTL）、PING/PONG、VIEW_UPDATE。
- 维护 two-hop cache、peer directory（含 TTL）。

**Layer 3：Draughts 匿名通信层**
- 处理业务数据包、路由选择（NNH）、加解密。
- 通过 Overlay 提供的接口读取 active/twohop/directory。

**Layer 4：CLI 层**
- 读取用户输入，post 到 io 线程执行。
- 展示 neighbors / twohop / stats，打印收到的消息。

---

## 端口职责

- `overlay_port`：HyParView Overlay 控制面。
- `draughts_port`：Draughts 业务面。

---

## 线程模型

- **单 io_context 线程**：所有 socket 回调、timer 回调、overlay/draughts 状态修改。
- **CLI 线程**：只读 stdin，并 post 到 io 线程。

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

## 配置项（必须支持）

- `is_bootstrap`：是否为引导节点（true/false）。
- `bootstrap_endpoints`：引导节点列表（`ipv4:overlay_port:draughts_port`，逗号分隔）。
- `overlay_port` / `draughts_port`：两个 UDP 端口。
- `active_min` / `active_max` / `passive_max`
- `join_ttl`
- `ping_interval_ms`
- `peer_timeout_ms`
- `view_update_interval_ms`
- `valid_window_s`

可选：
- `active_neighbors_file`、`self_info_file`、`peer_info_dir`、`identity_key_file`
- Draughts / CIPLC 参数（见 `config/default.conf`）

---

## 配置示例

**引导节点（bootstrap）**：
```ini
peer_id = nodeA
bind_ip = 127.0.0.1
overlay_port = 4000
draughts_port = 5000
is_bootstrap = true

active_min = 3
active_max = 5
passive_max = 80
join_ttl = 4
ping_interval_ms = 10000
peer_timeout_ms = 30000
view_update_interval_ms = 5000
valid_window_s = 60
```

**普通节点**：
```ini
peer_id = nodeB
bind_ip = 127.0.0.1
overlay_port = 4001
draughts_port = 5001
is_bootstrap = false
bootstrap_endpoints = 127.0.0.1:4000:5000

active_min = 3
active_max = 5
passive_max = 80
join_ttl = 4
ping_interval_ms = 10000
peer_timeout_ms = 30000
view_update_interval_ms = 5000
valid_window_s = 60
```

---

## 实验：单机 56 节点（node10/node20 为 CLI）

目标：本机同 IP 启动 56 个进程；节点 10/20 为交互式 CLI，其余为无 CLI；验证请求/回复成功。

### 1) 生成 56 个配置文件

在项目根目录执行：
```bash
mkdir -p config/exp56 logs
```
```bash
for i in $(seq 1 56); do
  overlay=$((4000 + i - 1))
  draughts=$((5000 + i - 1))
  cli="false"
  if [ "$i" = "10" ] || [ "$i" = "20" ]; then cli="true"; fi
  is_bootstrap="false"
  bootstrap_line="bootstrap_endpoints = 127.0.0.1:4000:5000"
  if [ "$i" = "1" ]; then
    is_bootstrap="true"
    bootstrap_line="# bootstrap_endpoints = 127.0.0.1:4000:5000"
  fi

  cat > config/exp56/node${i}.conf <<EOF
peer_id = node${i}
bind_ip = 127.0.0.1
overlay_port = ${overlay}
draughts_port = ${draughts}
is_bootstrap = ${is_bootstrap}
${bootstrap_line}

log_file = logs/node${i}.log
log_level = info
cli_enabled = ${cli}

active_min = 3
active_max = 5
passive_max = 80
join_ttl = 4
ping_interval_ms = 10000
peer_timeout_ms = 30000
view_update_interval_ms = 5000
valid_window_s = 60
EOF
done
```

### 2) 启动 54 个后台节点（非 CLI）

```bash
mkdir -p run
for i in $(seq 1 56); do
  if [ "$i" = "10" ] || [ "$i" = "20" ]; then continue; fi
  ./build/draughts_node config/exp56/node${i}.conf > run/node${i}.out 2>&1 &
done
```

### 3) 启动 CLI 节点（各开一个终端）

终端 A：
```bash
./build/draughts_node config/exp56/node10.conf
```

终端 B：
```bash
./build/draughts_node config/exp56/node20.conf
```

### 4) CLI 内测试请求/回复

终端 A（node10）：
```bash
neighbors
twohop
send node20 hello-from-node10
```

终端 B（node20）：
```bash
inbox
requests
reply <session_hex> ok-from-node20
```

终端 A（node10）：
```bash
inbox
```

### 5) 停止全部后台节点（可选）

```bash
pkill -f draughts_node
```

---

## 多节点测试（本地 3 节点）

终端 A：
```bash
./build/draughts_node config/a.conf
```

终端 B：
```bash
./build/draughts_node config/b.conf
```

终端 C：
```bash
./build/draughts_node config/c.conf
```

CLI 示例：
```bash
id
neighbors
twohop
send nodeB hello
```

终端 B：
```bash
inbox
requests
reply <session_hex> ok
```

---

## 验收标准

- **Active 数量**维持在 `[active_min, active_max]` 区间。
- **VIEW_UPDATE** 能持续刷新 two-hop 缓存与目录 TTL。
- **PING/PONG** 能剔除超时 peer。
- **Draughts 通信** `send` / `reply` 可用。

---

## CLI 命令

```
help                             显示帮助
id                               显示本地 peer id / endpoint
neighbors                        显示 active 邻居
twohop                           显示 two-hop 缓存
peers                            显示目录中的 peer
send <peer_id|ipv4:port> <text>  发送请求
send_session <session_hex> <text> 使用已有会话继续发送
inbox                            查看收件箱
requests                         查看待响应会话
reply <session_hex> <text>       回复请求
quit                             退出
```

---

## Draughts 数据包结构（1280 字节）

```
PK_PH_tmp (64) | PK_PPH_tmp (64) | PK_Init_tmp (64) | ADDR_NNH (6) |
C_ADDR_Real_Receiver (6) | C_ADDR_Real_Sender (6) | x (8) | magic (8) | session_id (16) | C_Data (1038)
```

- `ADDR_NNH` / `C_ADDR_Real_Receiver` / `C_ADDR_Real_Sender` 为 **IPv4(4 字节) + 端口(2 字节)**。
- `PK_PH_tmp` 为逐跳公钥，仅在三段“退出”阶段为 **0xEE..EE**。
- `C_Data` 使用 `PK_Init_tmp` 与 responder/initiator 密钥端到端加密。

---

## 日志

内部日志写入 `log_file`（默认 `draughts.log`），CLI 只输出用户交互信息。
