# Hyparview 本机实验文档（8 无 CLI + 2 CLI 请求/回复）

## 1. 目标

- 生成 10 个节点配置：
  - `node1~node8`：无 CLI
  - `node9,node10`：开启 CLI
- 先启动 8 个无 CLI 节点形成网络
- 启动两个 CLI 节点
- `node9` 向 `node10` 发请求，`node10` 根据 `session_hex` 回复
- 在结束前增加 2 个复用会话实验：
  - `node10` 复用已有 `session_hex` 再发送一次回复
  - `node9` 复用同一 `session_hex` 再次发请求，`node10` 再回复一次

## 2. 编译

```bash
cmake --build build -j
./scripts/build_topod.sh ./build/TopoDaemon
```

## 3. 生成实验配置

```bash
./scripts/clean_experiment.sh
rm -f run/pcap/hyparview_10_nodes_udp.pcap run/pcap/hyparview_10_nodes_udp.pcap.pid
mkdir -p run/pcap

./scripts/gen_configs.py \
  --count 10 \
  --cli-nodes 9,10 \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000 \
  --log-level info
```

## 4. 启动 tcpdump 抓包（UDP 业务包）

```bash
tcpdump -i lo -nn udp and portrange 5000-5009 \
  -w run/pcap/hyparview_10_nodes_udp.pcap &
echo "$!" > run/pcap/hyparview_10_nodes_udp.pcap.pid
```

> 每次重新实验前都先删除旧 `pcap`，避免混入上一次实验数据。

## 5. 启动 8 个无 CLI 节点（node1~node8）

```bash
ONLY_8=$(seq 1 8 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh \
  --only "$ONLY_8" \
  --interval 0.1 \
  --topod-delay 1
```

## 6. 启动两个 CLI 节点

### 终端 A（node9）

```bash
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node9.json ) > run/node9.topod.out 2>&1 &
echo "$! config/topod/node9.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node9.conf
```

### 终端 B（node10）

```bash
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node10.json ) > run/node10.topod.out 2>&1 &
echo "$! config/topod/node10.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node10.conf
```

## 7. CLI 交互验证 request/reply + session 复用

### 在 node9（终端 A）

```text
id
neighbors
twohop
send node10 hello-from-node9
```

### 在 node10（终端 B）

```text
inbox
requests
# 等待 1 秒再回复，避免刚交付后立即回复导致观测混叠
# (在 CLI 中直接等待 1 秒，不需要输入命令)
reply <session_hex> ack-from-node10
```

> `session_hex` 取自 `inbox` 或 `requests` 输出。

### 回到 node9（终端 A），确认首次回复

```text
inbox
```

预期可看到 `[REPLY] session=... text="ack-from-node10"`。

### 额外步骤 1：响应端复用 session，再回复一次（node10）

```text
reply <session_hex> ack-reuse-1-from-node10
```

### 回到 node9（终端 A），确认第二次回复

```text
inbox
```

预期新增 `[REPLY] session=... text="ack-reuse-1-from-node10"`。

### 额外步骤 2：请求端复用 session，再发一次请求（node9）

```text
send_session <session_hex> hello-reuse-2-from-node9
```

### node10 再次回复（node10）

```text
inbox
requests
reply <session_hex> ack-reuse-2-from-node10
```

### 最后回到 node9（终端 A）

```text
inbox
```

预期新增 `[REPLY] session=... text="ack-reuse-2-from-node10"`。

## 8. 结束实验

先停止抓包并保存文件：

```bash
if [[ -f run/pcap/hyparview_10_nodes_udp.pcap.pid ]]; then
  TCPDUMP_PID=$(cat run/pcap/hyparview_10_nodes_udp.pcap.pid)
  kill -INT "$TCPDUMP_PID" || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
fi
```

先在两个 CLI 终端输入：

```text
quit
```

然后在任意终端执行：

```bash
./scripts/stop_nodes.sh run/hyparview_chatcore.pids
./scripts/stop_nodes.sh run/hyparview_topod.pids
```

如需彻底清理再执行：

```bash
./scripts/clean_experiment.sh
```

## 9. 本次实测记录（2026-03-01）

- 会话 ID：
  - `session=b4eca7e1cf6046d10f5b9490398b9821`
- 首轮 request/reply：
  - `node9`: `twohop`（确认请求端当前两跳视图）
  - `node9`: `send node10 hello-from-node9`
  - `node10`: `reply b4eca7e1cf6046d10f5b9490398b9821 ack-from-node10`
  - `node9 inbox` 收到：`ack-from-node10`
- 复用步骤 1（响应端复用 session 再回复）：
  - `node10`: `reply b4eca7e1cf6046d10f5b9490398b9821 ack-reuse-1-from-node10`
  - `node9 inbox` 新增：`ack-reuse-1-from-node10`
- 复用步骤 2（请求端复用 session 再发请求，响应端再回复）：
  - `node9`: `send_session b4eca7e1cf6046d10f5b9490398b9821 hello-reuse-2-from-node9`
  - `node10`: `reply b4eca7e1cf6046d10f5b9490398b9821 ack-reuse-2-from-node10`
  - `node9 inbox` 新增：`ack-reuse-2-from-node10`

对应日志证据（节选）：

- `logs/node9.log`
  - `cli twohop结果 self=node9 term=... active={...} twohop={...}`
  - `收到CLI发起通信请求 dest=node10 responder=... responder_pub_head=...`
  - `选择下一跳为...`
  - `选择下下跳为...`
  - `根据下一跳...选择下下跳为...`
  - `构造数据包 stage=cli_request_build_packet`
  - `packet_field=session_id set_value=b4eca7e1cf6046d10f5b9490398b9821`
  - `stage=cli_send_new_session action=store sid=... key=session_id value={...}`
  - `stage=cli_send_session action=get sid=... key=session_id value={...}`
- `logs/node10.log`
  - `stage=exit_request action=store sid=... key=session_id value={...}`
  - `stage=cli_reply action=get sid=... key=session_id value={...}`
  - `构造数据包 stage=cli_reply_build_response`
  - `packet_field=params.pk_init_tmp set_value=...`
  - `Crypto 细节 ... 基于[响应端长期私钥(identity.sk)]和[发起端临时公钥(...)] 执行加/解密`
  - `cli send reply outnode=...`

## 10. 环境注意

- 在当前终端环境中，若用一次性命令后台拉起进程，命令结束后子进程可能被回收。
- 建议按本文“终端 A/B”方式启动 CLI 节点，保持会话常驻，避免 `topod connect failed` 的偶发误判。
- `run/topod/node*.history.jsonl` 采用缩进 JSON 记录，便于直接打开阅读与截图。
