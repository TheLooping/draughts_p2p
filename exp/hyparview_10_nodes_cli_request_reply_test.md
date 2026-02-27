# Hyparview 本机实验文档（8 无 CLI + 2 CLI 请求/回复）

## 1. 目标

- 生成 10 个节点配置：
  - `node1~node8`：无 CLI
  - `node9,node10`：开启 CLI
- 先启动 8 个无 CLI 节点形成网络
- 启动两个 CLI 节点
- `node9` 向 `node10` 发请求，`node10` 根据 `session_hex` 回复

## 2. 编译

```bash
cmake --build build -j
./scripts/build_topod.sh ./build/TopoDaemon
```

## 3. 生成实验配置

```bash
./scripts/clean_experiment.sh

./scripts/gen_configs.py \
  --count 10 \
  --cli-nodes 9,10 \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000
```

## 4. 启动 8 个无 CLI 节点（node1~node8）

```bash
ONLY_8=$(seq 1 8 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh \
  --only "$ONLY_8" \
  --interval 0.1 \
  --topod-delay 1
```

## 5. 启动两个 CLI 节点

### 终端 A（node9）

```bash
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node9.json ) > run/node9.topod.out 2>&1 &
exec -a ChatCore ./build/ChatCore config/generated/node9.conf
```

### 终端 B（node10）

```bash
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node10.json ) > run/node10.topod.out 2>&1 &
exec -a ChatCore ./build/ChatCore config/generated/node10.conf
```

## 6. CLI 交互验证 request/reply

### 在 node9（终端 A）

```text
id
neighbors
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

### 回到 node9（终端 A）

```text
inbox
```

预期可看到 `[REPLY] session=... text="ack-from-node10"`。

## 7. 结束实验

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

## 8. 本次实测记录（2026-02-27）

- `node9` 发起请求：
  - `session=62c86d413f480a66def268e872cad28c`
- `node10` 收到请求并回复同一 `session`：
  - `reply 62c86d413f480a66def268e872cad28c ack-from-node10`
- `node9` 收到回复：
  - `session=62c86d413f480a66def268e872cad28c`

对应日志证据：

- `logs/node9.log`
  - `cli send request session=62c86d413f480a66def268e872cad28c`
  - `recv reply session=62c86d413f480a66def268e872cad28c`
- `logs/node10.log`
  - `recv request session=62c86d413f480a66def268e872cad28c`
  - `cli send reply session=62c86d413f480a66def268e872cad28c`

## 9. 环境注意

- 在当前终端环境中，若用一次性命令后台拉起进程，命令结束后子进程可能被回收。
- 建议按本文“终端 A/B”方式启动 CLI 节点，保持会话常驻，避免 `topod connect failed` 的偶发误判。
