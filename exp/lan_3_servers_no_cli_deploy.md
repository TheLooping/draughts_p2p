# 三机局域网部署实验（无 CLI 常驻节点）

本文针对当前 `draughts_p2p` 项目给出三台服务器部署指导，目标是：

- 基础节点长期后台运行（无 CLI）
- 后续用户节点可单独加入/退出，不影响现网基础节点

## 1. 节点规划

你给的示例分配是：

- `192.168.150.115`：16 节点
- `192.168.150.114`：8 节点
- `192.168.150.113`：8 节点

该分配总数是 `32`。如果你严格要 `30`，建议改为：

- `192.168.150.115`：14 节点（`node1~node14`）
- `192.168.150.114`：8 节点（`node15~node22`）
- `192.168.150.113`：8 节点（`node23~node30`）

下文默认按 **30 节点（14/8/8）** 给出，末尾附 32 节点变体。

## 2. 前置条件

三台机器都需要：

1. 同一代码版本（推荐同一 commit）
2. 已安装依赖（`openssl`、`cmake`、`go`、`nc`）
3. 防火墙放行以下端口段（按你实际 `base` 调整）：
   - overlay（TopoDaemon）：`6000~6029`
   - draughts（ChatCore UDP）：`5000~5029`
4. 目录统一为 `/home/wkw/draughts_p2p`

## 3. 构建二进制（每台机器）

在三台机器分别执行：

```bash
cd /home/wkw/draughts_p2p
cmake --build build -j
./scripts/build_topod.sh ./build/TopoDaemon
```

## 4. 在一台“配置控制机”生成全量 30 节点配置

建议在 `192.168.150.115` 生成，然后分发到另外两台。

```bash
cd /home/wkw/draughts_p2p
./scripts/clean_experiment.sh

./scripts/gen_configs.py \
  --count 30 \
  --cli-nodes "" \
  --active-min 3 \
  --active-max 5 \
  --overlay-base 4000 \
  --draughts-base 5000 \
  --topod-base 6000 \
  --bind-ip 192.168.150.115 \
  --bind-ip-map "1-14:192.168.150.115,15-22:192.168.150.114,23-30:192.168.150.113" \
  --log-level warn \
  --seed 20260306
```

说明：

- `--bind-ip-map` 已按节点范围写入各节点真实 IP。
- `--log-level warn` 用于降低日志抓包级细节，适合 30+ 节点常驻运行。
- 若排障再临时改成 `--log-level info` 或 `debug`。

## 5. 分发运行配置到三台机器

在配置控制机执行：

```bash
cd /home/wkw/draughts_p2p

for h in 192.168.150.115 192.168.150.114 192.168.150.113; do
  rsync -az \
    config/generated \
    config/topod \
    peers \
    keys \
    topology \
    "$h:/home/wkw/draughts_p2p/"
done
```

## 6. 分机启动（仅启动本机负责节点）

### 6.1 `192.168.150.115` 启动 `node1~node14`

```bash
cd /home/wkw/draughts_p2p
ONLY=$(seq 1 14 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh --only "$ONLY" --interval 0.1 --topod-delay 1
```

### 6.2 `192.168.150.114` 启动 `node15~node22`

```bash
cd /home/wkw/draughts_p2p
ONLY=$(seq 15 22 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh --only "$ONLY" --interval 0.1 --topod-delay 1
```

### 6.3 `192.168.150.113` 启动 `node23~node30`

```bash
cd /home/wkw/draughts_p2p
ONLY=$(seq 23 30 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh --only "$ONLY" --interval 0.1 --topod-delay 1
```

`run_hyparview_stack.sh` 内部使用 detached 方式启动，可后台常驻。

## 7. 验活检查

每台机器检查本机进程数量：

```bash
cd /home/wkw/draughts_p2p
wc -l run/hyparview_topod.pids run/hyparview_chatcore.pids
```

预期：

- `192.168.150.115`：各 14
- `192.168.150.114`：各 8
- `192.168.150.113`：各 8

抽查 IPC 返回：

```bash
# 在各机器替换为本机已启动节点（例如 node1 / node15 / node23）
printf "STATE\n" | nc -U run/topod/<local_node>.sock -w 1
```

若返回 `OK term=... active=...` 则本机拓扑进程工作正常。

## 8. 用户节点加入/退出（推荐做法）

推荐在初次生成时预留一批用户节点 ID（例如 `node31~node40`），但基础阶段只启动 `node1~node30`。

这样后续加入/退出非常简单：

1. 加入：在某台机器启动对应预留节点（TopoDaemon + ChatCore）
2. 退出：停止该节点 PID（不影响其他基础节点）

如果你需要，我可以下一步给你补一份“`node31~node40` 预留用户节点”的启动/停机脚本。

## 9. 停止与重启

单机停本机节点：

```bash
cd /home/wkw/draughts_p2p
./scripts/stop_nodes.sh run/hyparview_chatcore.pids
./scripts/stop_nodes.sh run/hyparview_topod.pids
```

只重启本机节点时，直接重复第 6 节对应命令即可。

## 10. 32 节点（16/8/8）变体

如果你就是要按示例 `16/8/8` 跑，改为：

```bash
./scripts/gen_configs.py \
  --count 32 \
  --cli-nodes "" \
  --active-min 3 \
  --active-max 5 \
  --overlay-base 4000 \
  --draughts-base 5000 \
  --topod-base 6000 \
  --bind-ip 192.168.150.115 \
  --bind-ip-map "1-16:192.168.150.115,17-24:192.168.150.114,25-32:192.168.150.113" \
  --log-level warn \
  --seed 20260306
```

并将三台机器启动范围改成：

- `115`: `node1~node16`
- `114`: `node17~node24`
- `113`: `node25~node32`
