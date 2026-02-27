# Hyparview 实验文档（Ubuntu 22.04 / 64 核）

## 1. 环境准备与清理

```bash
./scripts/clean_experiment.sh
```

说明：

- 以上命令均默认在项目根目录执行（当前目录就是仓库目录）。
- `clean_experiment.sh` 会删除实验生成状态与配置目录（如 `run/`、`config/generated/`、`config/topod/` 等），不会删除 `build/` 下已编译程序。

## 2. 编译 ChatCore 与 TopoDaemon

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
cd ..
```

```bash
./scripts/build_topod.sh ./build/TopoDaemon
```

## 3. 初始化本次实验配置（50 中继 + 2 CLI）

说明：生成 52 个节点配置，其中 `node51`、`node52` 开启 CLI；先启动 `node1~node50` 形成初始网络，再让 `node51`、`node52` 作为 CLI 节点加入。

```bash
./scripts/gen_configs.py \
  --count 52 \
  --cli-nodes 51,52 \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000
```

## 4. 批量启动 50 个不带 CLI 的节点（统一脚本）

```bash
ONLY_50=$(seq 1 50 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh \
  --only "$ONLY_50" \
  --interval 0.1 \
  --topod-delay 2
```

## 5. 单独启动两个带 CLI 的节点并加入网络

### 终端 A（node51）

```bash
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node51.json ) > run/node51.topod.out 2>&1 &
echo "$! config/topod/node51.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node51.conf
```

### 终端 B（node52）

```bash
touch run/hyparview_topod.pids
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node52.json ) > run/node52.topod.out 2>&1 &
echo "$! config/topod/node52.json" >> run/hyparview_topod.pids
exec -a ChatCore ./build/ChatCore config/generated/node52.conf
```

## 6. CLI 交互与请求/响应验证

### 在 node51（终端 A）

```text
id
neighbors
send node52 hello-from-node51
```

### 在 node52（终端 B）

```text
inbox
requests
reply <session_hex> ack-from-node52
```

### 回到 node51（终端 A）

```text
inbox
```

## 7. 终止实验

先在两个 CLI 终端输入：

```text
quit
```

然后在任意终端执行：

```bash
./scripts/stop_nodes.sh run/hyparview_chatcore.pids
./scripts/stop_nodes.sh run/hyparview_topod.pids
./scripts/clean_experiment.sh
```
