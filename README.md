# draughts_p2p（Hyparview 双进程版）

本分支将系统拆分为两个进程：

- `ChatCore`（C++）：匿名路由与业务报文核心。
- `TopoDaemon`（Go）：基于 Hyparview 的动态拓扑维护、版本号（term）与历史快照查询。

## 项目结构

```text
src/
  ChatCore/                        # C++ 主进程
    main.cpp
    draughts_app.cpp/.hpp
    draughts_packet.hpp
    topod_client.cpp/.hpp
    ...
  TopoDaemon/                      # Go 拓扑守护进程
    main.go
    go.mod
    third_party/
      hyparview/                   # 引入的 Hyparview 库源码
```

## 构建

依赖：

- C++17 编译器
- CMake 3.16+
- OpenSSL（libcrypto）
- Go 1.22+（用于构建 TopoDaemon）

构建 `ChatCore`：

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
cd ..
```

构建 `TopoDaemon`：

```bash
./scripts/build_topod.sh ./build/TopoDaemon
```

说明：

- CMake 会生成 `./build/draughts_node`，并复制一份到 `./build/ChatCore`。
- 推荐统一使用 `./build/ChatCore` 作为 C++ 主进程启动文件。

## 配置生成

使用脚本统一生成：

- `config/generated/*.conf`（ChatCore 配置）
- `config/topod/*.json`（TopoDaemon 配置）
- `peers/*.info`（节点信息）
- `keys/*.pem`/`*.pub`（密钥）
- `topology/*.neighbors`（实验初始拓扑）

核心脚本：

```bash
./scripts/gen_configs.py --help
```

## Ubuntu 22.04（64 核）实验命令：50 中继 + 2 CLI 节点加入

以下命令按顺序执行。

### 1. 清理旧状态

```bash
cd /home/wkw/draughts_p2p
./scripts/clean_experiment.sh
```

### 2. 编译

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
cd ..
./scripts/build_topod.sh ./build/TopoDaemon
```

### 3. 初始化本次实验（生成 52 节点配置，其中 node51/node52 为 CLI）

```bash
./scripts/gen_configs.py \
  --count 52 \
  --cli-nodes 51,52 \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000
```

### 4. 批量启动 50 个不带 CLI 的节点（node1~node50）

```bash
ONLY_50=$(seq 1 50 | sed 's/^/node/' | paste -sd, -)
./scripts/run_hyparview_stack.sh \
  --chatcore-binary ./build/ChatCore \
  --topod-binary ./build/TopoDaemon \
  --only "$ONLY_50" \
  --interval 0.1 \
  --topod-delay 2
```

### 5. 单独启动两个带 CLI 的节点并加入网络

终端 A（node51）：

```bash
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node51.json ) > run/node51.topod.out 2>&1 &
exec -a ChatCore ./build/ChatCore config/generated/node51.conf
```

终端 B（node52）：

```bash
( exec -a TopoDaemon ./build/TopoDaemon config/topod/node52.json ) > run/node52.topod.out 2>&1 &
exec -a ChatCore ./build/ChatCore config/generated/node52.conf
```

### 6. CLI 交互与请求/响应命令

在 node51（终端 A）：

```text
id
neighbors
send node52 hello-from-node51
```

在 node52（终端 B）：

```text
inbox
requests
reply <session_hex> ack-from-node52
```

回到 node51（终端 A）：

```text
inbox
```

### 7. 终止实验

先在两个 CLI 终端执行：

```text
quit
```

然后在任意终端执行：

```bash
./scripts/stop_nodes.sh run/hyparview_chatcore.pids
./scripts/stop_nodes.sh run/hyparview_topod.pids
./scripts/clean_experiment.sh
```

## CLI 命令

```text
help
id
neighbors
twohop
peers
inbox
requests
send <peer_id|ipv4:port> <text>
send_session <session_hex> <text>
reply <session_hex> <text>
quit
```

## Draughts 报文布局（1280 字节）

当前 `DraughtsParams` 已包含 `topo_term` 字段，用于历史版本回溯。

```text
PK_PH_tmp(64) |
PK_PPH_tmp(64) | PK_Init_tmp(64) |
ADDR_NNH(6) | C_ADDR_Real_Receiver(6) | C_ADDR_Real_Sender(6) |
topo_term(8) | x(8) | magic(8) |
session_id(16) | C_Data(1030)
```

