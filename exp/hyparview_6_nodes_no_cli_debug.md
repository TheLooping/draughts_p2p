# Hyparview 6 节点无 CLI 调试实验（TopoDaemon IPC 卡住）

## 1. 目标

- 生成 6 节点、全部 `cli_enabled=false` 的实验配置
- 本机运行 `TopoDaemon + draughts_node` 约 3 秒
- 不执行 `./scripts/clean_experiment.sh` 结束实验
- 基于本地日志定位 “IPC 拿不到 active 邻居” 的真实原因

## 2. 环境与编译

在仓库根目录执行：

```bash
cmake --build build -j
./scripts/build_topod.sh ./build/TopoDaemon
```

## 3. 生成 6 节点无 CLI 配置

```bash
./scripts/clean_experiment.sh
./scripts/gen_configs.py \
  --count 6 \
  --cli-nodes "" \
  --active-min 3 \
  --active-max 5 \
  --bind-ip 127.0.0.1 \
  --topod-base 6000
```

## 4. 启动并运行 3 秒（无 CLI）

```bash
./scripts/run_hyparview_stack.sh \
  --only node1,node2,node3,node4,node5,node6 \
  --interval 0.1 \
  --topod-delay 1

sleep 2

for i in 1 2 3 4 5 6; do
  echo "[STATE node$i]"
  printf "STATE\n" | nc -U run/topod/node$i.sock -w 1 || true
done

echo "[PLAN node1]"
printf "PLAN\n" | nc -U run/topod/node1.sock -w 1 || true

sleep 1
```

## 5. 结束实验（不清理）

只停进程，不执行 `./scripts/clean_experiment.sh`：

```bash
./scripts/stop_nodes.sh run/hyparview_chatcore.pids
./scripts/stop_nodes.sh run/hyparview_topod.pids
```

## 6. 本地现象与证据

### 6.1 IPC 请求进入但没有任何响应

`run/node1.topod.out`：

- `03:56:17` 收到 `STATE`，日志停在 `开始处理命令`
- `03:56:23` 收到 `PLAN`，日志也停在 `开始处理命令`
- 没有出现 `命令处理成功` / `命令处理结果` / `请求处理完成`

同样现象出现在 `node2~node6` 的 `STATE` 请求日志。

### 6.2 Overlay 广泛超时（2s）

`run/node1.topod.out`、`run/node2.topod.out` 等多处出现：

- `warn: [overlay] 响应读取失败 ... i/o timeout`
- `warn: [overlay] 成员消息发送失败 ... i/o timeout`

说明成员消息调用链长时间卡住，最终触发 `exchangeOverlay` 的 2 秒超时。

### 6.3 ChatCore 静态邻居已加载，不是“本地邻居文件为空”

`logs/node*.log` 显示：

- `static topology loaded: active=3 twohop=3`

即 ChatCore 侧静态邻居是有数据的，问题发生在 TopoDaemon 动态路径/IPC 路径。

## 7. 根因定位（代码级）

核心问题在 `src/TopoDaemon/main.go` 的锁与网络调用顺序：

1. `applyMutation` 在持有 `d.mu` 时执行 `fn()`
2. `fn()` 里会触发 `d.hv.SendJoin` / `d.hv.Recv`，进一步走到 `exchangeOverlay` 做网络 I/O
3. 对端在处理消息时会广播 snapshot，调用 `storeSnapshot` 也要抢同一个 `d.mu`
4. 于是形成锁等待链：  
   - 一侧持锁等待网络响应  
   - 另一侧处理该请求后又需要回调/广播并等待对方处理  
   - IPC `STATE/PLAN` 也需拿同一把锁，因此请求进入后卡住不返回

结论：  
不是简单的 “TopoDaemon 完全没连通”，而是 **TopoDaemon 在成员消息 + 快照广播路径上出现持锁网络调用导致的阻塞/近似死锁**，连带使 IPC 无法及时返回 active 邻居。

## 8. 修复与复测（2026-02-27）

### 8.1 修复点

文件：`src/TopoDaemon/main.go`

- 快照广播改为队列异步执行，成员消息先返回再广播（避免 Join 请求与 snapshot 回调互相等待）
- `bootstrapLoop` 判空改为 `active_size == 0`（避免 active=1 时持续重复 bootstrap）
- overlay 发送策略调整：  
  - `Join/ForwardJoin/Shuffle/高优先级 Neighbor` 写入后即返回，不等待对端 ACK  
  - 仅对低优先级 `Neighbor` 保留等待响应（用于 `neighbor_refuse` 语义）

### 8.2 复测结果（6 节点，无 CLI，运行约 3 秒）

使用与上文一致的启动命令，IPC 输出如下：

```text
[STATE node1]
OK term=5 active=node2,node3,node4,node5,node6
[STATE node2]
OK term=5 active=node1,node3,node4,node5,node6
[STATE node3]
OK term=4 active=node1,node2,node4,node5
[STATE node4]
OK term=4 active=node1,node2,node3,node6
[STATE node5]
OK term=3 active=node1,node2,node3
[STATE node6]
OK term=3 active=node1,node2,node4
[PLAN node1]
OK term=3 nh_id=node5 ... nnh_id=node3 ...
```

结论：  
修复后 `TopoDaemon` IPC 已能稳定返回 active 邻居与 PLAN 路由，不再出现“请求进入后无响应”的卡死现象。
