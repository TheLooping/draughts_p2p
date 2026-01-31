# draughts_p2p (SM2 / HyParView / Draughts)

This project is a C++17 prototype of the **Draughts anonymous routing protocol** on a fully decentralized P2P overlay. It implements:

- **HyParView** active/passive neighbor maintenance over **UDP/IPv4**.
- **Two-hop neighbor synchronization** for localized NNH selection.
- **Draughts random-walk routing** with **CIPLC** path-length control.
- **Anonymous request/response** using **SM2-ECDH + HKDF + AES-CTR XOR**.
- CLI for interaction; all internal logs go to a file.

This is an experimental prototype and is not hardened for adversarial Internet deployment.

---

## Build

Dependencies:
- C++17 compiler
- Boost headers (Boost.System header-only is enough)
- OpenSSL (libcrypto, OpenSSL 1.1.1+)

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```

Binary: `./build/draughts_node`

---

## Run (local example)

Edit `config/default.conf` for each node and run with the config file path:

```bash
./build/draughts_node ./config/default.conf
```

Useful config options for multi-node experiments:
- `cli_enabled` (true/false): disable CLI on headless relay nodes.
- `active_neighbors_file`: path to a JSON file with current active neighbors (overwritten on update, deleted on exit).

### Experiment: 60 nodes on one server (2 CLI)

Clean old artifacts:
```bash
./scripts/clean_experiment.sh
```

Generate configs:
```bash
./scripts/gen_configs.py \
  --count 60 \
  --cli-count 2 \
  --active-min 3 \
  --active-max 5 \
  --neighbor-set-k 5 \
  --bind-ip 127.0.0.1
```

Start CLI nodes in separate terminals (do this first so seed nodes are up):
```bash
./build/draughts_node config/generated/node1.conf
./build/draughts_node config/generated/node2.conf
```

Then start 58 relay nodes (skip CLI nodes, start seeds first):
```bash
./scripts/run_nodes.sh --seed-count 3 --seed-delay 1 --skip node1,node2
```

Start topology collector and sender:
```bash
./scripts/topology_collector.py --bind 0.0.0.0 --port 9000
./scripts/send_neighbors.py --dir neighbors --host 127.0.0.1 --port 9000 --interval 2
```

Stop all background relay nodes:
```bash
./scripts/stop_nodes.sh
```

Example: three nodes on localhost:

Terminal A (`config/a.conf`)
```ini
peer_id = A
bind_ip = 127.0.0.1
overlay_port = 4000
draughts_port = 5000
```

Terminal B (`config/b.conf`)
```ini
peer_id = B
bind_ip = 127.0.0.1
overlay_port = 4001
draughts_port = 5001
bootstraps = 127.0.0.1:4000:5000
```

Terminal C (`config/c.conf`)
```ini
peer_id = C
bind_ip = 127.0.0.1
overlay_port = 4002
draughts_port = 5002
bootstraps = 127.0.0.1:4000:5000
```

Notes:
- `overlay_port` is used for HyParView maintenance traffic.
- `draughts_port` is used for Draughts data traffic.
- `bootstraps` entries use `ipv4:overlay_port:draughts_port`.

---

## CLI commands

```
help                         show help
id                           show local peer id / endpoint
neighbors                    show active neighbors
send <ipv4:port> <text>       send request to responder endpoint
inbox                        list received messages
requests                     list pending responder sessions
reply <session_hex> <text>    reply to a received request
quit                          exit
```

---

## Draughts packet layout (1280 bytes)

```
PK_PH_tmp (64) | PK_PPH_tmp (64) | PK_Init_tmp (64) | ADDR_NNH (6) |
C_ADDR_Resp (6) | C_ADDR_Init (6) | x (8) | magic (8) | session_id (16) | C_Data (1038)
```

- `ADDR_NNH`, `C_ADDR_Resp`, `C_ADDR_Init` are **IPv4(4 bytes) + port(2 bytes)**.
- `PK_PH_tmp` is the per-hop public key; it is **0xEE..EE** only in the three exit phases.
- `C_Data` is end-to-end encrypted with `PK_Init_tmp` and responder/initiator keys.

---

## Notes on deviations and simplifications

- **Out node / responder logic** follows the provided flowcharts (`doc/Initiator.png`, `doc/node.png`) where they contradict the paper narrative.
- For prototype simplicity, `C_ADDR_*` are exposed to the current hop after per-hop decryption; in a hardened design, additional link encryption can be applied.
- CIPLC uses the chaotic function described in the paper (with parameters from config) and updates `x` hop-by-hop to derive the forwarding probability.

---

## Logs

All internal logs are written to `log_file` in the config (default `draughts.log`). The CLI only prints user-facing messages.
