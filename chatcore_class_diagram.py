import graphviz
from PIL import Image

# 创建有向图
dot = graphviz.Digraph("ChatCoreProcess", comment="ChatCore Process Class Architecture")

# --- 全局样式设置 ---
# 14.64 cm ~= 5.76 in，按 A4 纵向版心宽度控制导出尺寸
dot.attr(
    rankdir="TB",
    nodesep="0.3",
    ranksep="0.7",
    dpi="300",
    size="5.76,3.40",
    ratio="compress",
    margin="0.03",
    pad="0.02",
)
dot.attr(
    "node",
    shape="record",
    fontname="Helvetica-Bold",
    fontsize="28",
    style="filled",
    fillcolor="#f9f9f9",
)
dot.attr("edge", fontname="Helvetica", fontsize="28", color="#555555", penwidth="1.2")

# --- 定义类结构 ---
dot.node(
    "Cli",
    r"Cli (命令分发)\l----------------\l-node_: DraughtsNode&\l-app_: DraughtsApp&\l-stop_: atomic_bool\l-th_: thread\l----------------\l+start()\l+join()\l-run()\l",
    shape="box",
    group="right_col",
)
dot.node(
    "DraughtsApp",
    r"DraughtsApp (报文业务引擎)\l----------------\l-node_: DraughtsNode&\l-identity_: Sm2KeyPair\l-topod_: TopodClient\l-initiator_sessions_: map(session_id to InitiatorSession)\l-responder_lru_: ResponderLru\l----------------\l+start() bool\l+cmd_send(dest, text)\l+cmd_reply(session_hex, text)\l+handle_random_walk(p, from)\l+handle_exit_packet(p, from)\l",
    shape="box",
    group="left_col",
)
dot.node(
    "DraughtsNode",
    r"{DraughtsNode (拓扑缓存管理) | -active_neighbors_: vector(PeerDescriptor)\l-directory_: map(peer_id to PeerDescriptor)\l-twohop_: map(nh_id to TwoHopEntry)\l-topod_: TopodClient\l-topod_term_: uint64\l | +start() bool\l+cmd_show_neighbors()\l+cmd_show_twohop()\l+lookup_peer(peer_id)\l+pick_nnh_for(nh, exclude, strict)\l}",
    group="left_col",
)
dot.node(
    "TopodClient",
    r"TopodClient (TopoDaemon IPC 客户端)\l----------------\l-socket_path_: string\l-timeout_ms_: uint32\l-logger_: Logger&\l----------------\l+pick_route(exclude, out) bool\l+pick_history_nnh(nh, term, exclude, strict, out) bool\l+query_state(out) bool\l+query_twohop(out) bool\l",
    shape="box",
    group="left_col",
)
dot.node(
    "Config",
    r"Config (全局配置)\l----------------\l+peer_id: string\l+bind_ip: string\l+overlay_port: uint16\l+draughts_port: uint16\l+topod_ipc_socket: string\l+session_ttl_ms: uint32\l----------------\l+load_config(path, out, err) bool\l",
    shape="box",
    group="left_col",
)
dot.node(
    "PeerDescriptor",
    r"{proto::PeerDescriptor (节点描述) | +peer_id: string\l+ip: uint8[4]\l+overlay_port: uint16\l+draughts_port: uint16\l+pubkey: string\l | +to_tlv() Bytes\l+from_tlv(b) PeerDescriptor\l}",
    group="right_col",
)
dot.node(
    "DraughtsPacket",
    r"{DraughtsPacket (UDP 固定报文) | +pk_ph_tmp: uint8[64]\l+params: DraughtsParams\l+session_id: uint8[16]\l+c_data: uint8[1030]\l | +kPacketSize = 1280\l+is_exit_pk(pk) bool\l}",
    group="right_col",
)
dot.node(
    "ResponderLru",
    r"{DraughtsApp::ResponderLru (回复会话缓存) | -lru_: list(Entry)\l-index_: map(session_id to deque_iter)\l-capacity_: size_t\l | +insert_head(sid, value)\l+get_first_and_move_to_tail(sid, out) bool\l+session_counts() vector(pair(session_id,count))\l}",
    group="right_col",
)

# --- 核心：自定义层级分布 ---
with dot.subgraph() as s:
    s.attr(rank="same")
    s.node("DraughtsApp")
    s.node("Cli")

with dot.subgraph() as s:
    s.attr(rank="same")
    s.node("DraughtsNode")
    s.node("DraughtsPacket")

with dot.subgraph() as s:
    s.attr(rank="same")
    s.node("TopodClient")
    s.node("ResponderLru")

with dot.subgraph() as s:
    s.attr(rank="same")
    s.node("Config")
    s.node("PeerDescriptor")

# 两列纵向锚定，避免中间层整体偏移
dot.edge("DraughtsApp", "DraughtsNode", style="invis", weight="100")
dot.edge("DraughtsNode", "TopodClient", style="invis", weight="100")
dot.edge("TopodClient", "Config", style="invis", weight="100")

dot.edge("Cli", "DraughtsPacket", style="invis", weight="100")
dot.edge("DraughtsPacket", "ResponderLru", style="invis", weight="100")
dot.edge("ResponderLru", "PeerDescriptor", style="invis", weight="100")

# 锚定左右方向：确保左列在左、右列在右
dot.edge("DraughtsApp", "Cli", style="invis", weight="120")

# --- 定义关系 ---
dot.edge("Cli", "DraughtsNode", label="1")
dot.edge("Cli", "DraughtsApp", label="2")

dot.edge("DraughtsNode", "TopodClient", label="3")
dot.edge("DraughtsApp", "TopodClient", label="4")

dot.edge("DraughtsNode", "PeerDescriptor", label="5")
dot.edge("DraughtsApp", "DraughtsPacket", label="6")
dot.edge("DraughtsApp", "ResponderLru", label="7")
dot.edge("DraughtsApp", "DraughtsNode", label="8")

dot.edge("TopodClient", "Config", label="9", style="dashed")
dot.edge("DraughtsNode", "Config", label="10", style="dashed")
dot.edge("DraughtsApp", "Config", label="11", style="dashed")

dot.node(
    "Legend",
    """<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="36" CELLPADDING="0">
<TR>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">1：拓扑查询命令关联<BR ALIGN="LEFT"/>2：发送与回复命令关联<BR ALIGN="LEFT"/>3：STATE/TWOHOP 拉取关联</TD>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">4：PLAN/HISTORY 请求关联<BR ALIGN="LEFT"/>5：节点目录维护关联<BR ALIGN="LEFT"/>6：报文编解码与转发关联</TD>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">7：待回复会话管理关联<BR ALIGN="LEFT"/>8：本地邻居查询关联<BR ALIGN="LEFT"/>9：IPC 参数读取关联</TD>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">10：节点参数读取关联<BR ALIGN="LEFT"/>11：协议参数读取关联</TD>
</TR>
</TABLE>>""",
    shape="plain",
    fontname="Helvetica",
    fontsize="28",
)
# 底部整体居中：用左右端节点对称锚定 Legend
dot.edge("DraughtsApp", "Legend", style="invis", weight="70")
dot.edge("PeerDescriptor", "Legend", style="invis", weight="70")

# --- 保存渲染 ---
try:
    target_width_cm = 14.64
    target_dpi = 300
    output_png = "chatcore_class_diagram.png"

    dot.render("chatcore_class_diagram", format="png", cleanup=True)

    target_width_px = round((target_width_cm / 2.54) * target_dpi)
    with Image.open(output_png) as img:
        src_w, src_h = img.size
        target_height_px = round(src_h * target_width_px / src_w)
        resized = img.resize((target_width_px, target_height_px), Image.Resampling.LANCZOS)
        resized.save(output_png, dpi=(target_dpi, target_dpi))

    print(f"恭喜！类图已成功生成： {output_png}（宽度约 {target_width_cm}cm）")
except Exception as e:
    print(f"渲染失败，请确保系统已安装 graphviz 软件: {e}")
