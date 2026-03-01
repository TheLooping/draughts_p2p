import graphviz


def build_simple_architecture() -> graphviz.Digraph:
    dot = graphviz.Digraph("ChatCoreArchSimple", comment="ChatCore Simple Architecture")

    dot.attr(
        rankdir="TB",
        splines="polyline",
        nodesep="0.5",
        ranksep="0.75",
        dpi="300",
        labelloc="t",
        label="ChatCore 进程内架构（简化框图）",
        fontname="Helvetica",
        fontsize="18",
    )
    dot.attr(
        "node",
        shape="box",
        style="rounded",
        fontname="Helvetica",
        fontsize="13",
        color="#425466",
    )
    dot.attr("edge", fontname="Helvetica", fontsize="11", color="#425466")

    # Top layer
    dot.node("cli", "CLI 交互层\n输入解析 / 结果展示")

    # Middle layer
    dot.node("io", "事件调度层\nio_context")

    # Bottom core modules (simple boxes only)
    dot.node("app", "报文处理模块\n随机游走 / 出口交付 / 回程转发")
    dot.node("node", "拓扑状态模块\n邻居同步 / 两跳视角 / 目录映射")
    dot.node("session", "会话管理模块\ninitiator/responder 状态\n会话复用与过期清理")
    dot.node("crypto", "加解密模块\n逐跳参数层 / 端到端载荷层\n地址字段分层处理")

    # External interfaces
    dot.node("ipc", "本地 IPC 通道\nUnix Domain Socket\nPLAN/HISTORY/STATE/TWOHOP")
    dot.node("topod", "TopoDaemon")
    dot.node("udp", "UDP 数据通道")
    dot.node("remote", "其他节点 ChatCore")

    # Rank alignment
    with dot.subgraph() as s:
        s.attr(rank="same")
        s.node("app")
        s.node("node")
        s.node("session")
        s.node("crypto")

    with dot.subgraph() as s:
        s.attr(rank="same")
        s.node("ipc")
        s.node("udp")

    # Main flow
    dot.edge("cli", "io", "异步投递")
    dot.edge("io", "app")
    dot.edge("io", "node")
    dot.edge("io", "session")
    dot.edge("io", "crypto")

    # Internal collaboration
    dot.edge("app", "session", "读写会话")
    dot.edge("app", "crypto", "加解密处理")
    dot.edge("app", "node", "节点解析/视图使用")

    # External channels
    dot.edge("app", "ipc", "路由与历史查询")
    dot.edge("node", "ipc", "邻居与两跳查询")
    dot.edge("ipc", "topod")

    dot.edge("app", "udp", "收发报文")
    dot.edge("udp", "remote")

    return dot


if __name__ == "__main__":
    graph = build_simple_architecture()
    graph.render("chatcore_architecture_diagram", format="png", cleanup=True)
    print("简化架构图已生成: chatcore_architecture_diagram.png")
