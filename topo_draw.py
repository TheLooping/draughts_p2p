import networkx as nx
import matplotlib.pyplot as plt

# 1. 节点邻居数据（保持不变）
neighbors = {
    "node1": ["node10", "node3", "node4", "node5", "node8"],
    "node2": ["node3", "node5", "node6", "node7"],
    "node3": ["node1", "node2", "node4", "node5", "node6"],
    "node4": ["node1", "node10", "node3", "node8", "node9"],
    "node5": ["node1", "node2", "node3", "node7", "node9"],
    "node6": ["node2", "node3", "node7", "node8"],
    "node7": ["node2", "node5", "node6"],
    "node8": ["node1", "node4", "node6", "node9"],
    "node9": ["node10", "node4", "node5", "node8"],
    "node10": ["node1", "node4", "node9"]
}

# 2. 创建有向图（优化边的添加逻辑，避免重复）
G = nx.DiGraph()
G.add_nodes_from(neighbors.keys())

# 关键优化：先整理无重复的边列表，再添加双向边
edges = set()
for node, nlist in neighbors.items():
    for neighbor in nlist:
        edge = tuple(sorted((node, neighbor)))
        if edge not in edges:
            edges.add(edge)
            G.add_edge(node, neighbor)
            G.add_edge(neighbor, node)

# 3. 手动指定节点坐标 + 横向1.5倍拉伸
# 原始手动坐标
original_pos = {
    "node1": (-0.1, 0.0),  
    "node2": (0.8, 0.25),  
    "node3": (-0.05, 0.1),  
    "node4": (-0.8, 0.25),  
    "node5": (0.35, 0.05),  
    "node6": (0.3, 0.3), 
    "node7": (0.7, 0.05),  
    "node8": (-0.4, 0.3),  
    "node9": (-0.1, 0.25),  
    "node10": (-0.6, 0.05)  
}

# 横向（X轴）拉伸1.5倍，Y轴保持不变
pos = {}
for node, (x, y) in original_pos.items():
    pos[node] = (x * 1.5, y)  # X坐标×1.5，Y坐标不变

# 4. 绘制图形（4:3长宽比 + 手动拉伸后的布局）
plt.figure(figsize=(12, 6), dpi=150)  # 4:3长宽比

# 绘制节点
nx.draw_networkx_nodes(
    G, pos, 
    node_size=2500,
    node_color="lightskyblue",
    edgecolors="black",
    linewidths=2
)

# 绘制双向箭头边（实心狭长三角）
nx.draw_networkx_edges(
    G, pos, 
    width=1,
    arrowstyle="Fancy, head_length=0.6, head_width=0.2, tail_width=0.1",
    arrowsize=25,
    connectionstyle="arc3,rad=0.1",  # 弧形避免箭头重叠
    alpha=0.8,
    node_size=2500,
    edge_color="#666666",
)

# 绘制节点标签
nx.draw_networkx_labels(
    G, pos, 
    font_size=12,
    font_weight="bold",
    font_family="sans-serif"
)

# 5. 保存图片
plt.axis("off")
plt.tight_layout()
# 保存时也可指定dpi，确保比例不畸变
plt.savefig("p2p_network_topology_with_arrows.png", bbox_inches="tight", dpi=150)
plt.close()

print("4:3比例的拓扑图已保存！")
