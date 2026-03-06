import networkx as nx
import matplotlib.pyplot as plt

# 1. 替换为最新的节点邻居列表（按你提供的新数据）
neighbors = {
    "node1": ["node3", "node4", "node8"],
    "node2": ["node5", "node6", "node7", "node8"],
    "node3": ["node1", "node10", "node5", "node7"],
    "node4": ["node1", "node10", "node5", "node7"],
    "node5": ["node2", "node3", "node4"],
    "node6": ["node2", "node7", "node8", "node9"],
    "node7": ["node2", "node3", "node4", "node6", "node9"],
    "node8": ["node1", "node10", "node2", "node6"],
    "node9": ["node10", "node6", "node7"],
    "node10": ["node3", "node4", "node8", "node9"]
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


# 3. 绘制图形（核心：4:3长宽比 + 优化布局）
# 设置4:3长宽比（如12x9、16x12、8x6，这里选12x9兼顾清晰度）
# plt.figure(figsize=(12, 9), dpi=150)  

# 布局调整：重点解释k参数和优化策略
# k=1.2（核心参数）：控制节点间距，值越大节点越分散
original_pos = nx.spring_layout(
    G, 
    seed=42,        # 固定随机种子，布局可复现
    k=1.2,          # 节点间距系数（重点调节项）
    iterations=50,  # 迭代次数，越多布局越稳定
    scale=1.0       # 布局缩放范围（0~scale）
)

# 3. 手动指定节点坐标 + 横向1.5倍拉伸（保留原有坐标配置）
# 原始手动坐标
# original_pos = {
#     "node1": (-0.2, 0.5),  
#     "node2": (0.8, 0.25),  
#     "node3": (-0.15, 0.1),  
#     "node4": (-0.4, 0.15),  
#     "node5": (0.35, 0.05),  
#     "node6": (0.3, 0.3), 
#     "node7": (0.7, 0.05),  
#     "node8": (-0.4, 0.3),  
#     "node9": (-0.1, 0.25),  
#     "node10": (-0.6, 0.05)  
# }

# 例如：将node10移到指定坐标
original_pos["node1"] = (-0.4, 0.6) 
original_pos["node3"] = (-0.20, 0) 
original_pos["node3"] = (-0.20, 0)  
original_pos["node4"] = (-0.8, -0.20)  
original_pos["node5"] = (0.05, 0.40)  
original_pos["node6"] = (0.8, -0.30)  
original_pos["node7"] = (0.2, -0.30)  
original_pos["node8"] = (0.4, 0.70)  
original_pos["node9"] = (0.6, -0.70)  

# 横向（X轴）拉伸1.5倍，Y轴保持不变
pos = {}
for node, (x, y) in original_pos.items():
    pos[node] = (x * 8, y)  # X坐标×1.5，Y坐标不变

# 4. 绘制图形（4:3长宽比 + 实心狭长三角箭头）
plt.figure(figsize=(12, 9), dpi=150)  # 4:3长宽比

# 绘制节点
nx.draw_networkx_nodes(
    G, pos, 
    node_size=2500,
    node_color="lightskyblue",
    edgecolors="black",
    linewidths=2
)

# 绘制双向箭头边（实心狭长三角，保留原有样式）
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
