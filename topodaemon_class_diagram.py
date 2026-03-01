import graphviz

# 创建有向图
dot = graphviz.Digraph('TwoHopView', comment='Two-Hop View Maintenance Architecture')

# --- 全局样式设置 ---
dot.attr(rankdir='TB', nodesep='0.6', ranksep='0.7')
dot.attr('node', shape='record', fontname='Helvetica-Bold', fontsize='28', style='filled', fillcolor='#f9f9f9')
dot.attr('edge', fontname='Helvetica', fontsize='28', color='#555555', penwidth='1.3')

# --- 定义类结构 ---
dot.node(
    'daemon',
    r'daemon (控制中心)\l----------------\l+self: PeerDescriptor\l+term: uint64\l+active: map[string]PeerDescriptor\l+passive: map[string]PeerDescriptor\l+selfHistory: *snapshotRing\l+neighborHistory: map[string]*snapshotRing\l+historyMeta: map[string]int64\l+store: *historyStore\l----------------\l+advanceTermLocked(reason: string)\l+handleSnapshot(msg: overlayMessage)\l+gcNeighborHistoryLocked()\l',
    shape='box',
)
dot.node(
    'PeerDescriptor',
    r'PeerDescriptor (节点详情)\l----------------\l+PeerID: string\l+IP: string\l+OverlayPort: uint16\l+DraughtsPort: uint16\l+PubKey: string\l+TopodAddr: string\l----------------\l+ValidForRoute() bool\l',
    shape='box',
)
dot.node(
    'snapshotRing',
    r'snapshotRing (快照环)\l----------------\l-limit: int\l-order: []uint64\l-byTerm: map[uint64]NeighborSnapshot\l----------------\l+Put(s: NeighborSnapshot)\l+Latest() NeighborSnapshot\l+Get(term: uint64) NeighborSnapshot\l',
    shape='box',
)
dot.node(
    'NeighborSnapshot',
    r'NeighborSnapshot (视图快照)\l----------------\l+OwnerPeerID: string\l+Term: uint64\l+Active: []PeerDescriptor\l+TimestampMs: int64\l',
    shape='box',
)
dot.node(
    'historyStore',
    r'historyStore (持久化)\l----------------\l-path: string\l-mu: sync.Mutex\l----------------\l+Append(scope: string, snap: NeighborSnapshot)\l+LoadAll() []persistedRecord\l+Lookup(owner: string, term: uint64) *NeighborSnapshot\l',
    shape='box',
)

# --- 核心：自定义层级分布 ---
# 第一层：daemon（1-1）、historyStore（1-2 与 1-3 合并）
with dot.subgraph() as s:
    s.attr(rank='same')
    s.node('daemon')
    s.node('historyStore')

# 第二层：snapshotRing（左）、NeighborSnapshot（中）、PeerDescriptor（右）
with dot.subgraph() as s:
    s.attr(rank='same')
    s.node('snapshotRing')
    s.node('NeighborSnapshot')
    s.node('PeerDescriptor')

# 2x3 网格顺序约束（第一层第二、三列合并后，不再强行绑定第二层第三列）
dot.edge('daemon', 'historyStore', style='invis', weight='120')
dot.edge('snapshotRing', 'NeighborSnapshot', style='invis', weight='120')
dot.edge('NeighborSnapshot', 'PeerDescriptor', style='invis', weight='120')
dot.edge('daemon', 'snapshotRing', style='invis', weight='120')

# --- 定义关系 ---
dot.edge('daemon', 'PeerDescriptor', label='1')
dot.edge('daemon', 'snapshotRing', label='2')
dot.edge('daemon', 'historyStore', label='3')
dot.edge('snapshotRing', 'NeighborSnapshot', label='4')
dot.edge('NeighborSnapshot', 'PeerDescriptor', label='5', constraint='false', minlen='2')
dot.edge('historyStore', 'NeighborSnapshot', label='6', style='dashed')

dot.node(
    'Legend',
    """<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="36" CELLPADDING="0">
<TR>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">1：自身身份关联<BR ALIGN="LEFT"/>2：邻居历史维护关联</TD>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">3：持久化存储关联<BR ALIGN="LEFT"/>4：快照版本存储关联</TD>
  <TD ALIGN="LEFT" VALIGN="TOP" BALIGN="LEFT">5：快照邻居包含关联<BR ALIGN="LEFT"/>6：快照数据读写关联</TD>
</TR>
</TABLE>>""",
    shape='plain',
    fontname='Helvetica',
    fontsize='28',
)
# 底部整体居中：用左右端节点对称锚定 Legend
dot.edge('snapshotRing', 'Legend', style='invis', weight='70')
dot.edge('PeerDescriptor', 'Legend', style='invis', weight='70')

# --- 保存渲染 ---
try:
    dot.render('two_hop_class_diagram', format='png', cleanup=True)
    print("恭喜！类图已成功生成： two_hop_class_diagram.png")
except Exception as e:
    print(f"渲染失败，请确保系统已安装 graphviz 软件: {e}")
