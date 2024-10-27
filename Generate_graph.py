# -*- coding: utf-8 -*-
# @Time    : 2024/3/5 9:46
# @Author  : chenlelan
# @File    : Generate_graph.py

import networkx as nx
import pandas as pd
from matplotlib import pyplot as plt
from collections import namedtuple
import os
import numpy as np
from utils.preprocess import features_standard

def creat_graphs(node_file, edge_file):
    '''
    node_file--节点特征的csv文件
    edge_file--边缘特征的csv文件
    利用networkx从node_file和edge_file中加载节点和边，生成有向图
    '''
    # 加载节点和属性
    node_df = pd.read_csv(node_file)
    # 指定要规范化的列
    columns_to_normalize = node_df.columns[2:-2]  # 去除第1列的时间和第二列的IP以及最后两列的标签
    node_df = features_standard(node_df, columns_to_normalize)  # 归一化
    node_dict = {}
    node_feat_dict = {}
    label_dict = {}
    T = node_df['Time'].unique()
    print('时间戳列表', T)
    # node_feat = namedtuple('node_feat', ['b_sent_max', 'b_sent_avg', 'b_rcv_max', 'b_rcv_avg', 'p_sum', 'dur_time', 'dlt_time', 'dst_num', 'fail_con'])
    for t in T:
        # 处于同一时间窗的节点构建快照
        df = node_df.loc[node_df['Time'] == t]
        node = []
        # data = []
        node_feat = {}
        label = []
        for _, row in df.iterrows():
            node.append(row['Ip'])
            # 节点属性
            # data.append(node_feat(b_sent_max=row['BytesSentMax'], b_sent_avg=row['BytesSentAvg'], b_rcv_max=row['BytesRecvMax'], b_rcv_avg=row['BytesRecvAvg']
            #                  , p_sum=row['PktsSum'], dur_time=row['DurationAvg'], dlt_time=row['DeltaTimeAvg'], dst_num=row['DestDiveRatio'], fail_con=row['FailConRatio']))
            node_feat[row['Ip']] = [row['BytesSentMax'], row['BytesSentAvg'], row['BytesRecvMax'], row['BytesRecvAvg'], row['PktsSum'],
                                       row['DurationAvg'], row['DeltaTimeAvg'], row['DestDiveRatio'], row['FailConRatio'], row['SportNum'], row['DportNum'], row['SmallPktRatio']]
            label.append(row['Label'])
        node_dict[t] = node
        # node_feat_list.append(data)
        node_feat_dict[t] = node_feat  # 结构为{t: {node: feature}}
        # print('features of node at {} time :'.format(t), node_feat_dict[t])
        label_dict[t] = label

    # 加载边和属性
    edge_df = pd.read_csv(edge_file)
    # 指定要规范化的列
    columns_to_normal = edge_df.columns[3:]  # 去除前3列的时间和源IP以及目的IP
    edge_df = features_standard(edge_df, columns_to_normal)
    T_e = edge_df['Time'].unique()
    print('时间戳列表', T_e)
    assert T.all() == T_e.all(), "节点和边缘的时间戳不匹配"

    # 构建快照
    graphs = {}
    edge_feat_dict = {}
    for t in T:
        df_e = edge_df.loc[edge_df['Time'] == t]
        # 初始化一个空图
        G = nx.DiGraph()
        # 添加节点和属性
        l = label_dict[t]
        for i in range(len(l)):
            G.add_node(node_dict[t][i], label=l[i])

        # 添加边
        edge_feat = {}
        for _, row in df_e.iterrows():
            if row['Src'] in G:
                if row['Dst'] in G:
                    G.add_edge(row['Src'], row['Dst'])
                    edge_feat[(row['Src'], row['Dst'])] = [row['ByteMax'], row['ByteMin'], row['ByteAvg'], row['PktNum'], row['DurationTime'], row['DeltaAvg']]
        edge_feat_dict[t] = edge_feat
        # print('features of edg at {} time :'.format(t), edge_feat_dict[t])
        graphs[t] = G
        # print('nodes of graph at {} time'.format(t), graphs[t].nodes)
    return graphs, node_feat_dict, edge_feat_dict

def remap(graphs, node_feat_dict, edge_feat_dict):
    all_nodes = []
    for t in graphs:
        print("当前时刻为", t)
        assert (len(graphs[t].nodes) == len(node_feat_dict[t])), "图中节点数量与节点特征数量不匹配"
        all_nodes.extend(graphs[t].nodes)
    all_nodes = list(set(all_nodes))
    print("Total # nodes", len(all_nodes))
    # 从0开始给ip节点重新编码，计算对应的节点编码索引
    node_id = 0
    node_index = {}
    for t in graphs:
        for node in graphs[t].nodes:
            if node not in node_index:
                node_index[node] = node_id
                node_id += 1
    # print('id of the remap nodes', node_index)
    graphs_remap = []
    node_feat_remap = []
    edge_feat_remap = []
    for t in graphs:
        G = nx.DiGraph()
        n_feat = {}
        e_feat = {}
        for n in graphs[t].nodes:
            # print('原始节点ip', n ,'---->', '编码后id', node_index[n])
            G.add_node(node_index[n], label=graphs[t].nodes[n]['label'])
            n_feat[node_index[n]] = node_feat_dict[t][n]
        for e in graphs[t].edges:
            G.add_edge(node_index[e[0]], node_index[e[1]])
            # print(e[0],'****',e[1])
            e_feat[(node_index[e[0]], node_index[e[1]])] = edge_feat_dict[t][(e[0], e[1])]
        assert (len(G.nodes) == len(graphs[t].nodes)), "重新编码后的图与原图节点数不相符"
        assert (len(G.edges) == len(graphs[t].edges)), "重新编码后的图与原图边的数量不符"
        graphs_remap.append(G)
        node_feat_remap.append(n_feat)
        edge_feat_remap.append(e_feat)
        # print(edge_feat_remap)
    return graphs_remap, node_feat_remap, edge_feat_remap

def save_graphs(save_dir, graphs, node_feat, edge_feat):
    # 保存快照
    # save_dir = os.path.dirname(node_file)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    np.savez(os.path.join(save_dir, 'graphs_remap.npz'), graph=graphs)
    np.savez(os.path.join(save_dir, 'node_feat_remap.npz'), node_feat=node_feat)
    np.savez(os.path.join(save_dir, 'edge_feat_remap.npz'), edge_feat=edge_feat)

# plt.figure()
# ax1 = plt.gca()   # 保存当前的axes
def draw_graphs(graphs):
    '''
    绘制图快照
    graphs--各时间窗内的图快照列表
    '''
    t = 1
    for g in graphs:
        # 图着色，为标签为1的恶意节点设置为红色，反之则为绿色
        node_colors = []
        labels = nx.get_node_attributes(g, 'label')
        for _, label in labels.items():
            # print('label', label)
            if label == 1:
                node_colors.append('red')
            else:
                node_colors.append('green')
        plt.figure()
        p = nx.spring_layout(g)
        nx.draw_networkx(g, pos=p, node_size=30, node_shape='o',node_color=node_colors, width=1, style='solid', font_size=8)
        plt.title('Communication graph at time {}'.format(t), y=-0.1) # 在图的下方添加标题
        plt.show()
        t += 1
        # print("success")


# 测试示例
node_file = "../train_data/cleaned_data/iscx-traing-2011Aug12-15-cleaned-node-feature.csv"
edge_file = "../train_data/cleaned_data/iscx-traing-2011Aug12-15-cleaned-edge-feature.csv"
graphs, n_f, e_f = creat_graphs(node_file,edge_file)
g_remap , n_f_remap, e_f_remap = remap(graphs,n_f,e_f)
save_dir = ".../data/ISCX/"
if not os.path.isdir(save_dir):
    os.mkdir(save_dir)
save_graphs(save_dir, g_remap, n_f_remap, e_f_remap)
# gh = np.load("../data/Traffic/graphs_remap.npz", allow_pickle=True)['graph']
# adj_matrices = list(map(lambda x: nx.adjacency_matrix(x), gh))
# # print(type(graphs), len(graphs))
# # print(graphs)
# draw_graphs(gh)
# print(len(adj_matrices))





