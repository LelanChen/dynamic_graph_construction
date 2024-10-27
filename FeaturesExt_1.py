# -*- coding: utf-8 -*-
# @Time    : 2023/10/30 18:03
# @Author  : chenlelan
# @File    : FeaturesExt.py

import numpy as np
import pandas as pd

# ISCX
ATTACK_ISCX = ['192.168.2.112','131.202.243.84','198.164.30.2','192.168.2.110',
'192.168.2.113','192.168.1.103','192.168.2.112','192.168.2.109',
'147.32.84.180','147.32.84.170','147.32.84.140','147.32.84.130',
'10.0.2.15','192.168.106.141','172.16.253.130','172.16.253.131',
'172.16.253.240','74.78.117.238','192.168.3.35','192.168.3.25',
'172.29.0.116','172.29.0.109','192.168.248.165','10.37.130.4']

# Bot_IoT
ATTACK_BoT_IoT = ['192.168.100.147', '192.168.100.148', '192.168.100.149',
       '192.168.100.150', '192.168.100.3', '192.168.100.5', '192.168.100.6',
       '192.168.100.7']

# ToN_IoT
ATTACK_ToN_IoT = ['192.168.1.30', '192.168.1.31', '192.168.1.32', '192.168.1.193',
       '192.168.1.33', '192.168.1.37', '192.168.1.39', '192.168.1.36',
       '192.168.1.34', '192.168.1.38', '203.14.129.10', '13.55.50.68',
       '192.168.1.1', '192.168.1.250', '192.168.1.195', '192.168.1.152',
       '192.168.1.190', '192.168.1.169', '220.158.215.20']

class FeaturesExt():
    def __init__(self):
        self.node_features_name = ['Time', 'Ip', 'BytesSentMax', 'BytesSentAvg', 'BytesRecvMax', 'BytesRecvAvg',
                                   'PktsSum', 'DurationAvg', 'DeltaTimeAvg', 'DestDiveRatio',
                                   'FailConRatio', 'SportNum', 'DportNum', 'SmallPktRatio', 'Label']
        self.edge_features_name = ['Time','Src', 'Dst', 'ByteMax', 'ByteMin', 'ByteAvg', 'PktNum',
                                   'DurationTime', 'DeltaAvg']
        self.samples_num = 0

    def get_node_feature_name(self):
        return self.node_features_name

    def get_edge_feature_name(self):
        return self.edge_features_name
        
    def ext_features(self,result_df):
        adjacebcy_dict = {} # 邻接列表
        bytes_dict = {} # 主机发送数据包的字节数字典
        bytes_recv_dict = {} # 主机接收数据包的字节数字典
        pkt_num_dict = {}   # 主机传输数据包总数字典
        time_dict = {}  # 主机发送的流持续时间字典
        delta_dict = {} # 主机发送数据包的增量时间字典
        con_dict = {}  # 主机的连接状态（成功/失败）字典
        dst_dive_dict = {} # 主机的目标节点多样性字典
        sport_dict = {} # 主机的源端口使用列表字典
        dport_dict = {} # 主机的目的端口列表字典
        edge_list = []  # 流（边缘）的统计数据表
        for df in result_df:
            ip = df['src_ip'].tolist()[0]   # 当前主机的源IP
            dst = df['dst_ip'].tolist()[0]  # 目的主机的IP
            # print('发出当前会话的主机地址',ip)
            # print('接收当前会话的主机地址', dst)
            # 统计邻接列表
            src_adjacebcy_list = adjacebcy_dict.get(ip)
            dst_adjacebcy_list = adjacebcy_dict.get(dst)
            '''if self.get_con_state(df):
                # 如果会话连接成功，则将src->dst和dst->src加入邻接表
                dst_adjacebcy_list = adjacebcy_dict.get(dst)
                if src_adjacebcy_list != None:
                    src_adjacebcy_list.extend(dst)
                    adjacebcy_dict.update({ip: src_adjacebcy_list})
                else:
                    adjacebcy_dict.update({ip: [dst]})
                if dst_adjacebcy_list != None:
                    dst_adjacebcy_list.extend(ip)
                    adjacebcy_dict.update({dst: dst_adjacebcy_list})
                else: 
                    adjacebcy_dict.update({dst: [ip]})
            else: # 如果会话失败，则只将src->dst加入邻接表'''
            if src_adjacebcy_list != None:
                src_adjacebcy_list.append(dst)
                adjacebcy_dict.update({ip: src_adjacebcy_list})
            else:
                adjacebcy_dict.update({ip: [dst]})
            if self.get_con_state(df) == 'Fail': # 如果会话失败，则只将dst->src加入邻接表,防止邻居表重复
                if dst_adjacebcy_list != None:
                    dst_adjacebcy_list.append(ip)
                    adjacebcy_dict.update({dst: dst_adjacebcy_list})
                else:
                    adjacebcy_dict.update({dst: [ip]})

            # 统计每台主机发送的字节数列表构成字典bytes_dict
            src_bytes_list = bytes_dict.get(ip)
            src_b_list = self.get_src_bytes_list(df) # 源主机发送的字节数
            if src_bytes_list != None:
                src_bytes_list.extend(src_b_list)
                bytes_dict.update({ip: src_bytes_list})
            else:
                bytes_dict.update({ip: src_b_list})
            # 统计每台主机接收的字节数列表构成字典bytes_recv_dict
            dst_bytes_list = bytes_recv_dict.get(dst)
            if dst_bytes_list != None:
                dst_bytes_list.extend(src_b_list)
                bytes_recv_dict.update({dst: dst_bytes_list})
            else:
                bytes_recv_dict.update({dst: src_b_list})

            # 计算每台主机所发送的数据包数量总数
            src_pkt_num = pkt_num_dict.get(ip)
            s_pkt_num = self.get_src_pkt_num(df)
            if src_pkt_num != None:
                src_pkt_num += s_pkt_num
                pkt_num_dict.update({ip: src_pkt_num})
            else:
                pkt_num_dict.update({ip: s_pkt_num})

            # 计算每台主机的流持续时间列表构成字典times_dict
            src_duration_list = time_dict.get(ip)
            src_time_list = self.get_src_time_list(df)
            # 计算源主机发送的流持续时间
            duration_t = float(src_time_list[len(src_time_list) - 1] - src_time_list[0])
            if src_duration_list != None:
                src_duration_list.append(duration_t)
                time_dict.update({ip: src_duration_list})
            else:
                time_dict.update({ip: [duration_t]})
            '''if self.get_con_state(df):
                dst_duration_list = time_dict.get(dst)
                dst_time_list = self.get_dst_time_list(df)
                # 计算目的主机发送的流持续时间
                t = float(dst_time_list[len(dst_time_list) - 1] - dst_time_list[0])
                if dst_duration_list != None:
                    dst_duration_list.append(t)
                    time_dict.update({dst: dst_duration_list})
                else:
                    time_dict.update({dst: [t]})'''

            # 计算每台主机发送数据包的增量时间（前后两个数据包到达时间间隔）列表
            src_delta_list = delta_dict.get(ip)
            # src_time_list = self.get_src_time_list(df)
            # 计算前后两个数据包之间的增量时间
            src_d_list = self.com_delta_list(src_time_list)
            if src_delta_list != None:
                src_delta_list.extend(src_d_list)
                delta_dict.update({ip: src_delta_list})
            else:
                delta_dict.update({ip: src_d_list})
            '''if self.get_con_state(df):
                dst_delta_list = delta_dict.get(dst)
                dst_time_list = self.get_dst_time_list(df)
                # 计算前后两个数据包之间的增量时间
                dst_d_list = self.com_delta_list(dst_time_list)
                if dst_delta_list != None:
                    dst_delta_list.extend(dst_d_list)
                    delta_dict.update({dst: dst_delta_list})
                else:
                    delta_dict.update({dst: dst_d_list})'''

            # 计算每台主机的连接状态字典（失败/成功）
            con_state_list = con_dict.get(ip)
            con_state = self.get_con_state(df)
            if con_state_list != None:
                con_state_list.append(con_state)
                con_dict.update({ip: con_state_list})
            else:
                con_dict.update({ip: [con_state]})
            '''if con_state:
                dst_con_state_list = con_dict.get(dst)
                if dst_con_state_list != None:
                    dst_con_state_list.append(con_state)
                    con_dict.update({dst: dst_con_state_list})
                else:
                    con_dict.update({dst: [con_state]})'''

            # 统计每台主机的目标节点多样性(不同目的ip数量）
            dst_dive_rate = dst_dive_dict.get(ip)
            if dst_dive_rate != None:
                dst_dive_rate += 1
                dst_dive_dict.update({ip: dst_dive_rate})
            else:
                dst_dive_rate = 1
                dst_dive_dict.update({ip: dst_dive_rate})
                
            # 统计每台主机的源端口号使用列表
            pre_sport_list = sport_dict.get(ip)
            sport_list = self.get_sport_list(df)
            if pre_sport_list != None :
                pre_sport_list.extend(sport_list)
                sport_dict.update({ip: pre_sport_list})
            else:
                sport_dict.update({ip: sport_list})

            # 统计每台主机的目的端口号使用列表
            pre_dport_list = dport_dict.get(ip)
            dport_list = self.get_dport_list(df)
            if pre_dport_list != None:
                pre_dport_list.extend(dport_list)
                dport_dict.update({ip: pre_dport_list})
            else:
                dport_dict.update({ip: dport_list})

            # 统计src->dst的流（边缘）的特征
            '''
            ip -- 源IP地址
            dst -- 目的IP地址
            src_b_list -- src->dst的流发送的字节数列表
            s_pkt_num -- src->dst的流发送的数据包总数
            duration_t -- src->dst流的持续时间
            src_d_list -- src->dst的流的数据包增量时间列表
            '''
            edge = [ip, dst, src_b_list, s_pkt_num, duration_t, src_d_list]
            edge_list.append(edge)
        edge_df = pd.DataFrame(edge_list, columns=['src', 'dst', 'byte_list', 'pkt_num', 'dura_time', 'delta_list'])

        return adjacebcy_dict, bytes_dict, bytes_recv_dict, pkt_num_dict, time_dict, delta_dict, con_dict, dst_dive_dict, sport_dict, dport_dict, edge_df


    def com_features(self, result_df, time):
        (adj_dict, bytes_dict, bytes_recv_dict, pkt_num_dict, time_dict, delta_dict, con_dict, dst_dive_dict, 
         sport_dict, dport_dict, edge_df) = self.ext_features(result_df)
        # adj_dict = self.degree_based_filter(adj_dict) # 过滤
        node_features_list = self.com_node_features(adj_dict, bytes_dict, bytes_recv_dict, pkt_num_dict, time_dict, delta_dict, con_dict, dst_dive_dict, sport_dict, dport_dict, time)
        edge_features_list = self.com_edge_fetatres(edge_df, time)
        return node_features_list, edge_features_list, adj_dict

    def com_node_features(self,adj_dict, bytes_dict, bytes_recv_dict, pkt_num_dict, time_dict, delta_dict, con_dict, dst_dive_dict, sport_dict, dport_dict, time):
        row_list = []
        # adjacebcy_dict, bytes_dict, pkt_num_dict, time_dict, delta_dict, con_dict, dst_dive_dict, edge_df = self.ext_features(result_df)
        for ip in adj_dict:
            # print('*'*15,'开始提取基于主机的节点特征','*'*15)
            # print('当先主机地址：', ip)
            if bytes_dict.get(ip) != None: # 如果该节点有发送数据
                bytes_sent_max = max(bytes_dict[ip])  # 主机发送的最大字节数（最大数据包长度）
                # print('最大发送字节数：', bytes_sent_max)
                bytes_sent_avg = self.com_avg(bytes_dict[ip]) # 主机发送的平均字节数
                # print('平均发送字节数：', bytes_sent_avg)
                if bytes_recv_dict.get(ip) != None: # 如果该节点有接收数据
                    bytes_recv_max = max(bytes_recv_dict[ip])
                    # print('最大接收字节数：', bytes_recv_max)
                    bytes_recv_avg = self.com_avg(bytes_recv_dict[ip])  # 主机接收的平均字节数
                    # print('平均接收字节数：', bytes_recv_avg)
                else:
                    bytes_recv_max = 0
                    bytes_recv_avg = 0
                pkts_sum = pkt_num_dict[ip]  # 主机传输的数据包总数（包括发送和接收）
                # print('传输数据包的数量：', pkts_sum)
                duration_avg = self.com_avg(time_dict[ip])   # 主机的流平均持续时间
                # print('平均流持续时间：', duration_avg)
                delta_time_avg = self.com_avg(delta_dict[ip]) # 主机的发送数据包平均增量时间
                # print('平均增量时间：', delta_time_avg)
                dest_dive_ratio = dst_dive_dict[ip]  # 主机的目标节点多样性
                # print('目标节点多样性：', dest_dive_ratio)
                fail_con_ratio = self.com_fail_rate(con_dict[ip]) # 主机的失败连接率
                # print('失败连接率：', fail_con_ratio)
                label = self.set_label(ip)
                sport_nums = self.com_sport_num(sport_dict[ip])
                # print('源端口使用数量：', sport_nums)
                dport_nums = self.com_dport_num(dport_dict[ip])
                # print('目的端口数量：', dport_nums)
                small_pkt_ratio = self.com_small_pkt(bytes_dict[ip]) # 主机发送的小数据包的比率
                # print("小数据包数量:", small_pkt_nums)
                # print('当前主机标签：', label)
                row = [time, ip, bytes_sent_max, bytes_sent_avg, bytes_recv_max, bytes_recv_avg, pkts_sum, duration_avg,
                       delta_time_avg, dest_dive_ratio, fail_con_ratio, sport_nums, dport_nums, small_pkt_ratio, label]
                row_list.append(row)
            else:
                bytes_sent_max = 0
                bytes_sent_avg = 0
                bytes_recv_max = max(bytes_recv_dict[ip])
                bytes_recv_avg = self.com_avg(bytes_recv_dict[ip])
                pkts_sum = 0
                duration_avg = 0
                delta_time_avg = 0
                dest_dive_ratio = 0
                fail_con_ratio = 0
                sport_nums = 0
                dport_nums = 0
                small_pkt_ratio = 0
                label = self.set_label(ip)
                row = [time, ip, bytes_sent_max, bytes_sent_avg, bytes_recv_max, bytes_recv_avg, pkts_sum, duration_avg,
                       delta_time_avg, dest_dive_ratio, fail_con_ratio, sport_nums, dport_nums, small_pkt_ratio, label]
                row_list.append(row)
            self.samples_num += 1
        return row_list

    def com_edge_fetatres(self, edge_df, time):
        # print('*' * 15, '开始提取基于流的边缘特征', '*' * 15)
        row_list = []
        for i, flow in edge_df.iterrows():
            # print('源IP：',flow['src'], '目的IP：', flow['dst'])
            src = flow['src']
            dst = flow['dst']
            # e_df = edge_df.loc[(edge_df['src'] == src) & (edge_df['dst'] == v)]
            byte_max = max(flow['byte_list'])   # 流（边缘）发送的最大字节数
            # print('最大发送字节数：', byte_max)
            byte_min = min(flow['byte_list'])   # 流（边缘）发送的最小字节数
            # print('最小发送字节数：', byte_min)
            byte_avg = self.com_avg(flow['byte_list'])  # 流（边缘）平均发送的字节数
            # print('平均发送字节数：', byte_avg)
            pkt_num = flow['pkt_num']  # 流（边缘）所发送的数据包数量
            # print('发送数据包数量：', pkt_num)
            duration_time = flow['dura_time']   # 流（边缘）的通信持续时间
            # print('流通信持续时间：', duration_time)
            delta_avg = self.com_avg(flow['delta_list'])    # 流（边缘）发送数据包的平均增量时间
            # print('流的平均增量时间：', delta_avg)
            row = [time, src, dst, byte_max, byte_min, byte_avg, pkt_num, duration_time, delta_avg]
            row_list.append(row)
        return row_list

    def com_degree(self, adj_dict):
        # 根据邻接表计算节点的度数
        degree_dict = {}
        for src, dst in adj_dict.items():
            print('旧的邻接表：', src, ':', dst)
            src_degree = degree_dict.get(src)
            add_src_d = 0
            for v in dst:
                add_src_d += 1
                v_degree = degree_dict.get(v)
                if v_degree != None:
                    v_degree += 1
                    degree_dict.update({v: v_degree})
                else:
                    degree_dict.update({v: 1})
            if src_degree != None:
                src_degree += add_src_d
                degree_dict.update({src: src_degree})
            else:
                degree_dict.update({src: add_src_d})
        return degree_dict

    def degree_based_filter(self, adj_dict):
        # 根据节点度数过滤，将度数为1的节点过滤，因为这些节点不活跃，不太可能是僵尸节点
        d_dict = self.com_degree(adj_dict)
        filter_list = []     # 过滤节点列表
        for v, d in d_dict.items():
            if d <= 1:
                filter_list.append(v)
        # 将过滤掉的节点从邻接表中去除
        new_adj_dict = {}
        for src, dst in adj_dict.items():
            if src not in filter_list:
                adj_list = []
                for v in dst:
                    if v not in filter_list:
                        adj_list.append(v)
                if adj_list != None:
                    new_adj_dict.update({src: adj_list})
            else:
                pass
        return new_adj_dict

    def get_src_bytes_list(self,df):
        # 获取一个会话中源主机所发送的数据包的负载长度（字节数）列表
        forward_df = df[df['state'] == 'forward']
        src_b_list = forward_df['payload'].tolist()
        return src_b_list
    
    def get_dst_bytes_list(self,df):
        # 获取一个会话中目的主机所发送的数据包的负载长度（字节数）列表
        backward_df = df[df['state'] == 'backward']
        dst_b_list = backward_df['payload'].tolist()
        return dst_b_list

    def get_src_pkt_num(self,df):
        # 获取一个会话中源主机所发送的数据包总数
        forward_df = df[df['state'] == 'forward']
        return len(forward_df['payload'])
    
    def get_dst_pkt_num(self,df):
        # 获取一个会话中目的主机所发送的数据包总数
        backward_df = df[df['state'] == 'backward']
        return len(backward_df['payload'])

    def get_src_time_list(self,df):
        # 获取一个会话中源主机所发送数据包的时间戳列表
        forward_df = df[df['state'] == 'forward']
        src_time_list = forward_df['timestamp'].tolist()
        src_time_list.sort()    # 对时间列表进行升序排序
        return src_time_list
    
    def get_dst_time_list(self,df):
        # 获取一个会话中目的主机所发送数据包的时间戳列表
        backward_df = df[df['state'] == 'backward']
        dst_time_list = backward_df['timestamp'].tolist()
        dst_time_list.sort()    # 对时间列表进行升序排序
        return dst_time_list

    def com_delta_list(self,time_list):
        # 计算前后两个数据包之间的增量时间
        d_list = []
        for i in range(len(time_list) - 1):
            delta = float(time_list[i + 1] - time_list[i])
            d_list.append(delta)
        return d_list

    def get_con_state(self, df):
        # 判断会话是否连接失败（仅包含单向传输数据包）
        state = df['state'].tolist()
        if 'backward' in state:
            return 'Success'    # 连接成功
        else:
            return 'Fail'   # 连接失败

    def get_sport_list(self, df):
        # 获取主机通信使用的源端口列表
        forward_df = df[df['state'] == 'forward']
        sport_list = list(forward_df["sport"].value_counts().index)
        return sport_list
    
    def get_dport_list(self, df):
        # 获取主机通信的目的端口列表
        forward_df = df[df['state'] == 'forward']
        sport_list = list(forward_df["dport"].value_counts().index)
        return sport_list

    def com_small_pkt(self, byte_list):
        # 计算每台主机在观测时间内发送的没有负载或负载较小的数据包比例
        sum_small_pkts = 0
        for i in byte_list:
            if i <= 32: # 32 是根据模拟僵尸网络并将默认 paylaod 设置为 32 的 bonesi 框架选择的，可以更具实际情况合理设置
                sum_small_pkts += 1
        return sum_small_pkts / (len(byte_list) + 1e-5)

    def com_fail_rate(self, con_list):
        # 计算主机的失败连接率（失败的次数/总的通信次数）
        fail_sum = con_list.count('Fail')
        return fail_sum/(len(con_list))

    def com_sport_num(self, sport_list):
        # 计算主机的源端口使用数量
        sport_list = list(set(sport_list))  # 去除重复值
        return len(sport_list)
    
    def com_dport_num(self, dport_list):
        # 计算主机的目的端口使用数量
        dport_list = list(set(dport_list))  # 去除重复值
        return len(dport_list)

    def com_avg(self, list):
        if len(list) == 0:
            return 0
        else:
            total = sum(list)
            return total / len(list)

    def set_label(self,ip):
        if ip in ATTACK_BoT_IoT:
            return 1
        else:
            return 0

    def get_samples_num(self):
        return self.samples_num








