# -*- coding: utf-8 -*-
# @Time    : 2023/10/25 16:14
# @Author  : chenlelan
# @File    : FlowDivide.py

import pandas as pd

class FlowDivider():
    '''根据五元组对数据包进行流划分'''
    '''这是一个双向流（会话）划分类'''

    def create_five_tuple(self, pkt_list):
        # 将数据包根据五元组进行流划分
        list = []
        '''提取五元组信息'''
        for pkt in pkt_list:
            # pkt.show()  #展示当前类型包含的属性及值
            # 协议：其中1，标识ICMP、2标识IGMP、6标识TCP、17标识UDP、89标识OSPF。
            # pkt.payload.name:'IP','IPV6','ARP'或者其他
            if pkt.payload.name == 'IP':
                try:
                    five_tuple = '{}:{}:{}:{}:{}'.format(pkt['IP'].src, pkt.sport, pkt['IP'].dst, pkt.dport, pkt.proto)
                    ip_feature = [pkt['IP'].src, pkt.sport, pkt['IP'].dst, pkt.dport, pkt.proto, five_tuple, pkt.time, pkt.payload.len]
                    # print(ip_feature)
                    list.append(ip_feature)
                except AttributeError:
                    print('wrong_pkt')
            if pkt.payload.name == 'IPv6':
                try:
                    five_tuple = '{}:{}:{}:{}:{}'.format(pkt['IPv6'].src, pkt.sport, pkt['IPv6'].dst, pkt.dport, pkt.proto)
                    ip_feature = [pkt['IP'].src, pkt.sport, pkt['IP'].dst, pkt.dport, pkt.proto, five_tuple, pkt.time, pkt.payload.len]
                    list.append(ip_feature)
                except AttributeError:
                    print('wrong_pkt')
        pkts_df = pd.DataFrame(list, columns=['src_ip', 'sport', 'dst_ip', 'dport', 'proto', 'five_tuple', 'timestamp', 'payload'])
        print('IP协议过滤后数据包数量：', len(pkts_df['src_ip']))
        return pkts_df

    def bidflow_divide(self,pkts_list):
        # 通过value_counts将大的pkts_df拆分成小的pkts_df
        '''根据源IP和目的IP将数据包列表划分会话（即前向流和后向流）'''
        pkts_df = self.create_five_tuple(pkts_list)
        print('*'*15,'打印窗口中IP分布情况','*'*15)
        src_diff = pkts_df['src_ip'].value_counts().index # 对不同的源IP进行计数，并取其索引
        print('IP数量：',len(src_diff))
        print(pkts_df['src_ip'].value_counts())
        bidflows = []
        for src_ip in src_diff:
            src_df = pkts_df[pkts_df['src_ip'] == src_ip]
            diff_dst_index = src_df['dst_ip'].value_counts().index
            for dst_ip in diff_dst_index:
                # print('*' * 15, '一次会话', '*' * 15)
                # 定义src_ip -> dst_ip 为前向流forward
                forward_se = pkts_df.loc[pkts_df['src_ip'] == src_ip, 'dst_ip'] == dst_ip  # 这是通过两列数据定位pkts_df
                forward_df = pkts_df.loc[forward_se[forward_se == True].index]
                forward_df['state'] = 'forward'
                # 定义dst_ip -> src_ip 为前向流backward
                backward_se = pkts_df.loc[pkts_df['src_ip'] == dst_ip, 'dst_ip'] == src_ip  # 这是通过两列数据定位pkts_df
                backward_df = pkts_df.loc[backward_se[backward_se == True].index]
                backward_df['state'] = 'backward'
                bid_flow_df = pd.concat([forward_df, backward_df]) # 迭代返回一对src_ip和dst_ip对应的会话
                bidflows.append(bid_flow_df)
        return  bidflows



