# -*- coding: utf-8 -*-
# @Time    : 2023/10/20 9:55
# @Author  : chenlelan
# @File    : Windows.py

# from flowcontainer.extractor import extract
from scapy.all import *
import pandas as pd
import time
from datetime import datetime

class Windows:
    # 构建滑动窗口，窗口大小设置为60s，窗口滑动增量为10s
    def __init__(self, window_size=10, window_delta=5):
        self.window_size = window_size
        assert self.window_size >= 1, "无效的窗口大小值"
        self.window_delta = window_delta
        assert self.window_delta >= 1, "无效的窗口间隔值"
        self.start_time = 0
        # self.later_time = 60
        self.end_time = float('inf')

    def get_pcap_time(self, pcap_path):
        # 获取pcap文件的最早数据包的时间戳
        pkt_list = rdpcap(pcap_path)
        self.start_time = pkt_list[0].time
        # local_st = time.localtime(st)
        # self.start_time = time.strftime('%Y-%m-%d %H:%M:%S',local_st) # 转换成新的时间格式
        # self.start_time = datetime.strptime(self.start_time,'%Y-%m-%d %H:%M:%S')   # str转时间
        self.end_time = pkt_list[-1].time
        # local_et = time.localtime(et)
        # self.end_time = time.strftime('%Y-%m-%d %H:%M:%S', local_et)
        # self.end_time = datetime.strptime(self.end_time,'%Y-%m-%d %H:%M:%S')   # str转时间
        print('数据包开始时间戳{}s'.format(self.start_time))
        print('数据包结束时间戳{}s'.format(self.end_time))
        '''将数据包列表按照时间戳组织成字典'''
        time_pkt_list = []
        for pkt in pkt_list:
            t = pkt.time
            # local_t = time.localtime(t)
            # t = time.strftime('%Y-%m-%d %H:%M:%S', local_t)  # 转换成新的时间格式
            # t = datetime.strptime(t, '%Y-%m-%d %H:%M:%S')  # str转时间
            time_pkt = [t,pkt]
            time_pkt_list.append(time_pkt)
        df = pd.DataFrame(time_pkt_list, columns=['time','value']) # 将时间戳-数据包对写入DataFrame格式
        return df

    def read_pcap(self, df, num):
        '''读取一个时间窗口的数据包'''
        df = df.loc[(df['time'] >= self.start_time) & (df['time'] <= self.start_time+self.window_size)]
        # df = df[df['time'] >= self.start_time]
        # df = df[df['time'] <= self.start_time+self.window_size]
        pkt_list = df['value'].tolist()
        self.start_time = self.start_time + self.window_delta
        print('第',num,'个窗口读取的数据包数量：', len(pkt_list))
        # result = self.flow_divide(pkt_list) # 流划分
        return pkt_list

    '''
    def read_pcap(self, pcap_path):
        # 读取一个观测窗口中的流量数据
        if self.start_time == 0:
            # 如果是第一个滑动窗口，则将窗口初始时间设置为pcap文件的最早观测时间
            self.get_pcap_time(pcap_path)
        print('滑动窗口')
        self.later_time = self.start_time+timedelta(seconds=self.window_size)
        print(self.later_time)
        result = extract(infile=pcap_path,
                         filter="(frame.time >= self.start_time) && (frame.time <= self.later_time)",
                         split_flag=True)
        self.start_time = self.start_time + timedelta(seconds=self.window_delta)
        print(self.start_time)
        return result
    '''

    '''
    def flow_divide(self, pkt_list):
        # 将数据包根据五元组进行流划分
        flow_list = []
        # 提取五元组信息
        for pkt in pkt_list:
            # pkt.show()  #展示当前类型包含的属性及值
            # 协议：其中1，标识ICMP、2标识IGMP、6标识TCP、17标识UDP、89标识OSPF。
            # pkt.payload.name:'IP','IPV6','ARP'或者其他
            if pkt.payload.name == 'IP':
                try:
                    five_tuple = '{}:{}:{}:{}:{}'.format(pkt['IP'].src,pkt.sport,pkt['IP'].dst,pkt.dport,pkt.proto)
                    flow_list.append(five_tuple)
                except AttributeError:
                    print('wrong_pkt')
            if pkt.payload.name == 'IPv6':
                try:
                    five_tuple = '{}:{}:{}:{}:{}'.format(pkt['IPv6'].src,pkt.sport,pkt['IPv6'].dst,pkt.dport,pkt.proto)
                    flow_list.append(five_tuple)
                except AttributeError:
                    print('wrong_pkt')
        # 统计相同五元组
        dicts = {}
        for item in flow_list:
            if flow_list.count(item)>=1:
                dicts[item]=flow_list.count(item)   # 统计五元组重复次数
        # 根据5元组划分流
        i = 0
        flow_dict = {}
        for pkt in pkt_list:
            i += 1
            if i % 50 == 0:  # 每100次打印以下进度
                print('流切分进度：', (i / len(pkt_list)) * 100, '%')
            if pkt.payload.name == 'IP':
                try:
                    # 读取当前数据包的信息
                    t_tuple = '{}:{}:{}:{}:{}'.format(pkt['IP'].src, pkt.sport, pkt['IP'].dst, pkt.dport, pkt.proto)
                    # 比较信息,将数据包加入对应5元组的流
                    for key in dicts.keys():
                        if t_tuple == key:
                            flow = flow_dict.get(key)
                            if flow != None:
                                flow.extend(pkt)
                            else:
                                flow = []
                                flow.extend(pkt)
                            flow_dict.update({key: flow})
                except AttributeError:
                    print('wrong_pkt')
            if pkt.payload.name == 'IPv6':
                try:
                    # 读取当前数据包的信息
                    t_tuple = "{}:{}:{}:{}:{}".format(pkt['IPv6'].src, pkt.sport, pkt['IPv6'].dst, pkt.dport, pkt.proto)
                    # 比较信息,将数据包加入对应5元组的流
                    for key in dicts.keys():
                        if t_tuple == key:
                            flow = flow_dict.get(key)
                            if flow != None:
                                flow.extend(pkt)
                            else:
                                flow = []
                                flow.extend(pkt)
                            flow_dict.update({key: flow})
                except AttributeError:
                    print('wrong_pkt')
        return flow_dict
    '''

    def set_window_size(self, val):
        self.window_size = val

    def set_window_delta(self, val):
        self.window_delta = val

    def get_window_size(self):
        return self.window_size

    def get_window_delta(self):
        return self.window_delta

    def set_start_time(self, val):
        self.start_time = val

    def get_start_time(self):
        return self.start_time

    def set_end_time(self, val):
        self.end_time = val

    def get_end_time(self):
        return self.end_time
