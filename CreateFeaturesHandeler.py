# -*- coding: utf-8 -*-
# @Time    : 2023/10/23 10:23
# @Author  : chenlelan
# @File    : CreateFeaturesHandeler.py
import os.path
import glob
from FlowDivider import FlowDivider
from Windows import Windows
from FeaturesExt_1 import FeaturesExt
from SavetoCsv import CSV
import pickle

class CreateFeaturesHandeler():
    # 创建特征提取管理器
    def __init__(self, window_size=20, window_delta=10, single_csv=True):
        self.window_size = window_size
        self.window_delta = window_delta
        self.single_csv = single_csv
        assert (self.single_csv is True) or (self.single_csv is False), "single_csv标志的值无效"
        self.windows = Windows(window_size=self.window_size, window_delta=self.window_delta)
        self.Fe = FeaturesExt()
        self.Fd = FlowDivider()

        if self.single_csv:
            # 创建一个空csv文件，首行写入特征名
            self.csv1 = CSV(file_name="node-features")
            self.csv1.create_empty_csv()
            self.csv1.add_row(self.Fe.get_node_feature_name())
            self.csv2 = CSV(file_name="edge-features")
            self.csv2.create_empty_csv()
            self.csv2.add_row(self.Fe.get_edge_feature_name())
            self.csv3 = CSV(file_name="node-features")
            self.csv3.add_row(['time_stamp', 'src', 'dst'])
            self.csv3.create_empty_csv()

    def extract_features(self,folder_path):
        global adj_dict_path
        it = 1   # dataset中pcap文件数计数器
        for pcap_path in glob.glob(folder_path + "/" + "*.pcap"):  # 遍历文件夹中的所有pcap文件
            if self.single_csv:
                csv1 = self.csv1
                csv2 = self.csv2
                csv3 = self.csv3
            else:
                pcap_name = os.path.basename(pcap_path)
                pcap_name = pcap_name.split('.')[0]
                folder_name = folder_path + '/features'
                if not os.path.isdir(folder_name):
                    os.mkdir(folder_name)
                csv1 = CSV(file_name=pcap_name + '-node-feature', folder_name=folder_name)
                csv1.create_empty_csv()
                csv1.add_row(self.Fe.get_node_feature_name())
                csv2 = CSV(file_name=pcap_name + '-edge-feature', folder_name=folder_name)
                csv2.create_empty_csv()
                csv2.add_row(self.Fe.get_edge_feature_name())
                csv3 = CSV(file_name=pcap_name + '-adj-dict', folder_name=folder_name)
                csv3.create_empty_csv()
                csv3.add_row(['time', 'src', 'dst'])
                adj_dict_path = folder_name + pcap_name + '-adj-dict.pickle'

            # 通过滑动时间窗口提取特征
            t = 0 # 窗口计数器,表示静态图快照的时间戳
            print('处理第{}数据集{}'.format(it, pcap_path))
            it += 1
            time_pkt_df = self.windows.get_pcap_time(pcap_path)  # 获取{时间戳：数据包}字典
            print("\n计算 " + pcap_path + " 的特征\n")
            adj_dict_list = []
            while self.windows.get_start_time() < self.windows.get_end_time():
                pkts_list = self.windows.read_pcap(time_pkt_df, t)    # 当前窗口内监测到的数据包列表
                bidflows = self.Fd.bidflow_divide(pkts_list)     # 根据五元组对数据包进行流划分
                node_features_list, edge_features_list, adj_dict = self.Fe.com_features(bidflows, t)
                adj_dict_list.append(adj_dict)
                self.savetopkl(adj_dict_path, adj_dict_list)
                csv1.add_rows(node_features_list)
                csv2.add_rows(edge_features_list)
                csv3.add_dict(adj_dict, t)
                t += 1
            r = csv1.get_number_of_rows()
            print('写入的行数', r)
            csv1.close_csv()
            csv2.close_csv()
            csv3.close_csv()

    def savetopkl(self, path, data):
        with open(path, 'wb') as f:
            pickle.dump(data, f)


