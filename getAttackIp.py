# -*- coding: utf-8 -*-
# @Time    : 2024/5/11 20:07
# @Author  : chenlelan
# @File    : getAttackIp.py

import pandas as pd
def getAttackIp(data_path):
    df = pd.read_csv(data_path)
    attack_df = df[df["label"] == 1]
    # attack_df = df[df.iloc[:, 32] == 1]
    attack_ip = attack_df["src_ip"].value_counts().index
    # attack_ip = attack_df.iloc[:, 4].value_counts().index
    print("All Attack IP")
    print(attack_ip)
    proto = df["proto"].value_counts()
    print(proto)
    '''# udp_attack_df = df.loc[(df["attack"] == 1) & (df["proto"] == 'udp')]
    udp_attack_df = df.loc[(df.iloc[:, -3] == 1) & (df.iloc[:, 3] == 'udp')]
    # udp_attack_ip = udp_attack_df["saddr"].value_counts().index
    udp_attack_ip = udp_attack_df.iloc[:, 4].value_counts().index
    print("UDP Attack IP")
    print(udp_attack_ip)
    # tcp_attack_df = df.loc[(df["attack"] == 1) & (df["proto"] == 'tcp')]
    tcp_attack_df = df.loc[(df.iloc[:, -3] == 1) & (df.iloc[:, 3] == 'tcp')]
    # tcp_attack_ip = tcp_attack_df["saddr"].value_counts().index
    tcp_attack_ip = tcp_attack_df.iloc[:, 4].value_counts().index
    print("tcp Attack IP")
    print(tcp_attack_ip)
    # http_attack_df = df.loc[(df["attack"] == 1) & (df["proto"] == 'http')]
    http_attack_df = df.loc[(df.iloc[:, -3] == 1) & (df.iloc[:, 3] == 'http')]
    # http_attack_ip = http_attack_df["saddr"].value_counts().index
    http_attack_ip = http_attack_df.iloc[:, 4].value_counts().index
    print("http Attack IP")
    print(http_attack_ip)
    # icmp_attack_df = df.loc[(df["attack"] == 1) & (df["proto"] == 'icmp')]
    icmp_attack_df = df.loc[(df.iloc[:, -3] == 1) & (df.iloc[:, 3] == 'icmp')]
    # icmp_attack_ip = icmp_attack_df["saddr"].value_counts().index
    icmp_attack_ip = icmp_attack_df.iloc[:, 4].value_counts().index
    print("icmp Attack IP")
    # print(icmp_attack_df)
    print(icmp_attack_ip)
    # dst_ip = attack_df["daddr"].value_counts().index
    dst_ip = attack_df.iloc[:, 6].value_counts().index
    print(dst_ip)'''

data_path = "D:/科研/小论文/数据集/ToN-IoT/Train_Test_Network_dataset/train_test_network.csv"
getAttackIp(data_path)