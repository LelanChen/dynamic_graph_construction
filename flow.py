# -*- coding: utf-8 -*-
# @Time    : 2024/5/15 14:35
# @Author  : chenlelan
# @File    : flow.py

from flowcontainer.extractor import extract

pcap = extract("dataset/train.pcap", filter="ip.proto == 17", split_flag=False)

duration_time = []
for key in pcap:
    value = pcap[key]
    print('Flow {0} info:'.format(key))
    ## access ip src
    print('src ip:', value.src)
    ## access ip dst
    print('dst ip:', value.dst)
    ## access srcport
    print('sport:', value.sport)
    ## access_dstport
    print('dport:', value.dport)
    print("payload lengths:", value.ip_lengths)
    flow_time = value.payload_timestamps[-1] - value.payload_timestamps[0]
    print("duration time is :", flow_time)
    duration_time.append(flow_time)

duration_time_avg = sum(duration_time) / (len(duration_time) + 1e-5)
print("Avg duration time is :", duration_time_avg)

