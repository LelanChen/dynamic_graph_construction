# -*- coding: utf-8 -*-
# @Time    : 2023/10/23 9:47
# @Author  : chenlelan
# @File    : SavetoCsv.py

import csv, os, glob, re
import numpy as np

class CSV():

    def __init__(self, file_name="file.csv", folder_name=""):
        self.file_name = file_name
        self.folder_name = folder_name
        self.current_file_name = ""
        self.rows = 0
        self.csv_w = None
        self.csv_r = None
        if(self.file_name.endswith(".csv") is True):
            pass
        else:
            self.file_name = self.file_name + ".csv"

        def create_folder(folder_name):
            # 如果输入的文件夹不存在，创建一个空文件夹
            if(self.folder_name != ""):
                if (os.path.exists(folder_name)):
                    pass
                else:
                    os.makedirs(folder_name)
            else:
                pass

        create_folder(self.folder_name)

    def create_empty_csv(self):
        file_name = self.file_name.replace(".csv", "")
        numbers = []
        if(self.folder_name == ""):
            pass
        else:
            file_name = self.folder_name + "/" + file_name
        for fn in glob.glob(file_name + "*.csv"):   # 返回所有匹配的csv文件路径列表
            val = re.findall('\d+', fn)  # 正则化，遍历一个字符串，获得其中所有符合正则条件（包含数字）的字符，返回一个列表
            # print(val)
            if(len(val) == 0):
                pass
            else:
                numbers.append(int(val[len(val)-1]))
        if(len(numbers) == 0):
            numbers.append(0)
        new_index = max(numbers) + 1
        file_name = file_name + "_" + str(new_index) + ".csv"
        self.csv_w = open(file_name, "a+", newline='')
        self.csv_r = open(file_name, "r", newline='')
        if(self.folder_name != ""):
            part_of_name = file_name.split("/")
            self.current_file_name = part_of_name[len(part_of_name)-1]
        else:
            self.current_file_name = file_name

    def add_row(self, row):
        csv_writer = csv.writer(self.csv_w, delimiter=",")
        csv_writer.writerow(row)
        self.rows = self.rows + 1

    def add_rows(self, rows):
        csv_writer = csv.writer(self.csv_w, delimiter=",")
        csv_writer.writerows(rows)
        self.rows = self.rows + len(rows)

    def add_dict(self, dict, time):
        # 将不等长的邻接表字典存入csv
        for key, value in dict.items():
            row = [time, key] + value    # 将邻接表的源ip添加到列表前面
            print('邻接表：', type(key))
            print('邻接表：', row)
            np.savetxt(self.csv_w, [row], fmt='%s', delimiter=' ')


    def close_csv(self):
        if(self.csv_w is not None):
            self.csv_w.close()
        if(self.csv_r is not None):
            self.csv_r.close()

    def open_csv(self):
        file_name = self.get_file_path()
        try:
            self.csv_w = open(file_name, "a+", newline='')
            self.csv_r = open(file_name, "r", newline='')
        except Exception as e:
            print(e)
        if(self.csv_r is not None):
            try:
                csv_reader = csv.reader(self.csv_r, delimiter=",")
                self.rows = 0
                for row in csv_reader:
                    self.rows += 1
            except Exception as e:
                print(e)
        else:
            pass

    def get_number_of_rows(self, ignore_header=True):
        if(ignore_header is True):
            return self.rows - 1
        else:
            return self.rows

    def get_folder_name(self):
        return self.folder_name

    def get_current_file_name(self):
        return self.current_file_name

    def get_file_path(self):
        if(self.get_folder_name() == ""):
            return self.get_current_file_name()
        else:
            return self.get_folder_name() + "/" + self.get_current_file_name()