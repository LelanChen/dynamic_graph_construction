# -*- coding: utf-8 -*-
# @Time    : 2023/10/23 16:27
# @Author  : chenlelan
# @File    : main.py

from CreateFeaturesHandeler import CreateFeaturesHandeler
from Windows import Windows
from FlowDivider import FlowDivider
from FeaturesExt import FeaturesExt

def main():
    cfh = CreateFeaturesHandeler(single_csv=False)
    cfh.extract_features('dataset')



if __name__ == "__main__":
    main()