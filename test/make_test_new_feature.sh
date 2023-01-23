#!/bin/bash
# path="/Users/chenyu/Documents/Coding/openssl-master/"
path="/usr/local/lib/"
# g++ -std=c++11 -pthread -O3 -L ${path} -l ssl -l crypto test_new_feature.cpp  -o test_new_feature -I ${path}

g++ -std=c++11 -pthread -O3 -L ${path} -l ssl -l crypto test_new_feature.cpp  -o test_new_feature -I ${path} 