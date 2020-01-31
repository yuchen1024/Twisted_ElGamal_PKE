#!/bin/bash
dir="~/Documents/Project/openssl-master"

g++ -std=c++11 -pthread -O3 test_elgamal.cpp -L ${dir} -l ssl -l crypto -o test_elgamal -I ${dir}