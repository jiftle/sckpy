#!/bin/bash
# -----------------------------------------------------------------
# FileName: pub.sh
# Date: 2021-10-18
# Author: jiftle
# Description: 
# -----------------------------------------------------------------
echo "---> 编译"
go build -o sckpyc

echo "---> 发布"
cp -f ./sckpyc /opt/my-apps/sckpy

