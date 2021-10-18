#!/bin/bash
# -----------------------------------------------------------------
# FileName: pub.sh
# Date: 2021-10-18
# Author: jiftle
# Description: 
# -----------------------------------------------------------------
echo "---> 编译"
go build

echo "---> 发布"
cp -f ./client /opt/my-apps/sckpy

