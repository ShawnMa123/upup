#!/bin/bash

# 设置日志文件
LOG_FILE="docker-build-$(date +%Y%m%d%H%M%S).log"
echo "操作日志将保存到: $LOG_FILE"

# 获取当前版本号
if [ -f VERSION ]; then
  current_version=$(cat VERSION)
else
  current_version="1.0"
fi

# 分割版本号
major=$(echo $current_version | cut -d. -f1)
minor=$(echo $current_version | cut -d. -f2)

# 递增小版本号
new_minor=$((minor + 1))
new_version="${major}.${new_minor}"

# 更新版本文件
echo $new_version > VERSION
echo "新版本号: $new_version" | tee -a $LOG_FILE

# 构建镜像（带版本号和latest标签）
echo "开始构建镜像..." | tee -a $LOG_FILE
docker build -t shawn123456/upup:$new_version -t shawn123456/upup:latest . 2>&1 | tee -a $LOG_FILE

# 检查构建是否成功
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "镜像构建失败! 请查看日志: $LOG_FILE" | tee -a $LOG_FILE
    exit 1
fi

# 推送镜像
echo "开始推送镜像到Docker Hub..." | tee -a $LOG_FILE
docker push shawn123456/upup:$new_version 2>&1 | tee -a $LOG_FILE
docker push shawn123456/upup:latest 2>&1 | tee -a $LOG_FILE

echo "构建并推送完成! 新版本: $new_version" | tee -a $LOG_FILE
echo "详细日志已保存到: $LOG_FILE"