# 使用官方Python运行时作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制当前目录内容到容器的工作目录
COPY . .

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口（Flask默认端口）
EXPOSE 5000

# 定义环境变量
ENV FLASK_APP=main.py
ENV FLASK_ENV=production

# 运行应用
CMD ["flask", "run", "--host=0.0.0.0"]