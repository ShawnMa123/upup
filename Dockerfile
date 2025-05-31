# 第一阶段：构建环境
FROM python:3.9-alpine as builder

# 安装构建依赖
RUN apk add --no-cache build-base libffi-dev

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# 第二阶段：运行环境
FROM python:3.9-alpine

# 从构建阶段复制已安装的依赖
COPY --from=builder /install /usr/local

# 设置工作目录
WORKDIR /app

# 复制应用代码
COPY . .

# 暴露端口
EXPOSE 5000

# 设置环境变量
ENV FLASK_APP=main.py
ENV FLASK_ENV=production

# 运行应用
CMD ["flask", "run", "--host=0.0.0.0"]