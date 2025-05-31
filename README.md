# UpUp - 服务状态监控系统

UpUp是一个轻量级的服务状态监控系统，支持HTTP、TCP和Ping监控，提供实时状态展示、告警通知和用户管理功能。

## 功能特性

- ✅ 多协议监控：支持HTTP、TCP端口和Ping监控
- ✅ 实时状态面板：直观展示所有监控目标状态
- ✅ 历史日志：查看监控目标的历史状态变化
- ✅ 告警通知：支持邮件和Webhook告警
- ✅ 用户管理：多角色权限控制（管理员/普通用户）
- ✅ Docker支持：一键部署，开箱即用

## 技术栈

- Python Flask后端
- SQLite数据库（可配置为其他数据库）
- Bootstrap前端界面
- APScheduler定时任务
- Docker容器化

## 快速开始

### 本地运行

1. 克隆仓库：
```bash
git clone https://github.com/your-username/upup.git
cd upup
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

3. 初始化数据库：
```bash
python main.py
```

4. 访问应用：
http://localhost:5000

默认管理员账号：admin/admin123

### Docker部署

```bash
# 构建镜像
docker build -t shawn123456/upup .

# 运行容器
docker run -d -p 5000:5000 shawn123456/upup

# 使用docker-compose
docker-compose up -d
```

### Docker镜像
镜像已发布到Docker Hub：
```bash
docker pull shawn123456/upup
```

## 使用指南

1. 登录系统（默认管理员：admin/admin123）
2. 在"监控目标"页面添加监控目标
3. 在"告警配置"页面设置告警方式
4. 在"用户管理"页面管理用户权限

## 配置选项

通过环境变量配置应用：

| 变量名 | 默认值 | 描述 |
|--------|--------|------|
| `DATABASE_PATH` | monitor.db | 数据库文件路径 |
| `FLASK_DEBUG` | False | 调试模式 |
| `FLASK_APP` | main.py | 应用入口文件 |

## 贡献指南

欢迎提交Issue和PR！项目结构：

```
upup/
├── templates/       # HTML模板
├── main.py          # 主应用逻辑
├── Dockerfile       # Docker构建文件
├── docker-compose.yml # Docker编排文件
└── requirements.txt # 依赖列表
```

## 许可证

[MIT License](LICENSE)

---

# UpUp - Service Monitoring System

UpUp is a lightweight service monitoring system that supports HTTP, TCP, and Ping monitoring. It provides real-time status dashboards, alert notifications, and user management.

## Features

- ✅ Multi-protocol monitoring: HTTP, TCP port, and Ping
- ✅ Real-time dashboard: Visualize service status
- ✅ Historical logs: View status changes over time
- ✅ Alert notifications: Email and Webhook alerts
- ✅ User management: Role-based access control (Admin/User)
- ✅ Docker support: One-click deployment

## Tech Stack

- Python Flask backend
- SQLite database (configurable to others)
- Bootstrap frontend
- APScheduler for task scheduling
- Docker containerization

## Quick Start

### Local Setup

1. Clone repo:
```bash
git clone https://github.com/your-username/upup.git
cd upup
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize database:
```bash
python main.py
```

4. Access app:
http://localhost:5000

Default admin: admin/admin123

### Docker Deployment

```bash
# Build image
docker build -t shawn123456/upup .

# Run container
docker run -d -p 5000:5000 shawn123456/upup

# Using docker-compose
docker-compose up -d
```

### Docker Image
Available on Docker Hub:
```bash
docker pull shawn123456/upup
```

## User Guide

1. Login (default admin: admin/admin123)
2. Add monitoring targets in "Targets" page
3. Configure alerts in "Alerts" page
4. Manage users in "Users" page

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_PATH` | monitor.db | Database file path |
| `FLASK_DEBUG` | False | Debug mode |
| `FLASK_APP` | main.py | App entry point |

## Contributing

Issues and PRs welcome! Project structure:

```
upup/
├── templates/       # HTML templates
├── main.py          # Main application
├── Dockerfile       # Docker build
├── docker-compose.yml # Docker compose
└── requirements.txt # Dependencies
```

## License

[MIT License](LICENSE)