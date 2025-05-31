import json
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from ping3 import ping
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # 生产环境应使用更安全的随机密钥
import os
# 从环境变量获取数据库路径，默认为monitor.db
db_path = os.environ.get('DATABASE_PATH', 'monitor.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 管理员权限检查装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('需要管理员权限', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# 数据库模型
class MonitorTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)  # http, tcp, ping
    target = db.Column(db.String(255), nullable=False)
    interval = db.Column(db.Integer, default=60)  # 秒
    status = db.Column(db.String(20), default='unknown')
    last_checked = db.Column(db.DateTime)
    logs = db.relationship('MonitorLog', backref='target_ref', lazy=True)

class MonitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('monitor_target.id'))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    status = db.Column(db.String(20))
    response_time = db.Column(db.Float)
    message = db.Column(db.Text)

# 告警配置模型
class AlertConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    alert_type = db.Column(db.String(20), nullable=False)  # email, webhook
    config = db.Column(db.Text, nullable=False)  # JSON配置

# 监控函数
def check_http(target):
    try:
        start_time = time.time()
        response = requests.get(target, timeout=10)
        response_time = (time.time() - start_time) * 1000  # 毫秒
        if response.status_code == 200:
            return 'up', response_time, None
        else:
            return 'down', response_time, f'HTTP {response.status_code}'
    except Exception as e:
        return 'down', None, str(e)

def check_tcp(target):
    """TCP端口检查"""
    import socket
    try:
        # 解析主机和端口
        if ':' not in target:
            return 'down', None, 'Invalid target format (host:port required)'
            
        host, port_str = target.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            return 'down', None, 'Invalid port number'
            
        # 创建socket连接
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, port))
        response_time = (time.time() - start_time) * 1000  # 毫秒
        
        if result == 0:
            return 'up', response_time, None
        else:
            return 'down', response_time, f'Connection failed (error {result})'
    except Exception as e:
        return 'down', None, str(e)

def check_ping(target):
    try:
        response_time = ping(target, timeout=10) * 1000  # 毫秒
        if response_time is not None:
            return 'up', response_time, None
        else:
            return 'down', None, 'Ping failed'
    except Exception as e:
        return 'down', None, str(e)

def perform_monitoring():
    with app.app_context():
        targets = MonitorTarget.query.all()
        for target in targets:
            if target.target_type == 'http':
                status, response_time, message = check_http(target.target)
            elif target.target_type == 'tcp':
                status, response_time, message = check_tcp(target.target)
            elif target.target_type == 'ping':
                status, response_time, message = check_ping(target.target)
            else:
                continue
            
            # 更新目标状态
            target.status = status
            target.last_checked = db.func.current_timestamp()
            db.session.add(target)
            
            # 添加日志记录
            log = MonitorLog(
                target_id=target.id,
                status=status,
                response_time=response_time,
                message=message
            )
            db.session.add(log)
            
            # 检查状态变化并触发告警
            if target.status != status:
                trigger_alerts(target, status, message)
        
        db.session.commit()

# 告警触发函数
def trigger_alerts(target, new_status, message):
    # 获取所有告警配置
    alert_configs = AlertConfig.query.all()
    
    for config in alert_configs:
        if config.alert_type == 'email':
            send_email_alert(config, target, new_status, message)
        elif config.alert_type == 'webhook':
            send_webhook_alert(config, target, new_status, message)

# 邮件告警函数
def send_email_alert(config, target, status, message):
    import smtplib
    from email.mime.text import MIMEText
    import json
    
    try:
        # 解析配置
        config_data = json.loads(config.config)
        smtp_server = config_data.get('smtp_server')
        smtp_port = config_data.get('smtp_port', 587)
        username = config_data.get('username')
        password = config_data.get('password')
        from_addr = config_data.get('from_addr')
        to_addr = config_data.get('to_addr')
        
        if not all([smtp_server, username, password, from_addr, to_addr]):
            return
            
        # 创建邮件内容
        subject = f"服务告警: {target.name} 状态变为 {status}"
        body = f"""
        服务名称: {target.name}
        服务类型: {target.target_type}
        监控目标: {target.target}
        当前状态: {status}
        状态信息: {message}
        发生时间: {db.func.current_timestamp()}
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_addr
        
        # 发送邮件
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            
    except Exception as e:
        print(f"邮件发送失败: {str(e)}")

# Webhook告警函数
def send_webhook_alert(config, target, status, message):
    import requests
    import json
    
    try:
        # 解析配置
        config_data = json.loads(config.config)
        webhook_url = config_data.get('webhook_url')
        
        if not webhook_url:
            return
            
        # 创建请求数据
        payload = {
            "event": "status_change",
            "target_id": target.id,
            "target_name": target.name,
            "target_type": target.target_type,
            "target": target.target,
            "old_status": target.status,
            "new_status": status,
            "message": message,
            "timestamp": str(db.func.current_timestamp())
        }
        
        # 发送Webhook请求
        headers = {'Content-Type': 'application/json'}
        response = requests.post(webhook_url, data=json.dumps(payload), headers=headers, timeout=10)
        
        if response.status_code != 200:
            print(f"Webhook调用失败: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Webhook调用失败: {str(e)}")

# 初始化调度器
scheduler = BackgroundScheduler()
scheduler.add_job(perform_monitoring, 'interval', seconds=30)
scheduler.start()

# 路由
@app.route('/')
def dashboard():
    targets = MonitorTarget.query.all()
    return render_template('dashboard.html', targets=targets)

# 添加测试数据路由（开发用）
@app.route('/add-test')
def add_test():
    # 添加HTTP监控目标
    http_target = MonitorTarget(
        name='Example HTTP',
        target_type='http',
        target='https://example.com',
        interval=60
    )
    db.session.add(http_target)
    
    # 添加TCP监控目标
    tcp_target = MonitorTarget(
        name='Example TCP',
        target_type='tcp',
        target='example.com:80',
        interval=60
    )
    db.session.add(tcp_target)
    
    # 添加Ping监控目标
    ping_target = MonitorTarget(
        name='Example Ping',
        target_type='ping',
        target='example.com',
        interval=60
    )
    db.session.add(ping_target)
    
    db.session.commit()
    return redirect(url_for('dashboard'))

# 用户认证路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('用户名已存在', 'danger')
            return redirect(url_for('register'))
        
        # 创建新用户
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功登出', 'success')
    return redirect(url_for('dashboard'))

# 监控目标管理
@app.route('/targets')
@login_required
@admin_required
def manage_targets():
    targets = MonitorTarget.query.all()
    return render_template('targets.html', targets=targets)

@app.route('/target/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_target():
    if request.method == 'POST':
        name = request.form['name']
        target_type = request.form['type']
        target = request.form['target']
        interval = int(request.form['interval'])
        
        new_target = MonitorTarget(
            name=name,
            target_type=target_type,
            target=target,
            interval=interval
        )
        db.session.add(new_target)
        db.session.commit()
        return redirect(url_for('manage_targets'))
    
    return render_template('add_target.html')

@app.route('/target/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_target(id):
    target = MonitorTarget.query.get(id)
    if not target:
        return redirect(url_for('manage_targets'))
    
    if request.method == 'POST':
        target.name = request.form['name']
        target.target_type = request.form['type']
        target.target = request.form['target']
        target.interval = int(request.form['interval'])
        db.session.commit()
        return redirect(url_for('manage_targets'))
    
    return render_template('edit_target.html', target=target)

@app.route('/target/<int:id>')
@login_required
def target_detail(id):
    target = MonitorTarget.query.get(id)
    if not target:
        return redirect(url_for('manage_targets'))
    
    # 获取最近24小时的监控记录
    logs = MonitorLog.query.filter(
        MonitorLog.target_id == id,
        MonitorLog.timestamp >= db.func.datetime('now', '-1 day')
    ).order_by(MonitorLog.timestamp.asc()).all()
    
    return render_template('target_detail.html', target=target, logs=logs)

@app.route('/api/target/<int:id>/history')
@login_required
def target_history(id):
    # 获取最近24小时的监控记录
    logs = MonitorLog.query.filter(
        MonitorLog.target_id == id,
        MonitorLog.timestamp >= db.func.datetime('now', '-1 day')
    ).order_by(MonitorLog.timestamp.asc()).all()
    
    # 准备图表数据
    timestamps = [log.timestamp.strftime('%Y-%m-%d %H:%M') for log in logs]
    response_times = [log.response_time if log.response_time else 0 for log in logs]
    statuses = [log.status for log in logs]
    
    return {
        'timestamps': timestamps,
        'response_times': response_times,
        'statuses': statuses
    }

@app.route('/target/delete/<int:id>')
@login_required
@admin_required
def delete_target(id):
    target = MonitorTarget.query.get(id)
    if target:
        # 删除相关日志
        MonitorLog.query.filter_by(target_id=id).delete()
        db.session.delete(target)
        db.session.commit()
    return redirect(url_for('manage_targets'))

# 告警配置管理
@app.route('/alerts')
@login_required
@admin_required
def manage_alerts():
    alerts = AlertConfig.query.all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/alert/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_alert():
    if request.method == 'POST':
        name = request.form['name']
        alert_type = request.form['type']
        config_data = {}
        
        if alert_type == 'email':
            config_data = {
                'smtp_server': request.form['smtp_server'],
                'smtp_port': int(request.form['smtp_port']),
                'username': request.form['username'],
                'password': request.form['password'],
                'from_addr': request.form['from_addr'],
                'to_addr': request.form['to_addr']
            }
        elif alert_type == 'webhook':
            config_data = {
                'webhook_url': request.form['webhook_url']
            }
        
        new_alert = AlertConfig(
            name=name,
            alert_type=alert_type,
            config=json.dumps(config_data)
        )
        db.session.add(new_alert)
        db.session.commit()
        flash('告警配置添加成功', 'success')
        return redirect(url_for('manage_alerts'))
    
    return render_template('add_alert.html')

@app.route('/alert/delete/<int:id>')
@login_required
@admin_required
def delete_alert(id):
    alert = AlertConfig.query.get(id)
    if alert:
        db.session.delete(alert)
        db.session.commit()
        flash('告警配置已删除', 'success')
    return redirect(url_for('manage_alerts'))

# 修改密码
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not current_user.check_password(old_password):
            flash('原密码错误', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('新密码和确认密码不一致', 'danger')
            return redirect(url_for('change_password'))
        
        current_user.set_password(new_password)
        db.session.commit()
        flash('密码已成功更新', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# 用户管理（仅管理员）
@app.route('/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/user/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get(id)
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('manage_users'))
    
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        
        # 更新用户信息
        user.username = username
        user.role = role
        db.session.commit()
        flash('用户信息已更新', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('edit_user.html', user=user)

# 在应用启动时创建admin用户（仅用于演示）
def create_admin_user():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

# 确保数据库表已创建
with app.app_context():
    # 检查表是否存在
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    
    # 获取所有表名
    existing_tables = inspector.get_table_names()
    
    # 需要创建的表
    required_tables = ['user', 'monitor_target', 'monitor_log', 'alert_config']
    
    # 如果缺少任何表，则创建所有表
    if not all(table in existing_tables for table in required_tables):
        print("创建数据库表...")
        db.create_all()
        create_admin_user()

if __name__ == '__main__':
    # 运行应用
    DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=DEBUG_MODE, host='0.0.0.0')