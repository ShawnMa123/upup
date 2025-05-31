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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        
        db.session.commit()

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
def manage_targets():
    targets = MonitorTarget.query.all()
    return render_template('targets.html', targets=targets)

@app.route('/target/add', methods=['GET', 'POST'])
@login_required
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

@app.route('/target/delete/<int:id>')
@login_required
def delete_target(id):
    target = MonitorTarget.query.get(id)
    if target:
        # 删除相关日志
        MonitorLog.query.filter_by(target_id=id).delete()
        db.session.delete(target)
        db.session.commit()
    return redirect(url_for('manage_targets'))

# 在应用启动时创建admin用户（仅用于演示）
def create_admin_user():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    # 创建数据库表
    with app.app_context():
        db.create_all()
        create_admin_user()
    # 创建数据库表
    with app.app_context():
        db.create_all()
    app.run(debug=True)