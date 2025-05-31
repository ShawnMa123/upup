from datetime import datetime
from app import db

class Monitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), index=True, unique=True)
    type = db.Column(db.String(32))  # http, tcp, ping
    target = db.Column(db.String(256))  # URL or host:port
    interval = db.Column(db.Integer, default=60)  # 检查间隔，单位秒
    status = db.Column(db.Boolean, default=True)  # 当前状态，True为正常，False为异常
    last_checked = db.Column(db.DateTime)  # 上次检查时间

    # 关系（一对多，一个监控项有多个历史记录）
    status_history = db.relationship('MonitorStatusHistory', backref='monitor', lazy='dynamic')

    def __repr__(self):
        return f'<Monitor {self.name}>'

class MonitorStatusHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    status = db.Column(db.Boolean)  # 该次检查的状态
    response_time = db.Column(db.Float)  # 响应时间，单位毫秒
    monitor_id = db.Column(db.Integer, db.ForeignKey('monitor.id'))

    def __repr__(self):
        return f'<MonitorStatusHistory {self.monitor_id} {self.timestamp} {self.status}>'
