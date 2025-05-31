from apscheduler.schedulers.background import BackgroundScheduler
from app import app, db
from app.models import Monitor, MonitorStatusHistory
from app.monitor import check_http, check_tcp, check_ping
from datetime import datetime

scheduler = BackgroundScheduler()

def check_monitor(monitor):
    with app.app_context():
        # 获取上一次的状态
        last_status = monitor.status

        response_time = None
        status = False
        if monitor.type == 'http':
            response_time, status = check_http(monitor.target)
        elif monitor.type == 'tcp':
            response_time, status = check_tcp(monitor.target)
        elif monitor.type == 'ping':
            response_time, status = check_ping(monitor.target)

        # 更新监控项状态
        monitor.status = status
        monitor.last_checked = datetime.utcnow()
        # 记录历史
        history = MonitorStatusHistory(
            status=status,
            response_time=response_time,
            monitor=monitor
        )
        db.session.add(history)
        db.session.commit()

        # 这里可以添加报警触发逻辑（如果状态变化或第一次失败等）
        # 检查状态变化
        if last_status != status:
            # 状态发生变化
            # 如果当前状态是失败的（false），则发送报警
            if not status:
                # 发送报警
                from app.alerts import send_alert
                send_alert(monitor, last_status, not status)
            # 还可以考虑恢复通知：如果从失败变为成功，发送恢复通知
            else:
                # 发送恢复通知
                pass
        db.session.commit()

def setup_scheduler():
    # 启动调度器
    scheduler.start()

    # 添加现有监控项的任务
    monitors = Monitor.query.all()
    for monitor in monitors:
        # 注意：这里我们使用时间间隔（秒）作为任务的触发间隔
        scheduler.add_job(
            id=f'monitor_{monitor.id}',
            func=check_monitor,
            args=(monitor,),
            trigger='interval',
            seconds=monitor.interval
        )

# 注意：在应用启动时调用setup_scheduler()
