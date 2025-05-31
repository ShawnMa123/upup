from flask_mail import Mail, Message
from app import app

mail = Mail(app)

def send_alert(monitor, was_successful, now_failed):
    # 在这里实现发送邮件的逻辑
    # 例如，当监控从成功变为失败时发送
    # was_successful: 上一次状态
    # now_failed: 当前状态（失败）
    if was_successful and now_failed:
        msg = Message(f"Monitor {monitor.name} is down!",
                      sender="alert@example.com",
                      recipients=["admin@example.com"])
        msg.body = f"The monitor {monitor.name} ({monitor.target}) is currently down."
        mail.send(msg)
