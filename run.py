import os

from app import app, db
from app.scheduler import setup_scheduler

if __name__ == '__main__':
    # 在启动Flask应用之前设置调度器
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        setup_scheduler()
    app.run(debug=True)