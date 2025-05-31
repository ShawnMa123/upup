from flask import render_template, request, redirect, url_for
from app import app, db
from app.models import Monitor

@app.route('/')
def index():
    monitors = Monitor.query.all()
    return render_template('index.html', monitors=monitors)

@app.route('/add', methods=['POST'])
def add_monitor():
    name = request.form['name']
    type = request.form['type']
    target = request.form['target']
    interval = int(request.form['interval'])
    monitor = Monitor(name=name, type=type, target=target, interval=interval)
    db.session.add(monitor)
    db.session.commit()
    return redirect(url_for('index'))
