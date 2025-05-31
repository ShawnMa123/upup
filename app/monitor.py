import requests
import socket
from ping3 import ping
import time

def check_http(target):
    try:
        start = time.time()
        response = requests.get(target, timeout=10)
        response_time = time.time() - start
        return response_time * 1000, response.status_code == 200
    except Exception:
        return None, False

def check_tcp(target):
    host, port = target.split(':')
    port = int(port)
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=10)
        sock.close()
        response_time = time.time() - start
        return response_time * 1000, True
    except Exception:
        return None, False

def check_ping(target):
    try:
        start = time.time()
        result = ping(target, timeout=10)  # 返回延迟（秒），超时返回None
        if result is None:
            return None, False
        response_time = time.time() - start
        return response_time * 1000, True
    except Exception:
        return None, False
