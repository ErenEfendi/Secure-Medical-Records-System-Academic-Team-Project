# server/monitor.py
import logging
import time
import re
from collections import defaultdict, deque
from server.routes.log_routes import log_audit

LOG_FILE = "server/logs/audit.log"
FAILED_LOGIN_THRESHOLD = 5
TIME_WINDOW = 60 # seconds
failed_logins = defaultdict(deque)

def check_log_line(line):
    if "LOGIN" in line and "Failed" in line:
        # Extract IP address
        ip_match = re.search(r'ip="([^"]+)"', line)
        if ip_match:
            ip = ip_match.group(1)
            now = time.time()
            failed_logins[ip].append(now)
            
            # Clean up old entries
            while failed_logins[ip] and failed_logins[ip][0] < now - TIME_WINDOW:
                failed_logins[ip].popleft()
            
            if len(failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
                alert_msg = f"[ALERT] POTENTIAL BRUTE FORCE ATTACK DETECTED FROM {ip}!"
                print(alert_msg)
                log_audit("BRUTE_FORCE", ip=ip, result=alert_msg, level=logging.WARNING)
                return

def monitor():
    print(f"Starting Log Monitor on {LOG_FILE}...")
    try:
        with open(LOG_FILE, "r") as f:
            # Go to the end of the file
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5) # Wait for new logs
                    continue
                check_log_line(line)
    except FileNotFoundError:
        print("Log file not found yet. Waiting...")
        time.sleep(5)
        monitor()

if __name__ == "__main__":
    monitor()