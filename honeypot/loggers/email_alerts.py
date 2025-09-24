import os
import time
import json
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

def load_env():
    load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))
    return {
        'SMTP_SERVER': os.getenv('SMTP_SERVER'),
        'SMTP_PORT': int(os.getenv('SMTP_PORT', '587')),
        'SMTP_USER': os.getenv('SMTP_USER'),
        'SMTP_PASSWORD': os.getenv('SMTP_PASSWORD'),
        'ALERT_EMAIL_TO': os.getenv('ALERT_EMAIL_TO'),
        'ALERT_EMAIL_FROM': os.getenv('ALERT_EMAIL_FROM'),
        'ALERT_INTERVAL_MINUTES': int(os.getenv('ALERT_INTERVAL_MINUTES', '10')),
        'LOG_FILE': os.getenv('LOG_FILE', 'logs/attacks.json'),
        'ENABLE_ALERTS': os.getenv('ENABLE_ALERTS', 'false').lower() == 'true',
        'ALERT_SERVICES': [s.strip() for s in os.getenv('ALERT_SERVICES', 'http,ssh').split(',')],
    }

def get_last_event(log_file, last_ts):
    last_event = None
    last_event_ts = last_ts
    if not os.path.exists(log_file):
        return None, last_ts
    with open(log_file, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                ts = time.mktime(time.strptime(event['timestamp'], "%Y-%m-%d %H:%M:%S"))
                if ts > last_ts:
                    last_event = event
                    last_event_ts = ts
            except Exception:
                continue
    return last_event, last_event_ts

def send_email(event, config):
    if not event:
        return
    subject = f"Honeypot Alert: {event['service']} from {event['src_ip']}"
    body = json.dumps(event, indent=2)
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = config['ALERT_EMAIL_FROM']
    msg['To'] = config['ALERT_EMAIL_TO']
    try:
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            server.starttls()
            server.login(config['SMTP_USER'], config['SMTP_PASSWORD'])
            server.sendmail(config['ALERT_EMAIL_FROM'], [config['ALERT_EMAIL_TO']], msg.as_string())
        print(f"[+] Sent alert for 1 event")
    except Exception as e:
        print(f"[!] Failed to send alert: {e}")

def main():
    config = load_env()
    if not config['ENABLE_ALERTS']:
        print("[!] Alerts are disabled in .env")
        return
    last_ts = 0
    state_file = os.path.join(os.path.dirname(__file__), '../../logs/last_alert_ts.txt')
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            try:
                last_ts = float(f.read().strip())
            except Exception:
                last_ts = 0
    event, new_last_ts = get_last_event(config['LOG_FILE'], last_ts)
    # Filter by service
    if event and event['service'] in config['ALERT_SERVICES']:
        send_email(event, config)
        with open(state_file, 'w') as f:
            f.write(str(new_last_ts))
    else:
        print("[+] No new event to alert.")

if __name__ == "__main__":
    main()
