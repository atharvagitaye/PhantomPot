import yaml
import os
from honeypot.protocols.ssh import SSHHoneypot
from honeypot.protocols.http import HTTPHoneypot
from honeypot.protocols.ftp import FTPHoneypot

def load_config(path="honeypot/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    config = load_config()

    ssh_conf = config["honeypot"].get("ssh", {})
    http_conf = config["honeypot"].get("http", {})
    ftp_conf = config["honeypot"].get("ftp", {})
    log_file = config["logging"]["log_file"]

    import threading

    threads = []
    
    # Start honeypot services
    if ssh_conf.get("enabled", False):
        ssh_honeypot = SSHHoneypot(
            host="0.0.0.0",
            port=ssh_conf.get("port", 2222),
            log_file=log_file
        )
        t = threading.Thread(target=ssh_honeypot.start)
        t.start()
        threads.append(t)
        print(f"[+] SSH Honeypot started on port {ssh_conf.get('port', 2222)}")

    if http_conf.get("enabled", False):
        http_honeypot = HTTPHoneypot(
            host="0.0.0.0",
            port=http_conf.get("port", 8080)
        )
        t = threading.Thread(target=http_honeypot.run)
        t.start()
        threads.append(t)
        print(f"[+] HTTP Honeypot started on port {http_conf.get('port', 8080)}")

    if ftp_conf.get("enabled", False):
        ftp_honeypot = FTPHoneypot(
            host="0.0.0.0",
            port=ftp_conf.get("port", 21),
            log_file=log_file
        )
        t = threading.Thread(target=ftp_honeypot.start)
        t.start()
        threads.append(t)
        print(f"[+] FTP Honeypot started on port {ftp_conf.get('port', 21)}")

    # Start email alert scheduler if enabled
    from dotenv import load_dotenv
    load_dotenv()
    if os.getenv('ENABLE_ALERTS', 'false').lower() == 'true':
        from honeypot.email_scheduler import EmailAlertScheduler
        interval = int(os.getenv('ALERT_INTERVAL_MINUTES', '1'))
        email_scheduler = EmailAlertScheduler(interval_minutes=interval)
        email_scheduler.start()
        print(f"[+] Email alert scheduler started (interval: {interval} minutes)")
    
    print("[+] All services started. Press Ctrl+C to stop.")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")