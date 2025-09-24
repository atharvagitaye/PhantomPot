#!/usr/bin/env python3
"""
Automatic email alert scheduler for PhantomPot honeypot
Runs continuously and sends email alerts for new attacks at configured intervals
"""
import os
import sys
import time
import threading
import signal
from datetime import datetime

# Add honeypot module to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from honeypot.loggers.email_alerts import main as send_alerts

class EmailAlertScheduler:
    def __init__(self, interval_minutes=1):
        """
        Initialize the email alert scheduler
        
        Args:
            interval_minutes (int): How often to check for new alerts (in minutes)
        """
        self.interval_minutes = interval_minutes
        self.interval_seconds = interval_minutes * 60
        self.running = False
        self.thread = None
        
    def start(self):
        """Start the email alert scheduler"""
        if self.running:
            print("[!] Email scheduler is already running")
            return
            
        print(f"[+] Starting email alert scheduler (checking every {self.interval_minutes} minutes)")
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        
    def stop(self):
        """Stop the email alert scheduler"""
        if not self.running:
            return
            
        print("[+] Stopping email alert scheduler...")
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
            
    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Checking for new attacks...")
                
                # Run the email alerts check
                send_alerts()
                
                # Wait for the next interval
                time.sleep(self.interval_seconds)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Error in email scheduler: {e}")
                time.sleep(self.interval_seconds)
                
def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\n[+] Received shutdown signal")
    scheduler.stop()
    sys.exit(0)

def main():
    """Main function to run the email scheduler"""
    global scheduler
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Load interval from environment or use default
    from honeypot.loggers.email_alerts import load_env
    config = load_env()
    interval = config.get('ALERT_INTERVAL_MINUTES', 1)
    
    if not config.get('ENABLE_ALERTS', False):
        print("[!] Email alerts are disabled in .env file")
        print("[!] Set ENABLE_ALERTS=true to enable automatic email alerts")
        sys.exit(1)
    
    print(f"[+] PhantomPot Email Alert Scheduler")
    print(f"[+] Alert interval: {interval} minutes")
    print(f"[+] Monitoring: {config.get('LOG_FILE', 'logs/attacks.json')}")
    print(f"[+] Services: {', '.join(config.get('ALERT_SERVICES', ['http', 'ssh']))}")
    print(f"[+] Email from: {config.get('ALERT_EMAIL_FROM', 'N/A')}")
    print(f"[+] Email to: {config.get('ALERT_EMAIL_TO', 'N/A')}")
    print("[+] Press Ctrl+C to stop\n")
    
    # Create and start the scheduler
    scheduler = EmailAlertScheduler(interval_minutes=interval)
    scheduler.start()
    
    try:
        # Keep the main thread alive
        while scheduler.running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.stop()

if __name__ == "__main__":
    main()