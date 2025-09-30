import os
import time
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
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
        'ALERT_EMAIL_FROM_NAME': os.getenv('ALERT_EMAIL_FROM_NAME', 'PhantomPot Security System'),
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

def format_html_email(event):
    """Create a professional HTML email format for honeypot alerts"""
    
    # Determine attack type and icon
    service = event['service'].upper()
    service_icons = {
        'SSH': '🔑',
        'HTTP': '🌐', 
        'FTP': '📁'
    }
    icon = service_icons.get(service, '⚠️')
    
    # Extract relevant data based on service type
    data = event.get('data', {})
    timestamp = event.get('timestamp', 'Unknown')
    src_ip = event.get('src_ip', 'Unknown')
    src_port = event.get('src_port', 'Unknown')
    
    # Service-specific details
    details = ""
    if service == 'SSH':
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        command = data.get('decoy_command', data.get('command', 'N/A'))
        
        details = f"""
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Username:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{username}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Password:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{password}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Command:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{command}</td></tr>
        """
    
    elif service == 'HTTP':
        method = data.get('method', 'N/A')
        path = data.get('path', 'N/A')
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        user_agent = data.get('user_agent', 'N/A')
        
        details = f"""
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Method:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{method}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Path:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{path}</td></tr>
        """
        if username != 'N/A':
            details += f"""
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Username:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{username}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Password:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{password}</td></tr>
            """
        details += f"""
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">User Agent:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;word-break:break-all;">{user_agent}</td></tr>
        """
    
    elif service == 'FTP':
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        command = data.get('command', 'N/A')
        
        details = f"""
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Username:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{username}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Password:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{password}</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Command:</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{command}</td></tr>
        """
    
    # Determine threat level color
    threat_color = "#ff4444"  # High threat (red)
    if data.get('login_attempt'):
        threat_level = "HIGH - Credential Attack"
    elif username != 'N/A' and password != 'N/A':
        threat_level = "HIGH - Authentication Attempt"
    elif service == 'HTTP' and data.get('method') == 'POST':
        threat_level = "MEDIUM - Data Submission"
    else:
        threat_level = "LOW - Reconnaissance"
        threat_color = "#ff9944"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>PhantomPot Security Alert</title>
    </head>
    <body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
        
        <!-- Header -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);color:white;padding:20px;text-align:center;border-radius:10px 10px 0 0;">
            <h1 style="margin:0;font-size:24px;">{icon} PhantomPot Security Alert</h1>
            <p style="margin:5px 0 0 0;opacity:0.9;">Suspicious Activity Detected</p>
        </div>
        
        <!-- Threat Level Banner -->
        <div style="background:{threat_color};color:white;padding:15px;text-align:center;font-weight:bold;font-size:16px;">
            🚨 THREAT LEVEL: {threat_level}
        </div>
        
        <!-- Main Content -->
        <div style="background:#f9f9f9;padding:20px;border:1px solid #ddd;">
            <h2 style="color:#333;margin-top:0;border-bottom:2px solid #667eea;padding-bottom:10px;">
                {service} Attack Details
            </h2>
            
            <table style="width:100%;border-collapse:collapse;background:white;border-radius:5px;overflow:hidden;box-shadow:0 2px 5px rgba(0,0,0,0.1);">
                <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Timestamp:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{timestamp}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Source IP:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;color:#666;font-family:monospace;">{src_ip}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Source Port:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{src_port}</td></tr>
                <tr><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold;color:#333;">Service:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;color:#666;">{service}</td></tr>
                {details}
            </table>
        </div>
        
        <!-- Actions Section -->
        <div style="background:#e8f4f8;padding:20px;border:1px solid #b8e6f0;border-top:none;">
            <h3 style="color:#2c5aa0;margin-top:0;">🛡️ Recommended Actions</h3>
            <ul style="color:#333;padding-left:20px;">
                <li>Block the source IP address: <code style="background:#fff;padding:2px 5px;border:1px solid #ddd;border-radius:3px;">{src_ip}</code></li>
                <li>Investigate for additional reconnaissance from this source</li>
                <li>Review firewall rules and access controls</li>
                <li>Monitor for similar attack patterns</li>
            </ul>
        </div>
        
        <!-- Footer -->
        <div style="background:#2c3e50;color:white;padding:15px;text-align:center;border-radius:0 0 10px 10px;">
            <p style="margin:0;font-size:14px;">🍯 Generated by PhantomPot Honeypot System</p>
            <p style="margin:5px 0 0 0;font-size:12px;opacity:0.8;">
                For more information, check your honeypot logs and dashboard
            </p>
        </div>
        
        <!-- Raw Data (Collapsible) -->
        <div style="margin-top:20px;border:1px solid #ddd;border-radius:5px;">
            <div style="background:#f5f5f5;padding:10px;font-weight:bold;color:#666;border-bottom:1px solid #ddd;">
                📋 Raw Event Data (for technical analysis)
            </div>
            <div style="padding:15px;background:#f9f9f9;">
                <pre style="background:white;padding:15px;border:1px solid #ddd;border-radius:3px;overflow-x:auto;font-size:12px;line-height:1.4;">{json.dumps(event, indent=2)}</pre>
            </div>
        </div>
        
    </body>
    </html>
    """
    
    return html_body

def send_email(event, config):
    if not event:
        return
    
    # Create professional subject line
    service = event['service'].upper()
    src_ip = event.get('src_ip', 'Unknown')
    
    # Determine urgency based on attack type
    data = event.get('data', {})
    if data.get('login_attempt') or (data.get('username') and data.get('password')):
        urgency = "[HIGH PRIORITY]"
    else:
        urgency = "[ALERT]"
    
    subject = f"{urgency} PhantomPot: {service} Attack from {src_ip}"
    
    # Create multipart message for HTML email
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    
    # Format sender with custom name
    sender_name = config.get('ALERT_EMAIL_FROM_NAME', 'PhantomPot Security System')
    sender_email = config['ALERT_EMAIL_FROM']
    formatted_sender = f"{sender_name} <{sender_email}>"
    
    msg['From'] = formatted_sender
    msg['To'] = config['ALERT_EMAIL_TO']
    
    # Create HTML version
    html_body = format_html_email(event)
    html_part = MIMEText(html_body, 'html')
    
    # Create plain text fallback
    text_body = f"""
PhantomPot Security Alert - {service} Attack Detected

⚠️  THREAT DETECTED ⚠️

Timestamp: {event.get('timestamp', 'Unknown')}
Service: {service}
Source IP: {src_ip}
Source Port: {event.get('src_port', 'Unknown')}

Attack Details:
"""
    
    if service == 'SSH':
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        command = data.get('decoy_command', data.get('command', 'N/A'))
        text_body += f"""
- Username Attempted: {username}
- Password Attempted: {password}
- Command Executed: {command}
"""
    elif service == 'HTTP':
        method = data.get('method', 'N/A')
        path = data.get('path', 'N/A')
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        text_body += f"""
- HTTP Method: {method}
- Path Accessed: {path}
- Username Attempted: {username}
- Password Attempted: {password}
"""
    elif service == 'FTP':
        username = data.get('username', 'N/A')
        password = data.get('password', 'N/A')
        command = data.get('command', 'N/A')
        text_body += f"""
- Username Attempted: {username}
- Password Attempted: {password}
- FTP Command: {command}
"""
    
    text_body += f"""

Recommended Actions:
1. Block source IP: {src_ip}
2. Investigate for additional reconnaissance
3. Review access controls
4. Monitor for similar patterns

---
Generated by PhantomPot Honeypot System
"""
    
    text_part = MIMEText(text_body, 'plain')
    
    # Attach parts (email clients will display HTML if supported, text otherwise)
    msg.attach(text_part)
    msg.attach(html_part)
    
    try:
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            server.starttls()
            server.login(config['SMTP_USER'], config['SMTP_PASSWORD'])
            server.sendmail(config['ALERT_EMAIL_FROM'], [config['ALERT_EMAIL_TO']], msg.as_string())
        print(f"[+] Sent professional HTML alert for {service} attack from {src_ip}")
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
