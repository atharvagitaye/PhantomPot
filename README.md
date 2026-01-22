# PhantomPot 🍯

**A Multi-Protocol Honeypot System for Cybersecurity Research and Threat Intelligence**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Protocols](https://img.shields.io/badge/protocols-SSH%20%7C%20HTTP%20%7C%20FTP-orange)](#supported-protocols)

## Overview

PhantomPot is a sophisticated, multi-protocol honeypot system designed for cybersecurity research, threat intelligence gathering, and network security monitoring. It simulates vulnerable services to attract and log malicious activities, providing valuable insights into attack patterns, credential harvesting attempts, and threat actor behaviors.

### Key Objectives
- **Threat Detection**: Early warning system for network intrusions
- **Intelligence Gathering**: Collect IOCs (Indicators of Compromise)
- **Research**: Analyze attack methodologies and malware samples
- **Education**: Learn about cybersecurity through hands-on experience

## Features

### Core Capabilities
- **Multi-Protocol Support**: SSH, HTTP (WordPress), and FTP honeypots
- **Real-time Logging**: JSON-structured attack logs with timestamps
- **Email Alerts**: Automated notifications for new attack attempts
- **Geolocation Tracking**: IP-based geographic analysis (GeoLite2)
- **Credential Harvesting**: Capture login attempts and brute-force attacks
- **Interactive Deception**: Realistic service responses to maintain attacker engagement

### Technical Features
- **Concurrent Handling**: Multi-threaded architecture for simultaneous connections
- **Configurable Services**: Enable/disable protocols via YAML configuration
- **Professional Email Alerts**: HTML-formatted security notifications with threat analysis
- **Extensible Design**: Easy addition of new protocol implementations
- **Docker Ready**: Containerized deployment support
- **SIEM Integration**: Compatible with Splunk, ELK, and other analytics platforms

## Supported Protocols

### SSH Honeypot (Port 2222)
- **Paramiko-based** SSH server simulation
- **Credential logging** for all authentication attempts
- **Interactive shell** with realistic Ubuntu environment
- **Command logging** for post-authentication activities
- **Session recording** capabilities

### HTTP Honeypot (Port 8081)  
- **WordPress login page** simulation
- **Realistic CSS/HTML** mimicking genuine WordPress installations
- **POST data capture** for credential harvesting
- **Multi-path support** (`/`, `/wp-admin`, `/wp-login.php`)
- **User-Agent analysis** for bot detection

### FTP Honeypot (Port 2121)
- **Full FTP protocol** implementation
- **Directory navigation** simulation
- **File operation logging** (RETR, STOR, DELE, etc.)
- **Passive/Active mode** responses
- **Brute-force detection** capabilities

## Architecture

```
PhantomPot/
├── honeypot/
│   ├── protocols/          # Protocol implementations
│   │   ├── ssh.py          # SSH honeypot service
│   │   ├── http.py         # HTTP/WordPress honeypot
│   │   └── ftp.py          # FTP honeypot service
│   ├── loggers/            # Logging subsystem
│   │   ├── file_logger.py  # JSON file logging
│   │   └── email_alerts.py # Email notification system
│   ├── config.yaml         # Main configuration file
│   ├── server.py           # Main orchestration server
│   └── email_scheduler.py  # Alert scheduling service
├── logs/                   # Attack logs and data
│   ├── attacks.json        # Primary attack log
│   ├── honeypot.log        # System logs
│   └── last_alert_ts.txt   # Alert state tracking
└── requirements.txt        # Python dependencies
```

## Installation

### Prerequisites
- **Python 3.7+**
- **pip** package manager
- **Git** for cloning the repository

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/atharvagitaye/PhantomPot.git
   cd PhantomPot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables** (optional)
   ```bash
   cp .env.example .env
   # Edit .env with your email settings for alerts
   ```

4. **Run the honeypot**
   ```bash
   python -m honeypot.server
   ```

### Docker Installation

```bash
# Build the container
docker build -t phantompot .

# Run with port mapping
docker run -d \
  --name phantompot \
  -p 2222:2222 \
  -p 8081:8081 \
  -p 2121:2121 \
  -v $(pwd)/logs:/app/logs \
  phantompot
```

## Configuration

### Main Configuration (`honeypot/config.yaml`)

```yaml
honeypot:
  ssh:
    enabled: true
    port: 2222
  http:
    enabled: true
    port: 8081
  ftp:
    enabled: true
    port: 2121

logging:
  log_file: "./logs/attacks.json"
```

### Email Alerts (`.env`)

```bash
# Email Configuration
ENABLE_ALERTS=true
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_FROM=honeypot@yourserver.com
ALERT_EMAIL_FROM_NAME=PhantomPot Security System
ALERT_EMAIL_TO=security@yourcompany.com
ALERT_INTERVAL_MINUTES=10
ALERT_SERVICES=ssh,http,ftp
```

## Usage

### Starting the Honeypot

```bash
# Start all services
python -m honeypot.server

# Start specific protocols only
# (modify config.yaml to disable unwanted services)
```

### Individual Service Testing

```bash
# Test SSH honeypot
ssh admin@localhost -p 2222

# Test HTTP honeypot  
curl http://localhost:8081/

# Test FTP honeypot
ftp localhost 2121
```

### Log Analysis

```bash
# View recent attacks
tail -f logs/attacks.json

# Count attack types
jq -r '.service' logs/attacks.json | sort | uniq -c

# Extract credentials
jq -r 'select(.data.username) | "\(.data.username):\(.data.password)"' logs/attacks.json
```

## Monitoring & Analytics

### Splunk Integration

**Top SSH Usernames:**
```splunk
index=honeypot sourcetype=json service=ssh username=*
| stats count by username | sort -count | head 10
```

**FTP Brute Force Detection:**
```splunk
index=honeypot sourcetype=json service=ftp login_attempt=true
| stats count by src_ip | where count > 10 | sort -count
```

**HTTP Attack Timeline:**
```splunk
index=honeypot sourcetype=json service=http
| timechart span=1h count by path
```

### ELK Stack Configuration

**Logstash Configuration:**
```ruby
input {
  file {
    path => "/path/to/PhantomPot/logs/attacks.json"
    start_position => "beginning"
    codec => "json"
  }
}

filter {
  if [service] {
    mutate {
      add_tag => ["honeypot", "%{service}"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "honeypot-%{+YYYY.MM.dd}"
  }
}
```

### Custom Analytics

```python
# Python analysis script
import json
from collections import Counter

def analyze_attacks():
    with open('logs/attacks.json', 'r') as f:
        attacks = [json.loads(line) for line in f]
    
    # Top attack sources
    ips = Counter(attack['src_ip'] for attack in attacks)
    print("Top Attack Sources:", ips.most_common(10))
    
    # Credential analysis
    creds = [(a['data'].get('username'), a['data'].get('password')) 
             for a in attacks if 'username' in a.get('data', {})]
    print("Most Common Credentials:", Counter(creds).most_common(10))

if __name__ == "__main__":
    analyze_attacks()
```

## Security Considerations

### Deployment Best Practices

1. **Network Segmentation**
   - Deploy in isolated VLAN/subnet
   - Implement firewall rules to prevent lateral movement
   - Monitor all traffic to/from honeypot systems

2. **Resource Limits**
   - Implement connection rate limiting
   - Set maximum concurrent connections
   - Monitor system resource usage

3. **Legal Compliance**
   - Ensure deployment complies with local laws
   - Obtain necessary approvals for network monitoring
   - Document incident response procedures

### Security Hardening

```bash
# Run as non-root user
useradd -r -s /bin/false honeypot
sudo -u honeypot python -m honeypot.server

# Implement firewall rules
iptables -A INPUT -p tcp --dport 2222 -m limit --limit 10/min -j ACCEPT
iptables -A INPUT -p tcp --dport 8081 -m limit --limit 20/min -j ACCEPT
iptables -A INPUT -p tcp --dport 2121 -m limit --limit 10/min -j ACCEPT
```

## Development

### Adding New Protocols

1. Create protocol handler in `honeypot/protocols/`
2. Implement logging integration
3. Update configuration schema
4. Add service initialization in `server.py`

Example protocol template:
```python
class NewProtocolHoneypot:
    def __init__(self, host, port, log_file):
        self.host = host
        self.port = port
        self.logger = FileLogger(log_file)
    
    def handle_client(self, client, addr):
        # Protocol-specific implementation
        pass
    
    def start(self):
        # Service startup logic
        pass
```

## Roadmap

### Upcoming Features
- **Telnet Honeypot** - Legacy protocol simulation
- **SMTP Honeypot** - Email service deception
- **Database Honeypots** - MySQL/PostgreSQL simulation
- **IoT Protocols** - MQTT, CoAP support
- **Web Dashboard** - Real-time monitoring interface
- **Machine Learning** - Automated threat classification
- **Kubernetes Deployment** - Cloud-native orchestration

### Enhancement Priorities
1. **Performance Optimization** - Asynchronous I/O implementation
2. **Advanced Analytics** - Built-in threat intelligence correlation
3. **API Integration** - RESTful API for external systems
4. **Mobile Alerts** - Push notifications via mobile apps

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
**⚠️ Disclaimer**: PhantomPot is designed for legitimate cybersecurity research, education, and network defense purposes. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction. The authors are not liable for any misuse of this software.
##DEV