import json, time, os
from dotenv import load_dotenv

class FileLogger:
    def __init__(self, log_file):
        self.log_file = log_file
        load_dotenv(os.path.join(os.path.dirname(__file__), '../../.env'))

    def log_event(self, service, src_ip, src_port, data):
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "service": service,
            "src_ip": src_ip,
            "src_port": src_port,
            "data": data
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")
