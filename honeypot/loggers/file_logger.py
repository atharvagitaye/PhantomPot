import json, time

class FileLogger:
    def __init__(self, log_file):
        self.log_file = log_file

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
