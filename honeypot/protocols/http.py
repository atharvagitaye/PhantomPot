import http.server
import socketserver
import logging
import json
from datetime import datetime

class HTTPHoneypotHandler(http.server.BaseHTTPRequestHandler):
    def log_attack(self, data):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": self.client_address[0],
            "src_port": self.client_address[1],
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "payload": self.rfile.read(int(self.headers.get('Content-Length', 0))).decode(errors='ignore') if self.command in ['POST', 'PUT'] else ""
        }
        # Log to honeypot.log
        logging.basicConfig(filename="logs/honeypot.log", level=logging.INFO)
        logging.info(json.dumps(log_entry))
        # Log to attacks.json
        with open("logs/attacks.json", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def do_GET(self):
        self.log_attack({})
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>It works!</h1></body></html>")

    def do_POST(self):
        self.log_attack({})
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>POST received!</h1></body></html>")

    def log_message(self, format, *args):
        # Suppress default logging
        return

class HTTPHoneypot:
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port

    def run(self):
        print(f"[+] HTTP Honeypot listening on {self.host}:{self.port}")
        with socketserver.TCPServer((self.host, self.port), HTTPHoneypotHandler) as httpd:
            httpd.serve_forever()
