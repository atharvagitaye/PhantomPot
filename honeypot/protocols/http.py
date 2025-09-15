import http.server
import socketserver

import json
import time
from honeypot.loggers.file_logger import FileLogger


class HTTPHoneypotHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.logger = FileLogger("logs/attacks.json")
        super().__init__(*args, **kwargs)

    def log_attack(self, service, data=None, payload=None):
        event_data = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
        }
        if self.command in ['POST', 'PUT']:
            event_data["payload"] = payload if payload is not None else ""
        else:
            event_data["payload"] = ""
        if data:
            event_data.update(data)
        self.logger.log_event(
            service=service,
            src_ip=self.client_address[0],
            src_port=self.client_address[1],
            data=event_data
        )

    def do_GET(self):
        self.log_attack("http")
        if self.path in ["/admin", "/login"]:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            login_form = f'''
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Acme Corp Admin Login</title>
                <style>
                    body {{
                        background: #f4f6fb;
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }}
                    .login-container {{
                        background: #fff;
                        padding: 2rem 2.5rem;
                        border-radius: 8px;
                        box-shadow: 0 2px 12px rgba(0,0,0,0.08);
                        min-width: 320px;
                        text-align: center;
                    }}
                    .logo {{
                        width: 60px;
                        margin-bottom: 1rem;
                    }}
                    .login-title {{
                        font-size: 1.5rem;
                        margin-bottom: 1.5rem;
                        color: #222;
                    }}
                    .login-form label {{
                        display: block;
                        margin-bottom: 0.5rem;
                        color: #444;
                        text-align: left;
                    }}
                    .login-form input[type="text"],
                    .login-form input[type="password"] {{
                        width: 100%;
                        padding: 0.5rem;
                        margin-bottom: 1rem;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 1rem;
                    }}
                    .login-form input[type="submit"] {{
                        width: 100%;
                        padding: 0.7rem;
                        background: #1976d2;
                        color: #fff;
                        border: none;
                        border-radius: 4px;
                        font-size: 1rem;
                        cursor: pointer;
                        transition: background 0.2s;
                    }}
                    .login-form input[type="submit"]:hover {{
                        background: #125ea2;
                    }}
                </style>
            </head>
            <body>
                <div class="login-container">
                    <img src="https://upload.wikimedia.org/wikipedia/commons/5/59/Empty.png" class="logo" alt="Acme Corp Logo">
                    <div class="login-title">Acme Corp Admin Login</div>
                    <form class="login-form" method="POST" action="{self.path}">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required autofocus>
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                        <input type="submit" value="Login">
                    </form>
                </div>
            </body>
            </html>
            '''.encode()
            self.wfile.write(login_form)
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>It works!</h1></body></html>")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode(errors='ignore')
        # Parse credentials if path is /admin or /login
        if self.path in ["/admin", "/login"]:
            from urllib.parse import parse_qs
            creds = parse_qs(post_data)
            username = creds.get('username', [''])[0]
            password = creds.get('password', [''])[0]
            # Log credentials as an attack
            log_data = {
                'username': username,
                'password': password,
                'login_path': self.path
            }
            self.log_attack("http", log_data, payload=post_data)
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = (
                b"<html><head><title>Admin Panel</title></head><body>"
                b"<h2>Login failed</h2>"
                b"<p>Invalid username or password.</p>"
                b"<a href='" + self.path.encode() + b"'>Try again</a>"
                b"</body></html>"
            )
            self.wfile.write(html)
        else:
            self.log_attack("http", payload=post_data)
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
