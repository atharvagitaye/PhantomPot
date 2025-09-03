import socket
import threading
import paramiko
from honeypot.loggers.file_logger import FileLogger

# Generate an in-memory RSA host key for the fake SSH server
HOST_KEY = paramiko.RSAKey.generate(2048)

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, logger, client_ip, client_port):
        self.logger = logger
        self.client_ip = client_ip
        self.client_port = client_port

    def check_auth_password(self, username, password):
        self.logger.log_event(
            service="ssh",
            src_ip=self.client_ip,
            src_port=self.client_port,
            data={"username": username, "password": password}
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

class SSHHoneypot:
    def __init__(self, host, port, log_file):
        self.host = host
        self.port = port
        self.logger = FileLogger(log_file)

    def handle_client(self, client, addr):
        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(HOST_KEY)

            server = HoneypotServer(self.logger, addr[0], addr[1])
            transport.start_server(server=server)

            chan = transport.accept(20)
            if chan is None:
                transport.close()
        except Exception as e:
            print(f"[!] Error handling {addr}: {e}")
        finally:
            client.close()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(100)

        print(f"[+] SSH Honeypot (Paramiko) listening on {self.host}:{self.port}")

        while True:
            client, addr = sock.accept()
            print(f"[+] Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client, addr)).start()