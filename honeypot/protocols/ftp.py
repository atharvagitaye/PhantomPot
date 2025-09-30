import socket
import threading
import os
from honeypot.loggers.file_logger import FileLogger

class FTPHoneypot:
    def __init__(self, host, port, log_file):
        self.host = host
        self.port = port
        self.logger = FileLogger(log_file)

    def handle_client(self, client, addr):
        """Handle FTP client connection"""
        try:
            # Send FTP welcome banner
            client.send(b"220 Welcome to FTP Server\r\n")
            
            username = None
            authenticated = False
            current_dir = "/"
            
            while True:
                try:
                    # Receive command from client
                    data = client.recv(1024)
                    if not data:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    if not command:
                        continue
                    
                    # Log the command
                    self.logger.log_event(
                        service="ftp",
                        src_ip=addr[0],
                        src_port=addr[1],
                        data={"command": command, "authenticated": authenticated}
                    )
                    
                    # Parse FTP commands
                    parts = command.split(' ', 1)
                    cmd = parts[0].upper()
                    args = parts[1] if len(parts) > 1 else ""
                    
                    if cmd == "USER":
                        username = args
                        client.send(b"331 User name okay, need password.\r\n")
                        
                    elif cmd == "PASS":
                        password = args
                        # Log login attempt
                        self.logger.log_event(
                            service="ftp",
                            src_ip=addr[0],
                            src_port=addr[1],
                            data={"username": username, "password": password, "login_attempt": True}
                        )
                        
                        # Always reject authentication but simulate different responses
                        if username and password:
                            # Simulate failed login for honeypot
                            client.send(b"530 Login incorrect.\r\n")
                        else:
                            client.send(b"530 Login incorrect.\r\n")
                            
                    elif cmd == "SYST":
                        client.send(b"215 UNIX Type: L8\r\n")
                        
                    elif cmd == "PWD" or cmd == "XPWD":
                        client.send(f'257 "{current_dir}" is current directory.\r\n'.encode())
                        
                    elif cmd == "CWD" or cmd == "XCWD":
                        # Simulate directory change
                        if args:
                            if args == "..":
                                if current_dir != "/":
                                    current_dir = "/" + "/".join(current_dir.strip("/").split("/")[:-1])
                                    if current_dir != "/":
                                        current_dir = current_dir.strip("/")
                            else:
                                current_dir = f"{current_dir.rstrip('/')}/{args.lstrip('/')}"
                        client.send(b"250 Directory successfully changed.\r\n")
                        
                    elif cmd == "LIST" or cmd == "NLST":
                        # Simulate file listing
                        client.send(b"150 Here comes the directory listing.\r\n")
                        # Simulate some fake files
                        fake_listing = [
                            "drwxr-xr-x 2 ftp ftp 4096 Jan 01 12:00 documents",
                            "drwxr-xr-x 2 ftp ftp 4096 Jan 01 12:00 uploads", 
                            "-rw-r--r-- 1 ftp ftp 1024 Jan 01 12:00 readme.txt",
                            "-rw-r--r-- 1 ftp ftp 2048 Jan 01 12:00 config.ini"
                        ]
                        for line in fake_listing:
                            client.send(f"{line}\r\n".encode())
                        client.send(b"226 Directory send OK.\r\n")
                        
                    elif cmd == "TYPE":
                        client.send(b"200 Switching to Binary mode.\r\n")
                        
                    elif cmd == "PASV":
                        # Simulate passive mode response (won't actually work)
                        client.send(b"227 Entering Passive Mode (127,0,0,1,200,10).\r\n")
                        
                    elif cmd == "PORT":
                        client.send(b"200 PORT command successful.\r\n")
                        
                    elif cmd == "RETR":
                        # Simulate file download attempt
                        client.send(b"550 Failed to open file.\r\n")
                        
                    elif cmd == "STOR":
                        # Simulate file upload attempt
                        client.send(b"550 Permission denied.\r\n")
                        
                    elif cmd == "DELE":
                        # Simulate file deletion attempt
                        client.send(b"550 Delete operation failed.\r\n")
                        
                    elif cmd == "MKD" or cmd == "XMKD":
                        # Simulate directory creation
                        client.send(b"550 Create directory operation failed.\r\n")
                        
                    elif cmd == "RMD" or cmd == "XRMD":
                        # Simulate directory removal
                        client.send(b"550 Remove directory operation failed.\r\n")
                        
                    elif cmd == "SIZE":
                        # Simulate file size request
                        client.send(b"550 Could not get file size.\r\n")
                        
                    elif cmd == "MDTM":
                        # Simulate file modification time request
                        client.send(b"550 Could not get modification time.\r\n")
                        
                    elif cmd == "NOOP":
                        client.send(b"200 NOOP ok.\r\n")
                        
                    elif cmd == "HELP":
                        help_text = "214-The following commands are recognized:\r\n" \
                                  "214 USER PASS SYST PWD CWD LIST TYPE PASV PORT RETR STOR QUIT\r\n"
                        client.send(help_text.encode())
                        
                    elif cmd == "QUIT":
                        client.send(b"221 Goodbye.\r\n")
                        break
                        
                    else:
                        # Unknown command
                        client.send(b"502 Command not implemented.\r\n")
                        
                except UnicodeDecodeError:
                    # Handle binary data or encoding issues
                    continue
                except Exception as e:
                    print(f"[!] Error processing FTP command: {e}")
                    break
                    
        except Exception as e:
            print(f"[!] Error handling FTP client {addr}: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    def start(self):
        """Start the FTP honeypot server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(100)
            print(f"[+] FTP Honeypot listening on {self.host}:{self.port}")
            
            while True:
                try:
                    client, addr = sock.accept()
                    print(f"[+] FTP connection from {addr}")
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    print(f"[!] Error accepting FTP connection: {e}")
                    continue
                    
        except Exception as e:
            print(f"[!] Error starting FTP honeypot: {e}")
        finally:
            sock.close()