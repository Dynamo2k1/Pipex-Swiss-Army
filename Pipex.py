#!/usr/bin/env python3

import sys
import socket
import argparse
import threading
import subprocess
import ssl
import select
import logging
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init
import os

# Setup logging and colorama
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
init(autoreset=True)

class Pipex:
    def __init__(self):
        self.args = self.parse_args()
        self.configure_logging()
        self.validate_args()

    class SecureSocketWrapper:
        def __init__(self, sock: socket.socket, ssl_context: Optional[ssl.SSLContext] = None,
                     server_side: bool = False):
            self.sock = sock
            self.ssl_context = ssl_context
            self.server_side = server_side

        def __enter__(self):
            if self.ssl_context:
                self.sock = self.ssl_context.wrap_socket(
                    self.sock,
                    server_side=self.server_side,
                    suppress_ragged_eofs=True
                )
            return self.sock

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.sock.close()

    def parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="pipex - Enhanced Network Swiss Army Knife",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''Examples:
  %(prog)s -t 192.168.1.2 -p 5555 -l -c
  %(prog)s -t 192.168.1.2 -p 5555 -l -u /tmp/uploads
  %(prog)s -t 192.168.1.2 -p 5555 -l -e "cat /etc/passwd" --ssl
  echo 'ABCDEF' | %(prog)s -t 192.168.1.2 -p 5555'''
        )
        parser.add_argument('-t', '--target', help='Target host')
        parser.add_argument('-p', '--port', type=int, required=True, help='Target port')
        parser.add_argument('-l', '--listen', action='store_true', help='Listen mode')
        parser.add_argument('-e', '--execute', help='Execute command')
        parser.add_argument('-c', '--command', action='store_true', help='Command shell')
        parser.add_argument('-u', '--upload', help='Upload directory')
        parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS')
        parser.add_argument('--cert', help='SSL certificate file')
        parser.add_argument('--key', help='SSL private key file')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        parser.add_argument('-T', '--timeout', type=int, default=30, help='Connection timeout')
        return parser.parse_args()

    def configure_logging(self):
        level = logging.DEBUG if self.args.verbose else logging.INFO
        logger.setLevel(level)

    def validate_args(self):
        if not self.args.listen and not self.args.target:
            logger.error("Target host required in client mode")
            sys.exit(1)
        if self.args.ssl and (not self.args.cert or not self.args.key):
            logger.error("SSL requires both certificate and private key")
            sys.exit(1)
        if self.args.ssl:
            # Check if the cert and key files exist
            if not Path(self.args.cert).is_file() or not Path(self.args.key).is_file():
                logger.error("SSL certificate or key file not found")
                sys.exit(1)

    def create_ssl_context(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.CLIENT_AUTH if self.args.listen else ssl.Purpose.SERVER_AUTH
        context = ssl.create_default_context(purpose)
        if self.args.cert and self.args.key:
            context.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        # For demonstration, disable hostname checking on client side.
        context.verify_mode = ssl.CERT_NONE if not self.args.listen else ssl.CERT_REQUIRED
        context.check_hostname = False
        return context

    def client_sender(self, buffer: str):
        context = self.create_ssl_context() if self.args.ssl else None

        try:
            logger.debug(f"Attempting to connect to {self.args.target}:{self.args.port}")
            print(f"DEBUG: Attempting to connect to {self.args.target}:{self.args.port}")
            with socket.create_connection((self.args.target, self.args.port), timeout=self.args.timeout) as sock:
                with self.SecureSocketWrapper(sock, context) as client:
                    logger.debug(f"Connected to {self.args.target}:{self.args.port}")
                    print("DEBUG: Connected.")

                    # -- UPLOAD MODE --
                    if self.args.upload:
                        if buffer:
                            # Expect piped input: first line is filename, rest is file data.
                            lines = buffer.splitlines()
                            if lines:
                                filename = lines[0].strip()
                                filedata = "\n".join(lines[1:]) if len(lines) > 1 else ""
                                client.sendall((filename + "\n").encode())
                                if filedata:
                                    client.sendall(filedata.encode())
                        else:
                            filename = input("Enter new filename to upload: ").strip()
                            client.sendall((filename + "\n").encode())
                            print("Enter file content (end with EOF/Ctrl+D):")
                            filedata = sys.stdin.read()
                            client.sendall(filedata.encode())

                        # Read response using select
                        response = b""
                        while True:
                            r, _, _ = select.select([client], [], [], 2)
                            if r:
                                part = client.recv(4096)
                                if not part:
                                    break
                                response += part
                            else:
                                break
                        print(response.decode(), end="")
                        return

                    # -- NON-UPLOAD MODE WITH PIPED INPUT --
                    if buffer:
                        logger.debug("Sending piped input.")
                        client.sendall(buffer.encode())
                        response = b""
                        while True:
                            r, _, _ = select.select([client], [], [], 2)
                            if r:
                                part = client.recv(4096)
                                if not part:
                                    break
                                response += part
                            else:
                                break
                        print(response.decode(), end="")
                        return

                    # -- INTERACTIVE MODE --
                    # Check if any initial data (like a banner) is waiting.
                    r, _, _ = select.select([client], [], [], 0.5)
                    if r:
                        banner = client.recv(4096)
                        if banner:
                            print(banner.decode(), end="")

                    # Main interactive loop:
                    while True:
                        try:
                            cmd = input(f"{Fore.GREEN}pipex:#> {Style.RESET_ALL}")
                        except EOFError:
                            break
                        if cmd.lower().strip() == "exit":
                            client.sendall(b"exit\n")
                            break
                        client.sendall(cmd.encode() + b"\n")

                        # Read response until no more data is ready.
                        response = b""
                        while True:
                            r, _, _ = select.select([client], [], [], 2)
                            if r:
                                part = client.recv(4096)
                                if not part:
                                    break
                                response += part
                            else:
                                break
                        print(response.decode(), end="")

        except socket.error as e:
            logger.error(f"Socket error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
        finally:
            logger.debug("Client shutdown complete")

    def server_loop(self):
        context = self.create_ssl_context() if self.args.ssl else None
        bind_ip = '0.0.0.0' if not self.args.target else self.args.target
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_ip, self.args.port))
            server.listen(5)
            logger.info(f"Listening on {bind_ip}:{self.args.port}")

            while True:
                client_sock, addr = server.accept()
                logger.info(f"Accepted connection from {addr}")
                client_thread = threading.Thread(
                    target=self.client_handler,
                    args=(client_sock, addr, context),
                    daemon=True
                )
                client_thread.start()

    def client_handler(self, client_socket, addr, context):
        try:
            logger.debug(f"Handling connection from {addr}")
            with self.SecureSocketWrapper(client_socket, context, server_side=True) as client:
                # Use a timeout on the client socket as specified.
                client.settimeout(self.args.timeout)
                if self.args.upload:
                    self.handle_upload(client)
                elif self.args.execute:
                    self.handle_execute(client)
                elif self.args.command:
                    self.handle_command_shell(client)
                else:
                    logger.debug("No action specified for connection")
                    client.sendall(b"No action specified. Closing connection.\r\n")
        except Exception as e:
            logger.error(f"Handler error from {addr}: {str(e)}")
        finally:
            logger.debug(f"Closing connection from {addr}")
            client_socket.close()

    def handle_upload(self, client: socket.socket):
        try:
            client.settimeout(self.args.timeout)
            # Read filename (first line)
            file_name = client.recv(4096).decode().strip()
            if not file_name:
                raise ValueError("No filename provided")
            upload_dir = Path(self.args.upload).resolve()
            file_path = (upload_dir / file_name).resolve()
            if not str(file_path).startswith(str(upload_dir)):
                raise ValueError("Invalid file path")
            with open(file_path, 'wb') as f:
                while True:
                    try:
                        data = client.recv(4096)
                        if not data:
                            break
                        f.write(data)
                    except (socket.timeout, BlockingIOError):
                        break
            client.sendall(b"File upload successful")
        except Exception as e:
            err_msg = f"Upload error: {str(e)}"
            logger.error(err_msg)
            try:
                client.sendall(err_msg.encode())
            except Exception:
                pass

    def handle_execute(self, client: socket.socket):
        try:
            process = subprocess.Popen(
                self.args.execute, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate(timeout=self.args.timeout)
            output = stdout + stderr
            client.sendall(output.encode())
        except subprocess.SubprocessError as e:
            err_msg = f"Execution error: {str(e)}"
            logger.error(err_msg)
            client.sendall(err_msg.encode())

    def handle_command_shell(self, client: socket.socket):
        # Send an initial banner.
        client.sendall(b"pipex Interactive Shell:\n")
        process = subprocess.Popen(
            ["/bin/bash"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # line buffered
        )

        def forward_output(src):
            try:
                for line in iter(src.readline, ''):
                    if not line:
                        break
                    try:
                        client.sendall(line.encode())
                    except Exception:
                        break
            except Exception as e:
                logger.error(f"Error reading shell output: {str(e)}")

        threading.Thread(target=forward_output, args=(process.stdout,), daemon=True).start()
        threading.Thread(target=forward_output, args=(process.stderr,), daemon=True).start()

        try:
            while True:
                data = client.recv(1024).decode()
                if not data:
                    break
                if data.strip().lower() == "exit":
                    client.sendall(b"Exiting command shell.\n")
                    process.terminate()
                    break
                process.stdin.write(data + "\n")
                process.stdin.flush()
        except Exception as e:
            logger.error(f"Shell input error: {str(e)}")
            process.terminate()

    def run(self):
        if self.args.listen:
            self.server_loop()
        else:
            if sys.stdin.isatty():
                self.client_sender("")
            else:
                buffer = sys.stdin.read()
                self.client_sender(buffer)


if __name__ == '__main__':
    try:
        Pipex().run()
    except KeyboardInterrupt:
        logger.info("\nExiting...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)
