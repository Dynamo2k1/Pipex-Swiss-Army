#!/usr/bin/env python3

import sys
import socket
import argparse
from tkinter.ttk import Style
import threading
import subprocess
import ssl
import select
import logging
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
init()
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
            description="Piper - Enhanced Network Swiss Army Knife",
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

    def create_ssl_context(self) -> ssl.SSLContext:
        # For server, we expect client auth; for client, server auth.
        purpose = ssl.Purpose.CLIENT_AUTH if self.args.listen else ssl.Purpose.SERVER_AUTH
        context = ssl.create_default_context(purpose)
        if self.args.cert and self.args.key:
            context.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        # In many pentest tools you might disable verification; here we require cert validation.
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        return context

    def client_sender(self, buffer: str):
        context = self.create_ssl_context() if self.args.ssl else None

        try:
            logger.debug(f"Attempting to connect to {self.args.target}:{self.args.port}")
            print(f"DEBUG: Attempting to connect to {self.args.target}:{self.args.port}")
            with socket.create_connection((self.args.target, self.args.port)) as sock:
                with self.SecureSocketWrapper(sock, context) as client:
                    logger.debug(f"Connected to {self.args.target}:{self.args.port}")
                    print("DEBUG: Connected.")

                    # If data was piped in, send it first.
                    if buffer:
                        logger.debug("Sending piped input.")
                        client.sendall(buffer.encode())

                        # Wait a moment and then print response.
                        response = b""
                        client.settimeout(2)
                        try:
                            while True:
                                part = client.recv(1024)
                                if not part:
                                    break
                                response += part
                        except socket.timeout:
                            pass
                        print(response.decode(), end="")

                        # For piped input, we exit after processing.
                        return

                    # Otherwise, go into interactive mode.
                    while True:
                        try:
                            cmd = input(f"{Fore.GREEN}Piper:#> {Style.RESET_ALL}")
                        except EOFError:
                            break
                        if cmd.lower().strip() == "exit":
                            client.sendall(b"exit\n")
                            break

                        client.sendall(cmd.encode() + b"\n")

                        # Gather response.
                        response = b""
                        # Use a short timeout for responses.
                        client.settimeout(1)
                        try:
                            while True:
                                part = client.recv(1024)
                                if not part:
                                    break
                                response += part
                                if len(part) < 1024:
                                    break
                        except socket.timeout:
                            pass

                        print(response.decode(), end="")

        except socket.error as e:
            logger.error(f"Socket error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
        finally:
            logger.debug("Client shutdown complete")

    def server_loop(self):
        context = self.create_ssl_context() if self.args.ssl else None
        # Bind to all interfaces if no specific target is provided.
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
            logger.error(f"Handler error: {str(e)}")
        finally:
            logger.debug(f"Closing connection from {addr}")
            client_socket.close()

    def handle_upload(self, client: socket.socket):
        try:
            # Expect the client to send the filename first.
            file_name = client.recv(1024).decode().strip()
            file_path = Path(self.args.upload) / file_name
            # Security check: prevent directory traversal.
            if '..' in str(file_path) or not file_path.parent.samefile(Path(self.args.upload)):
                raise ValueError("Invalid file path")

            with open(file_path, 'wb') as f:
                while True:
                    data = client.recv(4096)
                    if not data:
                        break
                    f.write(data)
            client.sendall(b"File upload successful")
        except Exception as e:
            client.sendall(str(e).encode())

    def handle_execute(self, client: socket.socket):
        try:
            output = subprocess.check_output(
                self.args.execute,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=self.args.timeout
            )
            client.sendall(output)
        except subprocess.SubprocessError as e:
            client.sendall(str(e).encode())

    def handle_command_shell(self, client: socket.socket):
        client.sendall(b"Piper Interactive Shell:\n")

        # Start an interactive shell (use /bin/bash or /bin/sh)
        process = subprocess.Popen(
            ["/bin/bash"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0
        )

        while True:
            # Wait for input from either the client or the shell output.
            rlist, _, _ = select.select([client, process.stdout, process.stderr], [], [])
            for sock in rlist:
                if sock == client:
                    try:
                        data = client.recv(1024).decode()
                        if not data or data.strip().lower() == "exit":
                            client.sendall(b"Exiting command shell.\n")
                            process.terminate()
                            return
                        # Write the command to the shell.
                        process.stdin.write(data)
                        process.stdin.flush()
                    except Exception as e:
                        logger.error(f"Shell input error: {str(e)}")
                        process.terminate()
                        return
                elif sock in (process.stdout, process.stderr):
                    output = sock.readline()
                    if output:
                        try:
                            client.sendall(output.encode())
                        except Exception as e:
                            logger.error(f"Shell output error: {str(e)}")
                            process.terminate()
                            return

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
