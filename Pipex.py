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

# Initialize colorama
init()

# Configure logger
logger = logging.getLogger("pipex")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class Pipex:
    def __init__(self):
        self.args = self.parse_args()
        self.configure_logging()
        self.validate_args()

    class SecureSocketWrapper:
        def __init__(
            self,
            sock: socket.socket,
            ssl_context: Optional[ssl.SSLContext] = None,
            server_side: bool = False,
        ):
            self.sock = sock
            self.ssl_context = ssl_context
            self.server_side = server_side

        def __enter__(self):
            if self.ssl_context:
                self.sock = self.ssl_context.wrap_socket(
                    self.sock, server_side=self.server_side, suppress_ragged_eofs=True
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
        parser.add_argument(
            '-u',
            '--upload',
            help='Upload a file (client) or specify upload directory (server)',
        )
        parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS')
        parser.add_argument('--cert', help='Path to SSL certificate (.crt)')
        parser.add_argument('--key', help='Path to SSL private key (.key)')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
        parser.add_argument(
            '--timeout',
            type=float,
            default=5.0,
            help='Timeout for socket operations (seconds)',
        )
        return parser.parse_args()

    def validate_args(self):
        # If SSL is requested, both cert and key must be provided and exist
        if self.args.ssl:
            if not (self.args.cert and self.args.key):
                logger.error("SSL requires both certificate and private key")
                sys.exit(1)
            if not Path(self.args.cert).is_file() or not Path(self.args.key).is_file():
                logger.error("SSL certificate or key file not found")
                sys.exit(1)

        # Cannot use execute and command simultaneously in listen mode
        if self.args.listen and self.args.execute and self.args.command:
            logger.error("Cannot use both --execute and --command simultaneously")
            sys.exit(1)

        # If not listening, target must be specified
        if not self.args.listen and not self.args.target:
            logger.error("Target IP must be specified in client mode")
            sys.exit(1)

    def configure_logging(self):
        if self.args.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

    def create_ssl_context(self) -> ssl.SSLContext:
        purpose = ssl.Purpose.CLIENT_AUTH if self.args.listen else ssl.Purpose.SERVER_AUTH
        context = ssl.create_default_context(purpose)
        if self.args.cert and self.args.key:
            context.load_cert_chain(certfile=self.args.cert, keyfile=self.args.key)
        # Disable hostname checking and certificate verification for both ends
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
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
                        # 1) If the upload path is a local file, read & send it automatically
                        if os.path.isfile(self.args.upload):
                            local_path = self.args.upload
                            remote_filename = Path(local_path).name.encode()
                            with open(local_path, "rb") as f:
                                filebytes = f.read()
                            # Send "<filename>\n<filebytes>"
                            client.sendall(remote_filename + b"\n" + filebytes)
                            # Read single response from server
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

                        # 2) If piped data exists, treat first line as filename, rest as file data
                        elif buffer:
                            lines_buf = buffer.splitlines()
                            if lines_buf:
                                filename = lines_buf[0].strip()
                                filedata = "\n".join(lines_buf[1:]) if len(lines_buf) > 1 else ""
                                client.sendall((filename + "\n").encode())
                                if filedata:
                                    client.sendall(filedata.encode())
                                # Read response
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

                        # 3) No local file or piped input: prompt interactively
                        else:
                            filename = input("Enter new filename to upload: ").strip()
                            client.sendall((filename + "\n").encode())
                            print("Enter file content (end with EOF/Ctrl+D):")
                            filedata = sys.stdin.read()
                            client.sendall(filedata.encode())
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
        bind_ip = "0.0.0.0" if not self.args.target else self.args.target

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((bind_ip, self.args.port))
            server.listen(5)
            logger.info(f"Listening on {bind_ip}:{self.args.port}")

            while True:
                try:
                    client_socket, addr = server.accept()
                    logger.info(f"Accepted connection from {addr}")
                    handler_thread = threading.Thread(
                        target=self.client_handler, args=(client_socket,)
                    )
                    handler_thread.daemon = True
                    handler_thread.start()
                except Exception as e:
                    logger.error(f"Server error: {str(e)}")
                    break

    def client_handler(self, client_socket: socket.socket):
        context = self.create_ssl_context() if self.args.ssl else None
        if context:
            try:
                client_socket = context.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                logger.error(f"SSL handshake failed: {str(e)}")
                client_socket.close()
                return

        try:
            # If upload flag is set, handle file upload
            if self.args.upload:
                self.handle_upload(client_socket)
                return

            # If execute flag is set, run a single command
            if self.args.execute:
                self.handle_execute(client_socket, self.args.execute)
                return

            # If command flag is set, start interactive shell
            if self.args.command:
                self.handle_command_shell(client_socket)
                return

            # Otherwise, if any data is piped to listener, echo it back
            buffer = client_socket.recv(4096).decode()
            if buffer:
                client_socket.send(buffer.encode())
        except Exception as e:
            logger.error(f"Handler error: {str(e)}")
        finally:
            client_socket.close()

    def handle_upload(self, client: socket.socket):
        # Read incoming data until timeout or zero-length read
        data = b""
        while True:
            try:
                r, _, _ = select.select([client], [], [], 2)
                if r:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                else:
                    break
            except Exception:
                break

        if not data:
            client.sendall(b"ERROR: No data received.\n")
            return

        parts = data.split(b"\n", 1)
        if len(parts) < 2 or not parts[0]:
            client.sendall(b"ERROR: Filename missing.\n")
            return
        filename = parts[0].decode().strip()
        file_bytes = parts[1]

        remote_dir = Path(self.args.upload)
        try:
            if not remote_dir.exists():
                remote_dir.mkdir(parents=True, exist_ok=True)
            target_path = (remote_dir / filename).resolve()
            if not str(target_path).startswith(str(remote_dir.resolve())):
                raise ValueError("Invalid file path.")
            with open(target_path, "wb") as f:
                f.write(file_bytes)
            client.sendall(f"Upload of '{filename}' successful.\n".encode())
            logger.info(f"Saved upload to {target_path}")
        except Exception as e:
            client.sendall(f"ERROR: {str(e)}\n".encode())

    def handle_execute(self, client: socket.socket, command: str):
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate(timeout=30)
            output = stdout + stderr
            client.sendall(output)
        except Exception as e:
            client.sendall(f"ERROR: {str(e)}\n".encode())

    def handle_command_shell(self, client: socket.socket):
        client.sendall(b"*** Pipex Interactive Shell ***\n")
        shell = subprocess.Popen(
            ["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        def read_from_process(pipe):
            while True:
                data = pipe.readline()
                if not data:
                    break
                try:
                    client.sendall(data)
                except Exception:
                    break

        stdout_thread = threading.Thread(
            target=read_from_process, args=(shell.stdout,)
        )
        stderr_thread = threading.Thread(
            target=read_from_process, args=(shell.stderr,)
        )
        stdout_thread.daemon = True
        stderr_thread.daemon = True
        stdout_thread.start()
        stderr_thread.start()

        while True:
            try:
                cmd = client.recv(4096).decode().strip()
                if not cmd or cmd.lower() == "exit":
                    shell.kill()
                    break
                shell.stdin.write((cmd + "\n").encode())
                shell.stdin.flush()
            except Exception:
                break

        shell.terminate()
        client.close()

    def run(self):
        if self.args.listen:
            self.server_loop()
        else:
            # Read any piped data from stdin
            buffer = ""
            if not sys.stdin.isatty():
                buffer = sys.stdin.read()
            self.client_sender(buffer)


if __name__ == "__main__":
    try:
        Pipex().run()
    except KeyboardInterrupt:
        logger.info("\nExiting...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)
