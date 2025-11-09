# server.py
import socket, threading
from config import *
from packet import *
from datetime import datetime


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.s_sock = None
        self.clients = {}
        self.public_keys = {}
        self.lock = threading.Lock()

    def start(self):
        self.s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_sock.bind((self.host, self.port))
        self.s_sock.listen()
        self._log("Server starting...")
        self._log(f"Listening on {self.host}:{self.port}")

        try:
            while True:
                c_sock, c_addr = self.s_sock.accept()
                self._log(f"Connected from {c_addr[0]}:{c_addr[1]}")
                threading.Thread(
                    target=self._handle_client, args=(c_sock, c_addr), daemon=True
                ).start()
        except KeyboardInterrupt:
            self._log(f"Server shutting down...")
        finally:
            self.s_sock.close()

    def _handle_client(self, c_sock: socket.socket, c_addr):
        username = None
        try:
            while True:
                raw_data = c_sock.recv(BUFFER_SIZE)
                if not raw_data:
                    for other_user in self.clients:
                        # self._log(username)
                        # self._log(other_user)
                        if other_user != self.clients:
                            other_user_sock: socket.socket = self.clients.get(other_user)
                            other_user_sock.send(
                                system_response_packet(
                                    to_user=other_user,
                                    action="user_disconnected",
                                    status="ok",
                                    result={"target": username},
                                )
                            )
                    if username and username in self.clients:
                        self._remove_client(username)
                    break

                try:
                    data = parse_packet(raw_data)
                    # print(data)
                    if data.get("action") == "register" and "from" in data:
                        username = data.get("from")

                    data_type = data.get("type")
                    if data_type == "system":
                        self._handle_system_request(c_sock, data)
                    elif data_type == "message":
                        self._handle_message_request(c_sock, data)
                except json.JSONDecodeError as e:
                    self._log(f"Invalid data from {username}: {e}")
                    continue

        except (ConnectionResetError, ConnectionAbortedError, OSError):
            self._log(f"Connection lost with {c_addr[0]}:{c_addr[1]}")
        finally:
            c_sock.close()

    def _handle_message_request(self, c_sock: socket.socket, data: dict):
        from_user, to_user, enc_message = (
            data.get("from"),
            data.get("to"),
            data.get("enc_message"),
        )
        with self.lock:
            recipient_sock: socket.socket = self.clients.get(to_user)

        if recipient_sock:
            recipient_sock.send(create_packet(data))
            self._log(f"[{from_user}] -> [{to_user}]: {enc_message}")
        else:
            error_msg = f"User '{to_user}' not found!"
            c_sock.send(
                system_response_packet(
                    to_user=from_user,
                    action="",
                    status="error",
                    result=f"Unable to send message to user '{to_user}'! {error_msg}",
                )
            )
            self._log(message=f"[Server] -> [{from_user}]: {error_msg}")

    def _handle_system_request(self, c_sock: socket.socket, data: dict):
        action = data.get("action")
        from_user = data.get("from")
        if action == "register":
            username = data.get("payload", {}).get("username")
            public_key = data.get("payload", {}).get("public_key")

            with self.lock:
                if username in self.clients:
                    # self._log(
                    #     message=f"Registration failed for '{username}': Username already taken!"
                    # )
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user,
                            action=action,
                            status="error",
                            result=f"Username already taken. Please choose another one!",
                        )
                    )
                    c_sock.close()
                else:
                    self.clients[username] = c_sock
                    self.public_keys[username] = public_key
                    self._log(
                        message=f"[+] User '{from_user}' registered and connected."
                    )
            # print(self.clients)
            # print(self.public_keys)
        elif action == "get_online_users":
            with self.lock:
                online_users = list(self.clients.keys())

            if online_users:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action=action,
                        status="ok",
                        result=online_users,
                    )
                )
            else:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action=action,
                        status="error",
                        result=f"Unable to get online user list!",
                    )
                )

            self._log(message=f"[!] User '{from_user}' requested online users.")
        elif action == "get_public_key":
            target = data.get("payload", {}).get("target")
            with self.lock:
                target_public_key = self.public_keys.get(target)

            self._log(
                message=f"[!] User '{from_user}' requested public key of user '{target}'."
            )
            if target_public_key:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action="get_public_key",
                        status="ok",
                        result={"target": target, "public_key": target_public_key},
                    )
                )
                self._log(
                    message=f"[!] Sent user '{target}' public key to user '{from_user}'."
                )
            else:
                error_msg = f"User '{target}' not found or offline!"
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action="get_public_key",
                        status="error",
                        result=f"Unable to obtain user '{target}' public key! {error_msg}",
                    )
                )
                self._log(
                    message=f"[!] Cannot sent '{target}' public key to '{from_user}'! {error_msg}"
                )

    def _remove_client(self, username: str):
        with self.lock:
            if username in self.clients:
                del self.clients[username]
            if username in self.public_keys:
                del self.public_keys[username]

        self._log(message=f"[-] User '{username}' disconnected.")

    def _log(self, message: str):
        print(f"[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}] {message}")


if __name__ == "__main__":
    server = Server(HOST, PORT)
    server.start()
