from initial import config, pool, logger, cache
import remote, fake_desync, fragment, utils
import socket, time
from remote import match_domain


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.running = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(128)
        self.running = True

        try:
            while self.running:
                try:
                    client_sock, _ = self.sock.accept()
                    client_sock.settimeout(config["my_socket_timeout"])
                    pool.submit(self.upstream, client_sock)
                except OSError:
                    if self.running:
                        break
        except KeyboardInterrupt:
            logger.warning("Server shutting down.")
        finally:
            self.running = False
            cache.dump()
            self.sock.close()

    def handle_client_request(self, client_socket):
        try:
            initial_data = client_socket.recv(5, socket.MSG_PEEK)
            if not initial_data:
                client_socket.close()
                return None

            if initial_data[0] == 0x05:
                return self._handle_socks5(client_socket)
            else:
                return self._handle_http_protocol(client_socket)

        except Exception as e:
            logger.error(f"协议检测异常: {repr(e)}")
            client_socket.close()
            return None

    def _handle_socks5(self, client_socket):
        try:
            client_socket.recv(2)
            nmethods = client_socket.recv(1)[0]
            client_socket.recv(nmethods)
            client_socket.sendall(b"\x05\x00")

            header = client_socket.recv(3)
            while header[0] != 0x05:
                header = header[1:] + client_socket.recv(1)

            if len(header) != 3 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _ = header

            if cmd not in {0x01, 0x05}:
                client_socket.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                raise ValueError(f"Not supported socks command, {cmd}")

            server_name, server_port = utils.parse_socks5_address(client_socket)
            logger.info("%s:%d", server_name, server_port)

            if cmd == 0x01:
                remote_obj = remote.Remote(server_name, server_port, 6)
            elif cmd == 0x05:
                remote_obj = remote.Remote(server_name, server_port, 17)

            client_socket.sendall(
                b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            )
            return remote_obj

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {repr(e)}")
            client_socket.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            client_socket.close()
            return None

    def _handle_http_protocol(self, client_socket):
        data = client_socket.recv(16384)

        if data.startswith(b"CONNECT "):
            server_name, server_port = self.extract_servername_and_port(data)
            logger.info(f"CONNECT {server_name}:{server_port}")

            try:
                remote_obj = remote.Remote(server_name, server_port)
                client_socket.sendall(
                    b"HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent : MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return None

        elif data.startswith(
            (b"GET ", b"PUT ", b"DELETE ", b"POST ", b"HEAD ", b"OPTIONS ")
        ):
            response = utils.generate_302(data, "github.com")
            client_socket.sendall(response.encode(encoding="UTF-8"))
            client_socket.close()
            return None

        else:
            logger.info(f"未知请求: {data[:10]}")
            client_socket.sendall(
                b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            )
            client_socket.close()
            return None

    def upstream(self, client_sock):
        backend_sock = None
        try:
            backend_sock = self.handle_client_request(client_sock)
            if not backend_sock:
                return

            time.sleep(0.1)
            data = client_sock.recv(16384)
            if not data:
                return

            # SNI处理
            try:
                sni = utils.extract_sni(data)
                if backend_sock.domain in ("127.0.0.114", "::114") or (
                    config["BySNIfirst"]
                    and str(sni, encoding="ASCII") != backend_sock.domain
                ):
                    old_backend_sock = backend_sock
                    backend_sock = remote.Remote(
                        str(sni, encoding="ASCII"),
                        backend_sock.port,
                        backend_sock.protocol,
                    )
                    old_backend_sock.close()
            except Exception as e:
                logger.warning(f"SNI extraction failed: {e}")
                sni = None

            backend_sock.client_sock = client_sock
            backend_sock.connect()

            # 安全检查
            if backend_sock.policy.get("safety_check") and data.startswith(
                (b"GET ", b"PUT ", b"DELETE ", b"POST ", b"HEAD ", b"OPTIONS ")
            ):
                response = utils.generate_302(data, sni or backend_sock.domain)
                client_sock.sendall(response.encode())
                return

            # SNI策略更新
            if sni and str(sni) != str(backend_sock.domain):
                backend_sock.sni = sni
                backend_sock.policy.update(match_domain(str(sni)))

            # TLS版本检查
            if backend_sock.policy.get("safety_check"):
                try:
                    if utils.detect_tls_version_by_keyshare(data) != 1:
                        logger.warning("Not a TLS 1.3 connection")
                        client_sock.send(utils.generate_tls_alert(data))
                        return
                except Exception as e:
                    logger.warning(f"TLS version check failed: {e}")

            # 启动下游处理
            pool.submit(self.downstream, backend_sock, client_sock)

            # 发送数据
            mode = backend_sock.policy.get("mode")
            if mode == "TLSfrag":
                fragment.send_fraggmented_tls_data(backend_sock, data)
            elif mode == "FAKEdesync":
                fake_desync.send_data_with_fake(backend_sock, data)
            elif mode == "DIRECT":
                backend_sock.send(data)
            elif mode == "GFWlike":
                return

            # 继续转发数据
            while self.running:
                data = client_sock.recv(16384)
                if data:
                    backend_sock.send(data)
                else:
                    break

        except Exception as e:
            logger.info(f"upstream error: {repr(e)}")

    def downstream(self, backend_sock, client_sock):
        try:
            while self.running:
                data = backend_sock.recv(16384)
                if data:
                    client_sock.sendall(data)
                else:
                    break
        except Exception as e:
            logger.info(f"downstream error: {repr(e)}")

    def extract_servername_and_port(self, data):
        host_and_port = str(data).split()[1]
        try:
            host, port = host_and_port.split(":")
        except:
            if "[" in host_and_port:
                host, port = host_and_port.split("]:")
                host = host[1:]
            else:
                idx = 0
                for _ in range(6):
                    idx = host_and_port.find(":", idx + 1)
                host = host_and_port[:idx]
                port = host_and_port[idx + 1 :]
        return (host, int(port))


def start_server():
    logger.info(f"Now listening at: 127.0.0.1:{config['port']}")
    server = Server("", config["port"])
    server.listen()


if __name__ == "__main__":
    start_server()
