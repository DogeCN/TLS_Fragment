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
                    client, _ = self.sock.accept()
                    client.settimeout(config["my_socket_timeout"])
                    pool.submit(self.upstream, client)
                except OSError:
                    break
        except KeyboardInterrupt:
            logger.warning("Server shutting down.")
        finally:
            self.running = False
            cache.dump()
            self.sock.close()

    def handle_client_request(self, client: socket.socket):
        try:
            initial_data = client.recv(5, socket.MSG_PEEK)
            if not initial_data:
                client.close()
                return None

            if initial_data[0] == 0x05:
                return self.handle_socks5(client)
            else:
                return self.handle_http(client)

        except Exception as e:
            logger.error(f"协议检测异常: {repr(e)}")
            client.close()
            return None

    def handle_socks5(self, client: socket.socket):
        try:
            client.recv(2)
            nmethods = client.recv(1)[0]
            client.recv(nmethods)
            client.sendall(b"\x05\x00")

            header = client.recv(3)
            while header[0] != 0x05:
                header = header[1:] + client.recv(1)

            if len(header) != 3 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _ = header

            domain, port = utils.parse_socks5_address(client)
            logger.info("%s:%d", domain, port)

            try:
                r = remote.Remote(domain, port, {1: 6, 5: 17}[cmd])
                client.sendall(
                    b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
                )
                return r
            except:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client.close()
                raise ValueError(f"Not supported socks command, {cmd}")

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {repr(e)}")
            client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            client.close()
            return None

    def handle_http(self, client: socket.socket):
        data = client.recv(16384)

        if data.startswith(b"CONNECT "):
            domain, port = self.extract_server_addr(data)
            logger.info(f"CONNECT {domain}:{port}")

            try:
                r = remote.Remote(domain, port)
                client.sendall(
                    b"HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                return r
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent : MyProxy/1.0\r\n\r\n"
                )
                client.close()
                return None

        elif data.startswith(
            (b"GET ", b"PUT ", b"DELETE ", b"POST ", b"HEAD ", b"OPTIONS ")
        ):
            response = utils.generate_302(data, "github.com")
            client.sendall(response.encode(encoding="UTF-8"))
            client.close()
            return None

        else:
            logger.info(f"未知请求: {data[:10]}")
            client.sendall(
                b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            )
            client.close()
            return None

    def upstream(self, client: socket.socket):
        backend = None
        try:
            backend = self.handle_client_request(client)
            if not backend:
                return

            time.sleep(0.1)
            data = client.recv(16384)
            if not data:
                return

            # SNI处理
            try:
                sni = utils.extract_sni(data)
                if backend.domain in ("127.0.0.114", "::114") or (
                    config["BySNIfirst"]
                    and str(sni, encoding="ASCII") != backend.domain
                ):
                    backend = remote.Remote(
                        str(sni, encoding="ASCII"),
                        backend.port,
                        backend.protocol,
                    )
            except Exception as e:
                logger.warning(f"SNI extraction failed: {e}")
                sni = None

            backend.client = client
            backend.connect()

            # 安全检查
            if backend.policy.get("safety_check") and data.startswith(
                (b"GET ", b"PUT ", b"DELETE ", b"POST ", b"HEAD ", b"OPTIONS ")
            ):
                response = utils.generate_302(data, sni or backend.domain)
                client.sendall(response.encode())
                return

            # SNI策略更新
            if sni and str(sni) != str(backend.domain):
                backend.sni = sni
                backend.policy.update(match_domain(str(sni)))

            # TLS版本检查
            if backend.policy.get("safety_check"):
                try:
                    if utils.detect_tls_version_by_keyshare(data) != 1:
                        logger.warning("Not a TLS 1.3 connection")
                        client.send(utils.generate_tls_alert(data))
                        return
                except Exception as e:
                    logger.warning(f"TLS version check failed: {e}")

            # 启动下游处理
            pool.submit(self.downstream, backend, client)

            # 发送数据
            mode = backend.policy.get("mode")
            if mode == "TLSfrag":
                fragment.send_fraggmented_tls_data(backend, data)
            elif mode == "FAKEdesync":
                fake_desync.send_data_with_fake(backend, data)
            elif mode == "DIRECT":
                backend.send(data)
            elif mode == "GFWlike":
                return

            # 继续转发数据
            while self.running:
                data = client.recv(16384)
                if data:
                    backend.send(data)
                else:
                    break

        except Exception as e:
            logger.info(f"upstream error: {repr(e)}")

    def downstream(self, backend: socket.socket, client: socket.socket):
        try:
            while self.running:
                data = backend.recv(16384)
                if data:
                    client.sendall(data)
                else:
                    break
        except Exception as e:
            logger.info(f"downstream error: {repr(e)}")

    def extract_server_addr(self, data):
        addr = str(data).split()[1]
        if addr.startswith("["):
            host, port = addr[1:].split("]:")
        elif addr.count(":") == 1:
            host, port = addr.split(":")
        else:
            host, port = addr.rsplit(":", 1)
        return (host, int(port))


def start_server():
    logger.info(f"Now listening at: 127.0.0.1:{config['port']}")
    server = Server("", config["port"])
    server.listen()


if __name__ == "__main__":
    start_server()
