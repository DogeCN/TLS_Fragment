from log import logger
import remote, fake_desync, fragment, utils
import socket, threading, time
from config import config
from remote import match_domain
import json
from pathlib import Path

# 直连缓存
direct_cache = set()
cache_file = Path("direct_cache.json")

def load_direct_cache():
    global direct_cache
    try:
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                data = json.load(f)
                direct_cache = set(data.get('domains', []))
    except:
        direct_cache = set()

def save_direct_cache():
    try:
        with open(cache_file, 'w') as f:
            json.dump({'domains': list(direct_cache)}, f)
    except:
        pass

def add_direct_domain(domain):
    direct_cache.add(domain)
    save_direct_cache()

def is_direct_cached(domain):
    return domain in direct_cache

ThreadtoWork = False
proxy_thread = None


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self, block=True):
        global ThreadtoWork, proxy_thread
        self.sock.listen(128)

        proxy_thread = threading.Thread(target=self.accept_connections, args=())
        proxy_thread.start()
        if block:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.warning("Server shutting down.")
            finally:
                ThreadtoWork = False
                self.sock.close()
        else:
            return self

    def accept_connections(self):
        global ThreadtoWork
        while ThreadtoWork:
            try:
                client_sock, _ = self.sock.accept()
                client_sock.settimeout(config["my_socket_timeout"])

                time.sleep(0.01)
                thread_up = threading.Thread(
                    target=self.my_upstream, args=(client_sock,)
                )
                thread_up.daemon = True
                thread_up.start()
            except OSError as e:
                if ThreadtoWork:
                    logger.warning(f"Accept error: {repr(e)}")
                break
            except Exception as e:
                if ThreadtoWork:
                    logger.warning(f"Server error: {repr(e)}")
                break
        
        try:
            self.sock.close()
        except:
            pass

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
                logger.debug("right 1, %s", str(header))
                header = header[1:] + client_socket.recv(1)
            logger.debug("socks5 header: %s", header)
            if len(header) != 3 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _ = header

            if cmd not in {0x01, 0x05}:
                client_socket.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                raise ValueError(f"Not supported socks command, {cmd}")

            server_name, server_port = utils.parse_socks5_address(client_socket)

            logger.info("%s:%d", server_name, server_port)

            try:
                if cmd == 0x01:
                    remote_obj = remote.Remote(server_name, server_port, 6)
                elif cmd == 0x05:
                    remote_obj = remote.Remote(server_name, server_port, 17)

                client_socket.sendall(
                    b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                return server_name if utils.is_ip_address(server_name) else None

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {repr(e)}")
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
                return server_name if utils.is_ip_address(server_name) else None

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

    def my_upstream(self, client_sock):
        first_flag = True
        backend_sock = None
        try:
            backend_sock = self.handle_client_request(client_sock)
            if backend_sock == None:
                return

            global ThreadtoWork
            while ThreadtoWork:
                try:
                    if first_flag is True:
                        first_flag = False

                        time.sleep(0.1)
                        data = client_sock.recv(16384)
                        if not data:
                            break

                        try:
                            extractedsni = utils.extract_sni(data)
                            if (
                                backend_sock.domain == "127.0.0.114"
                                or backend_sock.domain == "::114"
                                or (
                                    config["BySNIfirst"]
                                    and str(extractedsni, encoding="ASCII")
                                    != backend_sock.domain
                                )
                            ):
                                port, protocol = backend_sock.port, backend_sock.protocol
                                logger.info(
                                    f"replace backendsock: {extractedsni} {port} {protocol}"
                                )
                                old_backend_sock = backend_sock
                                backend_sock = remote.Remote(
                                    str(extractedsni, encoding="ASCII"), port, protocol
                                )
                                if old_backend_sock:
                                    old_backend_sock.close()
                        except Exception as e:
                            logger.warning(f"SNI extraction failed: {e}")

                        backend_sock.client_sock = client_sock

                        # 检查是否为缓存的直连域名
                        if is_direct_cached(backend_sock.domain):
                            logger.info(f"Using cached direct connection for {backend_sock.domain}")
                            try:
                                direct_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                direct_sock.settimeout(10)
                                direct_sock.connect((backend_sock.domain, backend_sock.port))
                                backend_sock.sock = direct_sock
                                backend_sock.policy = {"mode": "DIRECT"}
                            except Exception:
                                logger.warning(f"Cached direct connection failed for {backend_sock.domain}, trying proxy")
                                try:
                                    backend_sock.connect()
                                except Exception:
                                    break
                        else:
                            # 先尝试代理连接
                            try:
                                backend_sock.connect()
                            except Exception as proxy_error:
                                # 代理失败，尝试直连
                                logger.info(f"Proxy failed for {backend_sock.domain}, trying direct connection")
                                try:
                                    direct_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    direct_sock.settimeout(10)
                                    direct_sock.connect((backend_sock.domain, backend_sock.port))
                                    
                                    # 直连成功，缓存域名
                                    add_direct_domain(backend_sock.domain)
                                    logger.info(f"Direct connection successful, cached {backend_sock.domain}")
                                    
                                    # 替换backend_sock为直连套接字
                                    backend_sock.sock = direct_sock
                                    backend_sock.policy = {"mode": "DIRECT"}
                                except Exception as direct_error:
                                    logger.error(f"Both proxy and direct failed for {backend_sock.domain}")
                                    break

                        if backend_sock.policy.get(
                            "safety_check"
                        ) is True and data.startswith(
                            (b"GET ", b"PUT ", b"DELETE ", b"POST ", b"HEAD ", b"OPTIONS ")
                        ):
                            logger.warning("HTTP protocol detected, will redirect to https")
                            response = utils.generate_302(data, extractedsni)
                            client_sock.sendall(response.encode())
                            break

                        try:
                            backend_sock.sni = extractedsni
                            if str(backend_sock.sni) != str(backend_sock.domain):
                                backend_sock.policy = {
                                    **backend_sock.policy,
                                    **match_domain(str(backend_sock.sni)),
                                }
                        except Exception as e:
                            logger.warning(f"SNI processing failed: {e}")

                        if backend_sock.policy.get("safety_check") is True:
                            try:
                                can_pass = utils.detect_tls_version_by_keyshare(data)
                                if can_pass != 1:
                                    logger.warning(
                                        "Not a TLS 1.3 connection and will close"
                                    )
                                    try:
                                        client_sock.send(utils.generate_tls_alert(data))
                                    except:
                                        pass
                                    break
                            except Exception as e:
                                logger.warning(f"TLS version check failed: {e}")

                        if data:
                            thread_down = threading.Thread(
                                target=self.my_downstream,
                                args=(backend_sock, client_sock),
                            )
                            thread_down.daemon = True
                            thread_down.start()

                            mode = backend_sock.policy.get("mode")
                            if mode == "TLSfrag":
                                fragment.send_fraggmed_tls_data(backend_sock, data)
                            elif mode == "FAKEdesync":
                                fake_desync.send_data_with_fake(backend_sock, data)
                            elif mode == "DIRECT":
                                backend_sock.send(data)
                            elif mode == "GFWlike":
                                break

                    else:
                        data = client_sock.recv(16384)
                        if data:
                            backend_sock.send(data)
                        else:
                            break

                except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                    if e.errno in (10038, 10053, 10054):
                        logger.debug(f"Connection closed: {e}")
                    else:
                        logger.info(f"upstream : {repr(e)} from {backend_sock.domain if backend_sock else 'unknown'}")
                    break
                except Exception as e:
                    logger.info(f"upstream : {repr(e)} from {backend_sock.domain if backend_sock else 'unknown'}")
                    break

        finally:
            try:
                if client_sock:
                    client_sock.close()
            except:
                pass
            try:
                if backend_sock:
                    backend_sock.close()
            except:
                pass

    def my_downstream(self, backend_sock: remote.Remote, client_sock: socket.socket):
        try:
            global ThreadtoWork
            while ThreadtoWork:
                try:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                    else:
                        break
                except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                    if e.errno in (10038, 10053, 10054):
                        logger.debug(f"Connection closed: {e}")
                    else:
                        logger.info(f"downstream : {repr(e)} from {backend_sock.domain}")
                    break
                except Exception as e:
                    logger.info(f"downstream : {repr(e)} from {backend_sock.domain}")
                    break
        finally:
            try:
                if client_sock:
                    client_sock.close()
            except:
                pass
            try:
                if backend_sock:
                    backend_sock.close()
            except:
                pass

    def _is_proxy_domain(self, domain):
        return False

    def extract_servername_and_port(self, data):
        host_and_port = str(data).split()[1]
        try:
            host, port = host_and_port.split(":")
        except:
            if host_and_port.find("[") != -1:
                host, port = host_and_port.split("]:")
                host = host[1:]
            else:
                idx = 0
                for _ in range(6):
                    idx = host_and_port.find(":", idx + 1)
                host = host_and_port[:idx]
                port = host_and_port[idx + 1 :]
        return (host, int(port))


serverHandle = None


def start_server(block=True):
    load_direct_cache()
    global serverHandle
    logger.info(f"Now listening at: 127.0.0.1:{config['port']}")
    serverHandle = ThreadedServer("", config["port"]).listen(block)


def stop_server(wait_for_stop=True):
    global ThreadtoWork, proxy_thread
    ThreadtoWork = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", config["port"]))
    sock.close()
    if wait_for_stop:
        while proxy_thread.is_alive():
            pass
        logger.info("Server stopped")


ThreadtoWork = True

if __name__ == "__main__":
    start_server()
