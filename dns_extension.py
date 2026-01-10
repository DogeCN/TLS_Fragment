import requests
import dns.message
import dns.rdatatype
import dns.query
from urllib.parse import urlparse
import base64
import time
import threading
import concurrent.futures
from log import logger

logger = logger.getChild("dns_extension")


class MyDoh:
    def __init__(self, proxy, urls):
        self.servers = []
        self.current_index = 0
        self.lock = threading.Lock()

        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme == "https":
                server = {
                    "mode": "doh",
                    "url": url,
                    "req": requests.Session(),
                    "proxy": {"https": proxy},
                    "latency": float("inf"),
                }
            elif parsed.scheme == "udp":
                server = {
                    "mode": "udp",
                    "host": parsed.hostname,
                    "port": parsed.port or 53,
                    "req": None,
                    "proxy": None,
                    "latency": float("inf"),
                }
            else:
                continue
            self.servers.append(server)

    def _test_server_latency(self, server):
        """测试单个服务器延迟"""
        try:
            start_time = time.time()
            query_message = dns.message.make_query("google.com", "A")

            if server["mode"] == "doh":
                query_wire = query_message.to_wire()
                query_base64 = base64.urlsafe_b64encode(query_wire).decode().rstrip("=")
                query_url = server["url"] + query_base64

                response = server["req"].get(
                    query_url,
                    params={"type": "A", "ct": "application/dns-message"},
                    headers={"accept": "application/dns-message"},
                    proxies=server["proxy"],
                    timeout=3,
                )
                if response.status_code == 200:
                    server["latency"] = time.time() - start_time
                    return True
            else:  # udp
                dns.query.udp(
                    query_message, server["host"], port=server["port"], timeout=3
                )
                server["latency"] = time.time() - start_time
                return True
        except Exception:
            server["latency"] = float("inf")
        return False

    def optimize_servers(self):
        """优选DNS服务器"""
        logger.info("Optimizing DNS servers...")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(self.servers)
        ) as executor:
            futures = [
                executor.submit(self._test_server_latency, server)
                for server in self.servers
            ]
            concurrent.futures.wait(futures)

        # 按延迟排序
        self.servers.sort(key=lambda x: x["latency"])
        logger.info(
            f"DNS servers optimized. Best latency: {self.servers[0]['latency']:.3f}s"
        )

    def _get_next_server(self):
        """轮询获取下一个服务器"""
        with self.lock:
            server = self.servers[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.servers)
            return server

    def resolve(self, server_name, dns_type):
        logger.info(f"Online DNS Query {server_name} via multiple servers")

        # 尝试所有服务器
        for _ in range(len(self.servers)):
            server = self._get_next_server()
            try:
                query_message = dns.message.make_query(server_name, dns_type)

                if server["mode"] == "doh":
                    query_wire = query_message.to_wire()
                    query_base64 = (
                        base64.urlsafe_b64encode(query_wire).decode().rstrip("=")
                    )
                    query_url = server["url"] + query_base64

                    ans = server["req"].get(
                        query_url,
                        params={"type": dns_type, "ct": "application/dns-message"},
                        headers={"accept": "application/dns-message"},
                        proxies=server["proxy"],
                        timeout=5,
                    )

                    if (
                        ans.status_code == 200
                        and ans.headers.get("content-type") == "application/dns-message"
                    ):
                        answer_msg = dns.message.from_wire(ans.content)
                    else:
                        continue

                else:  # udp
                    answer_msg = dns.query.udp(
                        query_message, server["host"], port=server["port"], timeout=5
                    )

                result, current_time = {}, time.time()

                for rrset in answer_msg.answer:
                    domain = rrset.name.to_text()
                    if domain[-1] == ".":
                        domain = domain[:-1]
                    ttl = rrset.ttl
                    expires = current_time + ttl

                    if rrset.rdtype == dns.rdatatype.CNAME:
                        target = rrset[0].target.to_text()
                        if target[-1] == ".":
                            target = target[:-1]
                    elif rrset.rdtype == dns.rdatatype.A:
                        target = [record.address for record in rrset]
                    elif rrset.rdtype == dns.rdatatype.AAAA:
                        target = [record.address for record in rrset]

                    result[domain] = {"route": target, "expires": expires}

                logger.info(f"DNS query result: {result}")
                return result

            except Exception as e:
                logger.warning(
                    f"DNS query failed on server {server.get('url', server.get('host'))}: {e}"
                )
                continue

        logger.error("All DNS servers failed")
        raise Exception("DNS query failed")
