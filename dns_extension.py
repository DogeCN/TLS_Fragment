from concurrent.futures import as_completed
from urllib.parse import urlparse
from initial import pool, logger
import requests
import dns.message
import dns.rdatatype
import dns.query
import base64
import time

logger = logger.getChild("dns_extension")


class Server:
    def __init__(self, url: str):
        self.url = url

    def _query(self, domain, type):
        return dns.message.make_query(domain, type)

    def query(self, domain, type) -> dns.message.Message: ...


class DohServer(Server):
    def __init__(self, url: str):
        super().__init__(url)
        self.session = requests.Session()

    def query(self, domain, type):
        wire = self._query(domain, type).to_wire()
        b64 = base64.urlsafe_b64encode(wire).decode().rstrip("=")
        resp = self.session.get(
            self.url + "?dns=" + b64,
            params={"type": type, "ct": "application/dns-message"},
            headers={"accept": "application/dns-message"},
            proxies={"https": None},
            timeout=3,
        )
        if (
            resp.status_code == 200
            and resp.headers.get("content-type") == "application/dns-message"
        ):
            return dns.message.from_wire(resp.content)
        else:
            raise Exception("DoH query failed")


class UdpServer(Server):
    def __init__(self, host: str, port: int = 53):
        super().__init__(host)
        self.port = port

    def query(self, domain, type):
        return dns.query.udp(
            self._query(domain, type), self.url, port=self.port, timeout=3
        )


class DnsResolver:
    def __init__(self, urls: list[str]):
        self.servers: list[Server] = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme == "https":
                self.servers.append(DohServer(url))
            elif parsed.scheme == "udp":
                self.servers.append(UdpServer(parsed.hostname, parsed.port or 53))

    def resolve(self, domain, type):
        logger.info(f"Resolving {domain} via DNS")

        def query_server(server: Server):
            try:
                answer = server.query(domain, type)
                result = {}
                now = time.time()
                for rrset in answer.answer:
                    name = rrset.name.to_text().rstrip(".")
                    expires = now + rrset.ttl

                    if rrset.rdtype == dns.rdatatype.CNAME:
                        target = rrset[0].target.to_text().rstrip(".")
                    elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        target = [record.address for record in rrset]
                    else:
                        continue
                    result[name] = {"route": target, "expires": expires}
                if result:
                    return result
            except Exception as e:
                logger.debug(f"DNS query failed on {server.url}: {e}")
            return None

        # 并发查询所有服务器，返回最快结果
        futures = [pool.submit(query_server, server) for server in self.servers]

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    logger.info(f"DNS result: {result}")
                    for f in futures:
                        f.cancel()
                    return result
            except Exception as e:
                logger.warning(f"DNS future failed: {e}")

        raise Exception("All DNS servers failed")
