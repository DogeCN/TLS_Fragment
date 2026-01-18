from typing import Dict, Tuple, Optional, Any
from initial import (
    domain_map,
    config,
    default_policy,
    ipv4_map,
    ipv6_map,
    cache,
    ip_to_binary_prefix,
    logger,
)
from dns_extension import DnsResolver
import socket
import time
import copy
import utils

logger = logger.getChild("remote")

resolver = DnsResolver(urls=config["doh_servers"])


def match_ip(ip: str) -> Dict[str, Any]:
    map_obj = ipv6_map if ":" in ip else ipv4_map
    return copy.deepcopy(map_obj.search(ip_to_binary_prefix(ip)))


def match_domain(domain: str) -> Dict[str, Any]:
    matches = domain_map.search("^" + domain + "$")
    if matches:
        longest_match = sorted(matches, key=len, reverse=True)[0]
        return copy.deepcopy(config["domains"].get(longest_match, {}))
    return {}


def get_policy(address: str) -> Dict[str, Any]:
    return match_ip(address) if utils.is_ip_address(address) else match_domain(address)


def route(
    address: str, policy: Dict[str, Any], tmp_cache: Optional[Dict] = None
) -> Tuple[str, Dict[str, Any]]:
    if tmp_cache is None:
        tmp_cache = {}

    policy.update(get_policy(address))
    redirect = policy.get("route")

    if redirect.startswith("^"):
        stopchain = True
        redirect = redirect[1:]
    else:
        stopchain = False

    if not utils.is_ip_address(address) and redirect == address:
        policy["route"] = default_policy["route"]
        return route(address, policy, tmp_cache)

    if not utils.is_ip_address(address) and redirect.endswith(".dns.resolve"):
        # DNS resolution
        if address in cache:
            result = cache[address]["route"]
        elif address in tmp_cache:
            result = tmp_cache[address]["route"]
        else:
            # Execute DNS query
            query_type = "AAAA" if redirect == "6.dns.resolve" else "A"
            try:
                tmp_cache.update(resolver.resolve(address, query_type))
                result = tmp_cache[address]["route"]
            except:
                # Fallback query
                fallback_type = "A" if query_type == "AAAA" else "AAAA"
                tmp_cache.update(resolver.resolve(address, fallback_type))
                result = tmp_cache[address]["route"]

            # Cache result
            if result and policy.get("DNS_cache"):
                if ttl := policy.get("DNS_cache_TTL"):
                    tmp_cache[address]["expires"] = time.time() + ttl
                cache[address] = tmp_cache[address]

        if isinstance(result, list):
            result = result[0]
    else:
        if utils.is_ip_address(address) and redirect.endswith(".dns.resolve"):
            return address, policy

        try:
            ip_to_binary_prefix(redirect)
            result = utils.calc_redirect_ip(address, redirect)
        except:
            result = redirect

        if stopchain:
            return result, policy

    if result == address:
        return address, policy

    logger.info(f"route {address} to {result}")
    return route(result, policy, tmp_cache)


class Remote:
    client: socket.socket
    sni: bytes

    def __init__(self, domain: str, port: int = 443, protocol: int = 6):
        self.domain = domain
        self.protocol = protocol
        self.connected = False
        self.policy: dict[str, str | bool | int] = copy.deepcopy(default_policy)
        self.policy.setdefault("port", port)

        self.address, self.policy = route(self.domain, self.policy)
        self.port = self.policy["port"]

        logger.info("connect %s %d", self.address, self.port)

        # TTL processing
        if (
            self.policy.get("fake_ttl", "").startswith("q")
            and self.policy.get("mode") == "FAKEdesync"
        ):
            ttl = utils.get_ttl(self.address, self.port)
            if ttl == -1:
                ttl = 10
            self.policy["fake_ttl"] = utils.fake_ttl_mapping(
                self.policy["fake_ttl"], ttl
            )

        # Create socket
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        sock_type = socket.SOCK_STREAM if protocol == 6 else socket.SOCK_DGRAM
        self.sock = socket.socket(family, sock_type)

        if protocol == 6:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(config["my_socket_timeout"])

    def connect(self) -> None:
        if self.protocol == 6:
            self.sock.connect((self.address, self.port))

    def send_with_oob(self, data: bytes, oob: bytes) -> None:
        if self.protocol == 6:
            self.sock.send(data + oob, socket.MSG_OOB)
        else:
            self.sock.sendall(data)

    def send(self, data: bytes) -> None:
        if self.protocol == 6:
            self.sock.sendall(data)
        else:
            # UDP processing
            data = data[3:]
            address, port, offset = utils.parse_socks5_address_from_data(data)
            data = data[offset:]

            if config["UDPfakeDNS"] and utils.is_udp_dns_query(data):
                try:
                    response = utils.build_socks5_udp_ans(
                        address, port, utils.fake_udp_dns_query(data)
                    )
                    self.client.sendall(response)
                    return
                except Exception as e:
                    logger.warning(f"UDP DNS fake failed: {e}")

            self.sock.sendto(data, (address, port))

    def recv(self, size: int) -> bytes:
        if self.protocol == 6:
            return self.sock.recv(size)
        else:
            data, address = self.sock.recvfrom(size)
            return utils.build_socks5_udp_ans(address[0], address[1], data)

    def close(self) -> None:
        try:
            self.sock.close()
        except:
            pass
