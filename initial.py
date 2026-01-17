from concurrent.futures import ThreadPoolExecutor
import ahocorasick
import json
import ipaddress
import random
import logging


def expand_pattern(s):
    left, right = s.find("("), s.find(")")
    if left == -1 and right == -1:
        return s.split("|")
    if -1 in (left, right) or left > right or right == left + 1:
        raise ValueError(f"Invalid pattern: {s}")

    prefix = s[:left]
    suffix = s[right + 1 :]
    inner = s[left + 1 : right]
    return [prefix + part + suffix for part in inner.split("|")]


def expand_policies(policies):
    expanded = {}
    for key, value in policies.items():
        for item in key.replace(" ", "").split(","):
            for pattern in expand_pattern(item):
                expanded[pattern] = value
    return expanded


def ip_to_binary_prefix(ip_or_network):
    try:
        network = ipaddress.ip_network(ip_or_network, strict=False)
        bits = 32 if network.version == 4 else 128
        return bin(int(network.network_address))[2:].zfill(bits)[: network.prefixlen]
    except ValueError:
        ip = ipaddress.ip_address(ip_or_network)
        bits = 32 if ip.version == 4 else 128
        return bin(int(ip))[2:].zfill(bits)


class Trie:
    def __init__(self):
        self.root = {"children": [None, None], "val": None}

    def insert(self, prefix, value):
        node = self.root
        for bit in prefix:
            idx = int(bit)
            if not node["children"][idx]:
                node["children"][idx] = {"children": [None, None], "val": None}
            node = node["children"][idx]
        node["val"] = value

    def search(self, prefix):
        node = self.root
        result = {}
        for bit in prefix:
            idx = int(bit)
            if node["val"]:
                result = node["val"]
            if not node["children"][idx]:
                return result
            node = node["children"][idx]
        return node["val"] or result


class Cache(dict):
    def __init__(self, file: str, buffer_size: int):
        super().__init__()
        self.file = file
        self.buffer_size = buffer_size
        self.counter = 0

    def load(self):
        if self.file:
            try:
                with open(self.file, "r") as f:
                    self.update(json.load(f))
            except FileNotFoundError:
                pass

    def dump(self):
        if self.file:
            with open(self.file, "w") as f:
                json.dump(self, f)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.counter += 1
        if self.counter >= self.buffer_size:
            self.counter = 0
            self._cleanup_expired()
            self.dump()

    def _cleanup_expired(self):
        import time

        expired_keys = [k for k, v in self.items() if v.get("expires", 0) < time.time()]
        for key in expired_keys:
            del self[key]


# 加载配置
with open("config.json", "r") as f:
    config: dict = json.load(f)

# 创建全局线程池
pool = ThreadPoolExecutor(max_workers=config.get("max_workers", 100))

# 配置日志
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filemode="w",
    encoding="utf-8",
    filename=config.get("logfile"),
)

logger = logging.getLogger("tls_fragmenter")
logger.setLevel(config["loglevel"])

# 处理默认策略
default_policy = config["default_policy"]
default_policy["fake_packet"] = default_policy["fake_packet"].encode()

if default_policy["fake_ttl"] == "auto":
    default_policy["fake_ttl"] = random.randint(10, 60)

# 展开策略
config["domains"] = expand_policies(config["domains"])
config["IPs"] = expand_policies(config["IPs"])

# 创建索引
domain_map = ahocorasick.AhoCorasick(*config["domains"].keys())
ipv4_map = Trie()
ipv6_map = Trie()

for ip, policy in config["IPs"].items():
    trie = ipv6_map if ":" in ip else ipv4_map
    trie.insert(ip_to_binary_prefix(ip), policy)

# DNS缓存
cache = Cache("cache.json", config.get("DNS_cache_update_interval", 10))
cache.load()
