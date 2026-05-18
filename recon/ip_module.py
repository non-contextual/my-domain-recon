"""
IP Module — IP 归属地/ASN 情报 + 逆向 DNS + IPv6 内网 IP 泄漏检测。

数据来源：
  - ip-api.com（免费，无需 API key，45 req/min）
  - Python dns.resolver（逆向 DNS）

IPv6 内网泄漏检测：
  部分服务器通过 IPv6 地址中嵌入内网 IP（EUI-64 或手动配置），
  如 2001:x:y:z:c0a8:xx:: 中 c0a8 = 192.168，泄漏了内网网段信息。
"""

import struct
import socket
import httpx
import dns.resolver
import dns.reversename


# 私有 IP 段（RFC 1918）
PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8  (loopback)
]


def _is_private_ip(ip_int: int) -> bool:
    """判断一个 32 位整数表示的 IP 是否属于私有地址段。"""
    for base, mask in PRIVATE_RANGES:
        if (ip_int & mask) == base:
            return True
    return False


def detect_ipv6_private_leak(ipv6_addresses: list[str]) -> list[dict]:
    """
    检测 IPv6 地址中嵌入的私有 IPv4 地址。

    常见场景：
    - IPv4-mapped IPv6: ::ffff:192.168.1.1
    - 手动配置，将内网 IP 的 hex 编码嵌入 IPv6 前缀：
      2001:250:640b:6666:c0a8:302e:: → 192.168.48.46

    返回发现的泄漏列表。
    """
    leaks = []
    for addr in ipv6_addresses:
        addr = addr.strip()
        # 方法一：IPv4-mapped IPv6 (::ffff:x.x.x.x)
        if addr.lower().startswith("::ffff:"):
            ipv4_part = addr[7:]
            try:
                packed = socket.inet_aton(ipv4_part)
                ip_int = struct.unpack(">I", packed)[0]
                if _is_private_ip(ip_int):
                    leaks.append({
                        "ipv6":               addr,
                        "embedded_private_ip": ipv4_part,
                        "method":             "IPv4-mapped",
                        "note": f"IPv4-mapped IPv6 包含私有 IP {ipv4_part}，通常不应出现在公网响应中",
                    })
            except Exception:
                pass
            continue

        # 方法二：扫描 IPv6 地址中所有连续的 4 字节十六进制组合
        # 将地址展开为完整 128-bit，逐 4 字节滑窗检测
        try:
            packed128 = socket.inet_pton(socket.AF_INET6, addr)
        except Exception:
            continue

        # 滑窗：每次取连续 4 字节
        for offset in range(len(packed128) - 3):
            chunk = packed128[offset : offset + 4]
            ip_int = struct.unpack(">I", chunk)[0]
            if _is_private_ip(ip_int):
                embedded = socket.inet_ntoa(chunk)
                # 排除全零地址
                if embedded not in ("0.0.0.0", "127.0.0.1"):
                    leaks.append({
                        "ipv6":               addr,
                        "embedded_private_ip": embedded,
                        "method":             "embedded-bytes",
                        "note": (
                            f"IPv6 地址 {addr} 中偏移 {offset} 处嵌入私有 IP {embedded}，"
                            "可能泄漏内网拓扑信息"
                        ),
                    })
                    break  # 每个 IPv6 地址只报告一次

    return leaks


def _reverse_dns(ip: str) -> str | None:
    """逆向 DNS 查询（PTR 记录）。"""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR", lifetime=4)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def _lookup_ip(ip: str) -> dict:
    """
    通过 ipapi.co 查询 IP 归属地和 ASN 信息（HTTPS，免费，无需 API key）。
    备用：ip-api.com（HTTP）。
    """
    # 主：ipapi.co (HTTPS)
    try:
        with httpx.Client(
            timeout=8.0, follow_redirects=True,
            headers={"User-Agent": "osint-recon/1.0"},
        ) as client:
            resp = client.get(f"https://ipapi.co/{ip}/json/")
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("error"):
                    return {
                        "country":    data.get("country_name"),
                        "region":     data.get("region"),
                        "city":       data.get("city"),
                        "isp":        data.get("org"),        # ipapi.co 用 org 代替 isp
                        "org":        data.get("org"),
                        "asn":        data.get("asn"),        # "AS4134"
                        "asname":     data.get("org"),
                        "is_hosting": False,
                        "is_proxy":   False,
                        "is_mobile":  False,
                        "error":      None,
                    }
    except Exception:
        pass

    # 备用：ip-api.com (HTTP)
    fields = "status,country,regionName,city,isp,org,as,asname,hosting,proxy,mobile"
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            resp = client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "country":    data.get("country"),
                        "region":     data.get("regionName"),
                        "city":       data.get("city"),
                        "isp":        data.get("isp"),
                        "org":        data.get("org"),
                        "asn":        data.get("as"),
                        "asname":     data.get("asname"),
                        "is_hosting": data.get("hosting", False),
                        "is_proxy":   data.get("proxy", False),
                        "is_mobile":  data.get("mobile", False),
                        "error":      None,
                    }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "所有 IP 情报源均不可达"}


def run(a_records: list[str], aaaa_records: list[str] | None = None) -> dict:
    """
    执行 IP 情报分析。

    Args:
        a_records:    IPv4 地址列表（来自 dns_module）
        aaaa_records: IPv6 地址列表（来自 dns_module），用于内网泄漏检测

    Returns:
        {
            "ips": {
                "218.75.16.101": {
                    "country": "China", "region": "Zhejiang", "city": "Wenzhou",
                    "isp": "ChinaNet", "asn": "AS4134 ...",
                    "reverse_dns": "101.16.75.218.in-addr.arpa",
                    "is_hosting": True, ...
                }
            },
            "ipv6_leaks": [
                {
                    "ipv6": "2001:...:c0a8:302e::",
                    "embedded_private_ip": "192.168.48.46",
                    "note": "..."
                }
            ],
            "error": None,
        }
    """
    ips_result: dict = {}
    error: str | None = None

    # IPv4 情报查询
    for ip in a_records:
        info = _lookup_ip(ip)
        info["reverse_dns"] = _reverse_dns(ip)
        ips_result[ip] = info

    # IPv6 内网泄漏检测
    ipv6_leaks = detect_ipv6_private_leak(aaaa_records or [])

    return {
        "ips":        ips_result,
        "ipv6_leaks": ipv6_leaks,
        "error":      error,
    }
