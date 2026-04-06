"""
Shodan Module — 通过 Shodan API 查询目标 IP 的开放端口、服务、CVE 漏洞信息。

使用前提：设置环境变量 SHODAN_API_KEY=<your_key>
若未设置，模块静默跳过，不影响其他侦察流程。

Shodan 免费账户限制：不支持 /shodan/host/{ip} 的历史数据，
但可以查询当前端口、服务 banner、漏洞列表。
"""

import os
import httpx


SHODAN_API_BASE = "https://api.shodan.io"


def _query_host(api_key: str, ip: str) -> dict:
    """
    查询单个 IP 的 Shodan 主机信息。
    返回原始 Shodan 数据或错误信息。
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(
                f"{SHODAN_API_BASE}/shodan/host/{ip}",
                params={"key": api_key},
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"error": f"No info available for {ip}"}
            elif resp.status_code == 401:
                return {"error": "Invalid Shodan API key"}
            else:
                return {"error": f"Shodan API error {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def _parse_host(raw: dict) -> dict:
    """
    从 Shodan 原始响应中提取关键信息。
    """
    if "error" in raw:
        return raw

    ports = sorted(raw.get("ports", []))

    # 提取服务摘要（每个端口的产品/版本）
    services = []
    for item in raw.get("data", []):
        port = item.get("port")
        transport = item.get("transport", "tcp")
        product = item.get("product", "")
        version = item.get("version", "")
        cpe = item.get("cpe", [])
        banner_snippet = (item.get("data", "") or "")[:100].strip().replace("\n", " ")

        svc: dict = {"port": port, "transport": transport}
        if product:
            svc["product"] = product
        if version:
            svc["version"] = version
        if cpe:
            svc["cpe"] = cpe
        if banner_snippet:
            svc["banner"] = banner_snippet
        services.append(svc)

    # CVE / 漏洞
    vulns = list(raw.get("vulns", {}).keys())  # ["CVE-2021-44228", ...]

    # 地理信息
    geo = {}
    for field in ("country_name", "city", "org", "isp", "asn"):
        val = raw.get(field)
        if val:
            geo[field] = val

    # 操作系统
    os_info = raw.get("os")

    # 标签（cloud, vpn, tor, etc.）
    tags = raw.get("tags", [])

    return {
        "ip": raw.get("ip_str"),
        "ports": ports,
        "services": services,
        "vulns": vulns,
        "geo": geo,
        "os": os_info,
        "tags": tags,
        "last_update": raw.get("last_update"),
    }


def run(a_records: list[str]) -> dict:
    """
    对所有 A 记录 IP 执行 Shodan 查询。

    Args:
        a_records: IP 地址列表（来自 dns_module 的 a_records）

    Returns:
        {
            "enabled": bool,           # 是否有 API key
            "api_key_set": bool,
            "results": {               # key = IP
                "1.2.3.4": { "ports": [...], "services": [...], "vulns": [...], ... }
            },
            "all_ports": [80, 443, ...],   # 所有 IP 的端口聚合
            "all_vulns": ["CVE-..."],       # 所有 CVE 聚合
        }
    """
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()

    if not api_key:
        return {
            "enabled": False,
            "api_key_set": False,
            "results": {},
            "all_ports": [],
            "all_vulns": [],
        }

    results: dict[str, dict] = {}
    for ip in a_records[:5]:  # 最多查 5 个 IP，避免超配额
        raw = _query_host(api_key, ip)
        results[ip] = _parse_host(raw)

    # 聚合端口和漏洞
    all_ports: set[int] = set()
    all_vulns: set[str] = set()
    for info in results.values():
        if "error" not in info:
            all_ports.update(info.get("ports", []))
            all_vulns.update(info.get("vulns", []))

    return {
        "enabled": True,
        "api_key_set": True,
        "results": results,
        "all_ports": sorted(all_ports),
        "all_vulns": sorted(all_vulns),
    }
