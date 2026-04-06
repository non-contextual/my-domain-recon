"""
Cert Module — 通过以下两种方式获取域名证书信息：
1. crt.sh 证书透明度日志（发现历史证书和子域名）
2. 直接连接目标，从 TLS 握手中提取当前证书的 SAN

两者都无需 API Key。
"""

import ssl
import socket
import httpx


CRT_SH_API = "https://crt.sh/?q={domain}&output=json"


def fetch_crtsh(domain: str, timeout: float = 12.0) -> list[dict]:
    """从 crt.sh 拉取证书透明度记录（%.domain.com 通配查询）。
    使用 trust_env=False 跳过本地代理，直接访问外网（避免代理超时/截断）。
    """
    query = f"%.{domain}"
    url = CRT_SH_API.format(domain=query)
    for trust in (True, False):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, trust_env=trust) as client:
                resp = client.get(url, headers={"Accept": "application/json"})
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        return data
        except Exception:
            pass
    return []


def fetch_tls_sans(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    直接连接目标，从 TLS 握手中提取当前证书的信息。

    返回：
    {
        "subject": "CN=example.com",
        "issuer": "Let's Encrypt",
        "sans": ["example.com", "www.example.com"],
        "not_after": "2025-01-01 00:00:00",
    }
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # 提取 Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")

        # 提取 Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_cn = issuer.get("organizationName", issuer.get("commonName", ""))

        # 提取 SAN
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                sans.append(san_value.lower())

        return {
            "subject": cn,
            "issuer": issuer_cn,
            "sans": sans,
            "not_after": cert.get("notAfter", ""),
            "error": None,
        }
    except Exception as e:
        return {"subject": "", "issuer": "", "sans": [], "not_after": "", "error": str(e)}


def extract_domains(records: list[dict]) -> dict:
    """从 crt.sh 记录中提取所有唯一域名/SAN。"""
    subdomains: set[str] = set()
    wildcards: set[str] = set()
    issuers: set[str] = set()

    for record in records:
        names = record.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                wildcards.add(name[2:])  # 去掉 *.
            else:
                subdomains.add(name)

        issuer = record.get("issuer_name", "")
        if issuer:
            issuers.add(issuer)

    return {
        "subdomains": sorted(subdomains),
        "wildcards": sorted(wildcards),
        "issuers": sorted(issuers),
        "total_certs": len(records),
    }


def run(domain: str) -> dict:
    """
    执行证书侦察。优先使用 crt.sh，不可用时降级为直连 TLS。

    返回：
    {
        "total_certs": 42,
        "subdomains": [...],
        "wildcards": [...],
        "issuers": [...],
        "tls_direct": { subject, issuer, sans, not_after },
        "source": "crtsh" | "tls_direct" | "both",
        "error": None,
    }
    """
    # 始终尝试获取直连 TLS 证书（速度快，且包含当前 SAN）
    tls_info = fetch_tls_sans(domain)

    # 尝试 crt.sh
    records = fetch_crtsh(domain)

    if records:
        extracted = extract_domains(records)
        # 将直连 TLS SAN 也合并进来（可能包含新增的 SAN）
        if tls_info["sans"]:
            for san in tls_info["sans"]:
                if san not in extracted["subdomains"]:
                    extracted["subdomains"].append(san)
            extracted["subdomains"] = sorted(set(extracted["subdomains"]))
        return {
            **extracted,
            "tls_direct": tls_info,
            "source": "both" if tls_info["sans"] else "crtsh",
            "error": None,
        }

    # crt.sh 不可用，降级为仅直连 TLS
    subdomains = sorted(set(tls_info["sans"])) if tls_info["sans"] else []
    return {
        "total_certs": 1 if tls_info["sans"] else 0,
        "subdomains": subdomains,
        "wildcards": [],
        "issuers": [tls_info["issuer"]] if tls_info["issuer"] else [],
        "tls_direct": tls_info,
        "source": "tls_direct",
        "error": "crt.sh unavailable, using direct TLS certificate only" if tls_info["sans"] else "Both crt.sh and TLS connection failed",
    }
