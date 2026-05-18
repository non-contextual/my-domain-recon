"""
TLS Module — 深度分析目标的 TLS/SSL 配置。

检测维度：
  - 协议版本（TLS 1.3 / 1.2 / 1.1 / 1.0）
  - 协商的加密套件及密钥强度
  - 证书有效期（临期预警）
  - 自签名检测
  - 证书颁发机构类型（免费 CA / 商业 CA / 私有 CA）
"""

import ssl
import socket
from datetime import datetime, timezone


# 已知 CA 分类（用于区分证书来源）
FREE_CAS    = ["let's encrypt", "zerossl", "buypass"]
GOV_CAS     = ["cnnic", "cfca", "gdca", "wotrus", "sheca"]  # 国内政府/机构 CA
PRIVATE_CAS = ["self-signed", "localhost"]

# TLS 版本安全等级
TLS_VERSION_RISK = {
    "TLSv1":   "critical",   # 废弃
    "TLSv1.1": "high",       # 废弃
    "TLSv1.2": "ok",
    "TLSv1.3": "best",
    "SSLv2":   "critical",
    "SSLv3":   "critical",
}

# 弱密码套件特征（CBC + 旧套件）
WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL",
    "ADH", "AECDH",  # 匿名密钥交换
    "CBC",           # 存在 BEAST/LUCKY13 风险（非必须标记，仅提示）
]


def _parse_cert_date(date_str: str) -> datetime | None:
    """解析 TLS 证书日期字符串（格式：'Jan  1 00:00:00 2026 GMT'）。"""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        try:
            return datetime.strptime(date_str.strip(), "%b  %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _classify_ca(issuer_org: str, issuer_cn: str) -> str:
    """将颁发者归类为 free / gov / commercial / self-signed。"""
    combined = (issuer_org + " " + issuer_cn).lower()
    if not combined.strip() or combined == combined and issuer_cn == issuer_org:
        return "self-signed"
    for ca in FREE_CAS:
        if ca in combined:
            return "free"
    for ca in GOV_CAS:
        if ca in combined:
            return "gov/national"
    return "commercial"


def _check_cipher_strength(cipher_name: str) -> tuple[str, str]:
    """
    评估密码套件强度。
    返回 (level, note)，level 为 "weak" | "ok" | "strong"
    """
    upper = cipher_name.upper()
    for pattern in WEAK_CIPHER_PATTERNS:
        if pattern in upper:
            if pattern == "CBC":
                return ("ok", f"CBC 模式（存在潜在侧信道风险）: {cipher_name}")
            return ("weak", f"弱密码套件: {cipher_name}")
    if "AESGCM" in upper or "CHACHA20" in upper or "AES_256" in upper or "AES_128" in upper:
        return ("strong", f"✓ AEAD 套件: {cipher_name}")
    return ("ok", f"套件: {cipher_name}")


def run(domain: str, port: int = 443) -> dict:
    """
    通过 TLS 握手分析目标的 SSL/TLS 配置。
    纯被动（仅正常握手，不发送额外探测包）。

    Returns:
        {
            "protocol":            "TLSv1.3",
            "protocol_risk":       "best" | "ok" | "high" | "critical",
            "cipher_name":         "TLS_AES_256_GCM_SHA384",
            "cipher_bits":         256,
            "cipher_strength":     "strong" | "ok" | "weak",
            "cipher_note":         str,
            "cert_subject":        "jwc.wzu.edu.cn",
            "cert_issuer_org":     "Let's Encrypt",
            "cert_issuer_cn":      "R10",
            "ca_type":             "free" | "commercial" | "gov/national" | "self-signed",
            "self_signed":         False,
            "cert_not_after":      "2026-06-01",
            "days_until_expiry":   55,
            "expiry_warning":      False,   # True if < 30 days
            "expiry_critical":     False,   # True if < 7 days or already expired
            "error":               None,
        }
    """
    result: dict = {
        "protocol":          None,
        "protocol_risk":     None,
        "cipher_name":       None,
        "cipher_bits":       None,
        "cipher_strength":   None,
        "cipher_note":       None,
        "cert_subject":      None,
        "cert_issuer_org":   None,
        "cert_issuer_cn":    None,
        "ca_type":           None,
        "self_signed":       False,
        "cert_not_after":    None,
        "days_until_expiry": None,
        "expiry_warning":    False,
        "expiry_critical":   False,
        "error":             None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # CERT_OPTIONAL：不验证合法性，但仍填充 getpeercert() 字典
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # TLS 协议版本
                proto = ssock.version() or "unknown"
                result["protocol"] = proto
                result["protocol_risk"] = TLS_VERSION_RISK.get(proto, "ok")

                # 加密套件
                cipher_info = ssock.cipher()  # (name, protocol, bits)
                if cipher_info:
                    cipher_name = cipher_info[0]
                    cipher_bits = cipher_info[2]
                    result["cipher_name"] = cipher_name
                    result["cipher_bits"] = cipher_bits
                    strength, note = _check_cipher_strength(cipher_name)
                    result["cipher_strength"] = strength
                    result["cipher_note"]     = note

                # 证书信息
                cert = ssock.getpeercert()
                if cert:
                    subject  = dict(x[0] for x in cert.get("subject", []))
                    issuer   = dict(x[0] for x in cert.get("issuer",  []))

                    result["cert_subject"]    = subject.get("commonName", "")
                    result["cert_issuer_org"] = issuer.get("organizationName", "")
                    result["cert_issuer_cn"]  = issuer.get("commonName", "")

                    # 自签名：subject == issuer
                    result["self_signed"] = (
                        subject.get("commonName") == issuer.get("commonName")
                        and not issuer.get("organizationName")
                    )

                    # CA 分类
                    result["ca_type"] = _classify_ca(
                        result["cert_issuer_org"],
                        result["cert_issuer_cn"],
                    )

                    # 证书有效期
                    not_after_str = cert.get("notAfter", "")
                    result["cert_not_after"] = not_after_str
                    expiry_dt = _parse_cert_date(not_after_str)
                    if expiry_dt:
                        now = datetime.now(timezone.utc)
                        days = (expiry_dt - now).days
                        result["days_until_expiry"] = days
                        result["expiry_warning"]  = days < 30
                        result["expiry_critical"] = days < 7

    except Exception as e:
        result["error"] = str(e)

    return result
