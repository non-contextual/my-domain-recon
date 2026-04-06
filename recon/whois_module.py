"""
WHOIS Module — 查询域名注册信息：注册人、注册商、过期时间等。
"""

import whois


def run(domain: str) -> dict:
    """
    查询 WHOIS 信息。

    返回示例：
    {
        "registrar": "Namecheap, Inc.",
        "creation_date": "2020-01-01",
        "expiration_date": "2026-01-01",
        "name_servers": ["ns1.example.com"],
        "registrant_org": "Example Corp",
        "emails": ["admin@example.com"],
        "error": None,
    }
    """
    try:
        w = whois.whois(domain)

        def normalize_date(d):
            """将日期列表或单个日期统一成字符串。"""
            if isinstance(d, list):
                d = d[0]
            if d is None:
                return None
            return str(d)[:10]  # 只保留 YYYY-MM-DD

        def normalize_list(val):
            if val is None:
                return []
            if isinstance(val, list):
                return [str(v).lower() for v in val if v]
            return [str(val).lower()]

        return {
            "registrar": w.registrar,
            "creation_date": normalize_date(w.creation_date),
            "expiration_date": normalize_date(w.expiration_date),
            "updated_date": normalize_date(w.updated_date),
            "name_servers": normalize_list(w.name_servers),
            "registrant_org": w.org,
            "emails": normalize_list(w.emails),
            "error": None,
        }
    except Exception as e:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": [],
            "registrant_org": None,
            "emails": [],
            "error": str(e),
        }
