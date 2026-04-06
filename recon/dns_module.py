"""
DNS Module — 解析目标域名的所有 DNS 记录，追踪 CNAME 链，识别 CDN 归属。
"""

import dns.resolver
import dns.reversename
import dns.rdatatype


# 已知 CDN 的 CNAME 关键字映射
CDN_CNAME_SIGNATURES = {
    "fastly.net": "Fastly",
    "cloudfront.net": "AWS CloudFront",
    "cloudflare.com": "Cloudflare",
    "akamaiedge.net": "Akamai",
    "akamaitech.net": "Akamai",
    "akamai.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "azureedge.net": "Azure CDN",
    "msecnd.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "googlehosted.com": "Google",
    "googlesyndication.com": "Google",
    "ghs.google.com": "Google",
    "pages.github.io": "GitHub Pages",
    "github.io": "GitHub Pages",
    "netlify.com": "Netlify",
    "vercel-dns.com": "Vercel",
    "vercel.app": "Vercel",
    "herokudns.com": "Heroku",
    "amazonaws.com": "AWS",
    "elb.amazonaws.com": "AWS ELB",
    "r.cloudflare.com": "Cloudflare",
    "impervadns.net": "Imperva",
    "incapdns.net": "Imperva",
    "sucuri.net": "Sucuri",
    "squarespace.com": "Squarespace",
    "shopify.com": "Shopify",
    "wpengine.com": "WP Engine",
}


def resolve_records(domain: str, record_type: str) -> list[str]:
    """解析指定类型的 DNS 记录，返回字符串列表。"""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def trace_cname_chain(domain: str, depth: int = 10) -> list[str]:
    """
    递归追踪 CNAME 链，返回完整链路。
    例如：example.com -> example.global.prod.fastly.net -> 151.101.x.x
    """
    chain = []
    current = domain
    for _ in range(depth):
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=5)
            target = str(answers[0].target).rstrip(".")
            chain.append(target)
            current = target
        except Exception:
            break
    return chain


def detect_cdn_from_cname(cname_chain: list[str]) -> str | None:
    """从 CNAME 链中识别 CDN 供应商。"""
    for cname in cname_chain:
        cname_lower = cname.lower()
        for signature, cdn_name in CDN_CNAME_SIGNATURES.items():
            if signature in cname_lower:
                return cdn_name
    return None


def run(domain: str) -> dict:
    """
    执行完整 DNS 侦察，返回结构化结果。

    返回示例：
    {
        "domain": "example.com",
        "a_records": ["93.184.216.34"],
        "aaaa_records": [],
        "mx_records": ["mail.example.com"],
        "ns_records": ["ns1.example.com"],
        "txt_records": ["v=spf1 ..."],
        "cname_chain": ["example.global.prod.fastly.net"],
        "cdn_hint": "Fastly",
    }
    """
    cname_chain = trace_cname_chain(domain)

    result = {
        "domain": domain,
        "a_records": resolve_records(domain, "A"),
        "aaaa_records": resolve_records(domain, "AAAA"),
        "mx_records": resolve_records(domain, "MX"),
        "ns_records": resolve_records(domain, "NS"),
        "txt_records": resolve_records(domain, "TXT"),
        "cname_chain": cname_chain,
        "cdn_hint": detect_cdn_from_cname(cname_chain),
    }

    return result
