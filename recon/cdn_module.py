"""
CDN Module — 通过 HTTP 响应头指纹识别 CDN，并尝试探测原始 IP。
同时生成 Fastly/CloudFront 风格的直接访问 URL。
"""

import httpx


# HTTP 响应头 CDN 指纹特征
CDN_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # (header_name, value_contains, cdn_name)
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-cache", "HIT", "Fastly"),          # Fastly 常见但不唯一
    ("via", "1.1 varnish", "Fastly"),
    ("x-cache", "cloudfront", "AWS CloudFront"),
    ("via", "cloudfront", "AWS CloudFront"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("server", "AkamaiGHost", "Akamai"),
    ("x-check-cacheable", "", "Akamai"),
    ("server", "nginx", None),             # 常见但不代表 CDN
    ("x-azure-ref", "", "Azure CDN"),
    ("x-ms-ref", "", "Azure CDN"),
    ("x-github-request-id", "", "GitHub Pages"),
    ("x-netlify", "", "Netlify"),
    ("x-vercel-id", "", "Vercel"),
    ("x-vercel-cache", "", "Vercel"),
    ("server", "Squarespace", "Squarespace"),
]


def detect_cdn_from_headers(headers: dict) -> str | None:
    """分析响应头，返回识别到的 CDN 名称。"""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for header_name, value_contains, cdn_name in CDN_HEADER_SIGNATURES:
        if header_name in headers_lower:
            if not value_contains or value_contains.lower() in headers_lower[header_name]:
                if cdn_name:
                    return cdn_name
    return None


def build_fastly_url(domain: str) -> str:
    """构造 Fastly 直连 URL，格式参考 btc.day 案例。"""
    # 去掉 www 前缀，取主域名部分
    base = domain.lstrip("www.").replace(".", "-", domain.count(".") - 1)
    return f"http://{domain}.global.prod.fastly.net"


def fetch_headers(url: str, timeout: float = 8.0) -> dict:
    """发送 HEAD 请求获取响应头（失败则降级为 GET）。"""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout,
                          verify=False) as client:
            resp = client.head(url)
            # HEAD 有时返回 405，降级到 GET
            if resp.status_code == 405:
                resp = client.get(url)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "final_url": str(resp.url),
            }
    except Exception as e:
        return {"status_code": None, "headers": {}, "error": str(e), "final_url": url}


def run(domain: str, dns_result: dict | None = None) -> dict:
    """
    执行 CDN 指纹识别。

    返回示例：
    {
        "cdn_detected": "Fastly",
        "detection_method": "header",   # "header" | "cname" | None
        "status_code": 200,
        "final_url": "https://example.com/",
        "key_headers": {...},
        "cloudfront_bucket": "https://d325bmwzjz2yc7.cloudfront.net",  # 若检测到
        "fastly_direct": "http://example.com.global.prod.fastly.net",  # 若检测到
    }
    """
    result: dict = {
        "cdn_detected": None,
        "detection_method": None,
        "status_code": None,
        "final_url": None,
        "key_headers": {},
        "cloudfront_bucket": None,
        "fastly_direct": None,
    }

    # 优先使用 DNS 模块已识别的 CDN 线索
    if dns_result and dns_result.get("cdn_hint"):
        result["cdn_detected"] = dns_result["cdn_hint"]
        result["detection_method"] = "cname"

    # 通过 HTTP 头验证或补充识别
    for scheme in ("https", "http"):
        fetch = fetch_headers(f"{scheme}://{domain}")
        if fetch["status_code"]:
            result["status_code"] = fetch["status_code"]
            result["final_url"] = fetch["final_url"]

            # 提取关键响应头（过滤掉冗长的 set-cookie 等）
            interesting_headers = [
                "server", "via", "x-cache", "x-served-by", "cf-ray",
                "x-amz-cf-id", "x-azure-ref", "x-vercel-id", "x-github-request-id",
                "x-netlify", "content-type", "x-powered-by",
            ]
            result["key_headers"] = {
                k: v for k, v in fetch["headers"].items()
                if k.lower() in interesting_headers
            }

            # 通过头检测 CDN（覆盖或补充 CNAME 检测）
            cdn_from_headers = detect_cdn_from_headers(fetch["headers"])
            if cdn_from_headers and not result["cdn_detected"]:
                result["cdn_detected"] = cdn_from_headers
                result["detection_method"] = "header"

            break

    # 若检测到 Fastly，构造直连 URL
    if result["cdn_detected"] == "Fastly":
        result["fastly_direct"] = build_fastly_url(domain)

    # 若 CloudFront，尝试在 final_url 中提取 bucket URL
    if result["cdn_detected"] == "AWS CloudFront":
        final = result.get("final_url", "")
        if "cloudfront.net" in final:
            result["cloudfront_bucket"] = final

    return result
