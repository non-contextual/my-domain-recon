"""
Headers Module — 分析 HTTP 安全响应头配置，识别安全缺口和版本信息泄漏。

检测维度：
  - 安全头覆盖率（HSTS / CSP / X-Frame-Options / X-Content-Type-Options 等）
  - 版本信息泄漏（Server 版本号、X-Powered-By、X-AspNet-Version 等）
  - 综合评级：A（优秀） / B（良好） / C（需改进） / F（高危缺口）
"""

import re
import httpx


# 需要检测的安全头 —— (header_name, 友好名, 重要程度, 期望值说明)
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS",                  "critical", "max-age >= 31536000"),
    ("content-security-policy",   "CSP",                   "high",     "任意非空值"),
    ("x-frame-options",           "X-Frame-Options",        "high",     "DENY 或 SAMEORIGIN"),
    ("x-content-type-options",    "X-Content-Type-Options", "medium",   "nosniff"),
    ("referrer-policy",           "Referrer-Policy",        "medium",   "任意非空值"),
    ("permissions-policy",        "Permissions-Policy",     "low",      "任意非空值"),
    ("x-xss-protection",          "X-XSS-Protection",       "low",      "1; mode=block（已被 CSP 取代）"),
]

# 可能泄漏版本信息的头
LEAK_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",           # Ruby on Rails
    "x-drupal-cache",
    "x-pingback",          # WordPress XML-RPC 端点
]

# 版本号特征正则（匹配到则认为泄漏了具体版本）
VERSION_RE = re.compile(
    r"[\d]+\.[\d]+[\.\d]*|"        # 1.2 / 1.2.3 / 1.2.3.4
    r"(apache|nginx|iis|php|tomcat|jetty|openresty|caddy|gunicorn|uvicorn)"
    r"[/\s][\d]+",
    re.IGNORECASE,
)


def _analyze_hsts(value: str) -> str:
    """检查 HSTS 头是否足够强。"""
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not m:
        return "配置异常：缺少 max-age"
    age = int(m.group(1))
    if age < 2592000:    # 30 天
        return f"max-age={age} — 过短，建议 ≥ 31536000（1 年）"
    if age < 31536000:   # 1 年
        return f"max-age={age} — 较短，建议 ≥ 31536000"
    note = "✓"
    if "includesubdomains" in value.lower():
        note += " includeSubDomains"
    if "preload" in value.lower():
        note += " preload"
    return note


def _check_security_headers(headers: dict) -> dict:
    """
    检查各安全头的存在性和配置质量。

    返回：
    {
        "strict-transport-security": {
            "present": True,
            "value": "max-age=31536000; includeSubDomains",
            "importance": "critical",
            "note": "✓ includeSubDomains",
        },
        ...
    }
    """
    results = {}
    h_lower = {k.lower(): v for k, v in headers.items()}

    for header_key, friendly, importance, hint in SECURITY_HEADERS:
        val = h_lower.get(header_key)
        if val:
            if header_key == "strict-transport-security":
                note = _analyze_hsts(val)
            elif header_key == "x-frame-options":
                note = "✓" if val.upper() in ("DENY", "SAMEORIGIN") else f"非标准值: {val}"
            elif header_key == "x-content-type-options":
                note = "✓" if "nosniff" in val.lower() else f"非 nosniff: {val}"
            elif header_key == "x-xss-protection":
                note = "✓" if "1" in val else f"值: {val}"
            else:
                note = "✓ (已配置)"
        else:
            note = "⚠ 缺失"

        results[header_key] = {
            "friendly": friendly,
            "present":  val is not None,
            "value":    val,
            "importance": importance,
            "note":     note,
            "hint":     hint,
        }

    return results


def _check_info_leaks(headers: dict) -> list[dict]:
    """
    检查响应头中的版本/框架信息泄漏。

    返回：[{"header": "server", "value": "Apache/2.4.51", "has_version": True}, ...]
    """
    leaks = []
    h_lower = {k.lower(): v for k, v in headers.items()}

    for header_key in LEAK_HEADERS:
        val = h_lower.get(header_key)
        if val:
            has_version = bool(VERSION_RE.search(val))
            leaks.append({
                "header":      header_key,
                "value":       val,
                "has_version": has_version,
            })

    return leaks


def _grade(sec_headers: dict, leaks: list) -> tuple[str, int]:
    """
    综合评级：
      - critical 头全部存在 + high 头全部存在 → A（加分项：low 头）
      - critical 头全部存在，缺少部分 high → B
      - 缺少 critical 头 → C
      - 存在版本泄漏 + 缺少 critical → F
    """
    critical_missing = [
        k for k, v in sec_headers.items()
        if v["importance"] == "critical" and not v["present"]
    ]
    high_missing = [
        k for k, v in sec_headers.items()
        if v["importance"] == "high" and not v["present"]
    ]
    version_leaks = [l for l in leaks if l["has_version"]]

    total   = len(sec_headers)
    present = sum(1 for v in sec_headers.values() if v["present"])
    score   = int(present / total * 100)

    if version_leaks and critical_missing:
        grade = "F"
    elif critical_missing:
        grade = "C"
    elif high_missing:
        grade = "B"
    else:
        grade = "A"

    return grade, score


def run(domain: str, existing_headers: dict | None = None) -> dict:
    """
    执行安全头分析。

    Args:
        domain: 目标域名
        existing_headers: 若已有 cdn_module 抓到的响应头，直接复用避免重复请求

    Returns:
        {
            "grade":    "A" | "B" | "C" | "F",
            "score":    0-100,
            "security": { header_key: {...} },
            "leaks":    [ {"header", "value", "has_version"} ],
            "missing_critical": [...],
            "error":    None | str,
        }
    """
    headers: dict = {}
    error: str | None = None

    if existing_headers:
        headers = existing_headers
    else:
        try:
            with httpx.Client(
                timeout=10.0,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
            ) as client:
                resp = client.get(f"https://{domain}")
                headers = dict(resp.headers)
        except Exception as e:
            error = str(e)

    sec = _check_security_headers(headers)
    leaks = _check_info_leaks(headers)
    grade, score = _grade(sec, leaks)

    missing_critical = [
        v["friendly"] for k, v in sec.items()
        if v["importance"] == "critical" and not v["present"]
    ]

    return {
        "grade":            grade,
        "score":            score,
        "security":         sec,
        "leaks":            leaks,
        "missing_critical": missing_critical,
        "error":            error,
    }
