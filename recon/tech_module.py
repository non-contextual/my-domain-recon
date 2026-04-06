"""
Tech Module — 通过 HTTP 响应特征识别目标站点的技术栈。

检测维度：
  - HTTP 响应头（Server、X-Powered-By、X-Generator 等）
  - HTML meta 标签 / generator 注释
  - Cookie 名称特征
  - 静态资源路径特征（JS/CSS 路径）
  - 已知框架/CMS 的路径指纹
"""

import re
import httpx


# ── 规则库 ──────────────────────────────────────────────────────────────────

# HTTP 响应头规则：{ header_name: [(regex, tech_name), ...] }
HEADER_RULES: dict[str, list[tuple[str, str]]] = {
    "server": [
        (r"nginx", "Nginx"),
        (r"apache", "Apache"),
        (r"microsoft-iis", "IIS"),
        (r"litespeed", "LiteSpeed"),
        (r"openresty", "OpenResty/Nginx"),
        (r"cloudflare", "Cloudflare"),
        (r"AmazonS3", "Amazon S3"),
        (r"AmazonEC2", "Amazon EC2"),
        (r"gws", "Google Web Server"),
        (r"gunicorn", "Gunicorn/Python"),
        (r"uvicorn", "Uvicorn/Python"),
        (r"caddy", "Caddy"),
        (r"tomcat", "Apache Tomcat"),
        (r"jetty", "Jetty"),
    ],
    "x-powered-by": [
        (r"php/?([\d.]+)?", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"express", "Express.js"),
        (r"next\.js", "Next.js"),
        (r"nuxt", "Nuxt.js"),
        (r"django", "Django"),
        (r"rails", "Ruby on Rails"),
        (r"laravel", "Laravel"),
        (r"wordpress", "WordPress"),
    ],
    "x-generator": [
        (r"drupal", "Drupal"),
        (r"wordpress", "WordPress"),
        (r"joomla", "Joomla"),
        (r"typo3", "TYPO3"),
        (r"ghost", "Ghost"),
    ],
    "x-drupal-cache": [
        (r".*", "Drupal"),
    ],
    "x-wp-total": [
        (r".*", "WordPress"),
    ],
    "x-shopify-stage": [
        (r".*", "Shopify"),
    ],
    "x-vercel-id": [
        (r".*", "Vercel"),
    ],
    "x-amz-cf-id": [
        (r".*", "AWS CloudFront"),
    ],
    "cf-ray": [
        (r".*", "Cloudflare"),
    ],
    "x-github-request-id": [
        (r".*", "GitHub Pages"),
    ],
}

# HTML 内容规则：(regex, tech_name)
HTML_RULES: list[tuple[str, str]] = [
    # Generator meta tag
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', None),  # 特殊处理：直接用匹配值
    # WordPress
    (r'/wp-content/', "WordPress"),
    (r'/wp-includes/', "WordPress"),
    (r'wp-json', "WordPress"),
    # Drupal
    (r'drupal\.settings', "Drupal"),
    (r'/sites/default/files/', "Drupal"),
    # Joomla
    (r'/media/jui/', "Joomla"),
    (r'joomla!', "Joomla"),
    # Laravel
    (r'laravel_session', "Laravel"),
    # React
    (r'__NEXT_DATA__', "Next.js"),
    (r'__nuxt', "Nuxt.js"),
    (r'react-root', "React"),
    (r'ng-version', "Angular"),
    (r'__svelte', "Svelte"),
    (r'data-gatsby-', "Gatsby"),
    # Vue
    (r'__vue_app__', "Vue.js"),
    # Bootstrap
    (r'bootstrap\.min\.css', "Bootstrap"),
    (r'bootstrap\.bundle', "Bootstrap"),
    # Tailwind
    (r'tailwind', "Tailwind CSS"),
    # jQuery
    (r'jquery[-./][\d.]+', "jQuery"),
    # Shopify
    (r'Shopify\.theme', "Shopify"),
    (r'cdn\.shopify\.com', "Shopify"),
    # Ghost
    (r'ghost/api/', "Ghost"),
    # Squarespace
    (r'squarespace\.com', "Squarespace"),
    # Wix
    (r'wix\.com/pages/', "Wix"),
    # Webflow
    (r'webflow\.com', "Webflow"),
    # Python
    (r'wsgiref', "Python/WSGI"),
    # Cloudflare Pages
    (r'__cf_bm', "Cloudflare"),
]

# Cookie 名称规则：(regex, tech_name)
COOKIE_RULES: list[tuple[str, str]] = [
    (r"PHPSESSID", "PHP"),
    (r"JSESSIONID", "Java/Spring"),
    (r"ASP\.NET_SessionId", "ASP.NET"),
    (r"_rails_session", "Ruby on Rails"),
    (r"laravel_session", "Laravel"),
    (r"wordpress_logged_in", "WordPress"),
    (r"wp-settings", "WordPress"),
    (r"__shopify_", "Shopify"),
    (r"_shopify_", "Shopify"),
    (r"connect\.sid", "Express.js"),
    (r"csrftoken", "Django"),
    (r"sessionid", "Django"),
    (r"__cf_bm", "Cloudflare"),
    (r"_ga", "Google Analytics"),
    (r"_gid", "Google Analytics"),
    (r"_fbp", "Facebook Pixel"),
]


def _match_rules(value: str, rules: list[tuple[str, str]]) -> list[str]:
    """对 value 逐条尝试规则，返回匹配到的技术名列表。"""
    found = []
    for pattern, tech in rules:
        if re.search(pattern, value, re.IGNORECASE):
            found.append(tech)
    return found


def analyze(domain: str, cdn_headers: dict | None = None) -> dict:
    """
    对目标域名发起 HTTP 请求，分析技术栈。

    Args:
        domain: 目标域名（不含协议）
        cdn_headers: 可选，复用 cdn_module 已经抓到的 headers，避免重复请求

    Returns:
        {
            "techs": ["Nginx", "PHP", "WordPress", ...],  # 去重后的技术列表
            "details": {
                "from_headers": [...],
                "from_html": [...],
                "from_cookies": [...],
            },
            "generator": "WordPress 6.4",  # meta generator 内容（如有）
            "error": None | str,
        }
    """
    techs_headers: list[str] = []
    techs_html: list[str] = []
    techs_cookies: list[str] = []
    generator: str | None = None
    error: str | None = None

    try:
        # 如果没有传入已有 headers，自行请求
        if cdn_headers is None:
            with httpx.Client(
                timeout=10.0,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
            ) as client:
                resp = client.get(f"https://{domain}")
                response_headers = dict(resp.headers)
                html_body = resp.text[:50_000]
                cookie_header = resp.headers.get("set-cookie", "")
        else:
            # 复用已有 headers，但仍需 html body
            response_headers = cdn_headers
            with httpx.Client(
                timeout=10.0,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
            ) as client:
                resp = client.get(f"https://{domain}")
                html_body = resp.text[:50_000]
                cookie_header = resp.headers.get("set-cookie", "")

        # ── 分析 HTTP headers ────────────────────────────────────────────
        for header_name, rules in HEADER_RULES.items():
            header_val = response_headers.get(header_name, "")
            if header_val:
                techs_headers.extend(_match_rules(header_val, rules))

        # ── 分析 HTML body ───────────────────────────────────────────────
        for pattern, tech in HTML_RULES:
            if tech is None:
                # generator meta tag：直接提取内容
                m = re.search(pattern, html_body, re.IGNORECASE)
                if m:
                    generator = m.group(1).strip()
                    # 从 generator 字符串里提取技术名
                    gen_lower = generator.lower()
                    for kw, name in [
                        ("wordpress", "WordPress"), ("drupal", "Drupal"),
                        ("joomla", "Joomla"), ("ghost", "Ghost"),
                        ("typo3", "TYPO3"), ("hugo", "Hugo"),
                        ("jekyll", "Jekyll"), ("gatsby", "Gatsby"),
                        ("next.js", "Next.js"), ("nuxt", "Nuxt.js"),
                        ("webflow", "Webflow"),
                    ]:
                        if kw in gen_lower:
                            techs_html.append(name)
            else:
                if re.search(pattern, html_body, re.IGNORECASE):
                    techs_html.append(tech)

        # ── 分析 Cookies ─────────────────────────────────────────────────
        if cookie_header:
            techs_cookies.extend(_match_rules(cookie_header, COOKIE_RULES))

    except Exception as e:
        error = str(e)

    # 去重，保持顺序
    seen: set[str] = set()
    all_techs: list[str] = []
    for t in techs_headers + techs_html + techs_cookies:
        if t and t not in seen:
            seen.add(t)
            all_techs.append(t)

    return {
        "techs": all_techs,
        "details": {
            "from_headers": list(dict.fromkeys(techs_headers)),
            "from_html": list(dict.fromkeys(techs_html)),
            "from_cookies": list(dict.fromkeys(techs_cookies)),
        },
        "generator": generator,
        "error": error,
    }


def run(domain: str, cdn_headers: dict | None = None) -> dict:
    """技术指纹识别入口，供 cli.py 调用。"""
    return analyze(domain, cdn_headers=cdn_headers)
