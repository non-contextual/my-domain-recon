"""
Wayback Module — 通过 Wayback Machine CDX API 分析目标的历史暴露情况。

能发现什么：
  - 域名最早/最近被归档的时间（推断建站时间）
  - 历史快照数量（活跃度）
  - 历史上曾暴露过的敏感文件路径（.sql/.bak/.env/.zip 等）
  - 已删除但曾公开的路径（历史存在，当前已消失）

数据来源：
  - Wayback Machine CDX API（免费，无需 API key）
    https://web.archive.org/cdx/search/cdx
"""

import httpx
from urllib.parse import quote


CDX_API = "https://web.archive.org/cdx/search/cdx"

# 敏感扩展名：历史上出现过就值得关注
SENSITIVE_EXTENSIONS = {
    ".sql", ".bak", ".backup", ".dump",
    ".env", ".env.local", ".env.production",
    ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z",
    ".log", ".cfg", ".conf", ".config",
    ".key", ".pem", ".crt", ".pfx",
    ".xml",   # 可能包含配置
    ".json",  # 可能包含配置
    ".yaml", ".yml",
    ".git",   # 目录
    ".svn",
}

# 无需关注的高频无意义路径（降噪）
NOISE_PATHS = {"/", "/index.html", "/index.php", "/favicon.ico", "/robots.txt", "/sitemap.xml"}

# 敏感路径关键词（路径中含有这些词则标记）
SENSITIVE_PATH_KEYWORDS = [
    "admin", "backup", "dump", "config", "secret",
    "passwd", "password", "credentials", "private",
    "internal", "debug", "test", "staging", "dev",
    "phpmyadmin", "adminer", "cpanel", "webmail",
]


def _is_sensitive_url(url: str) -> bool:
    """判断一个历史 URL 是否值得关注。"""
    url_lower = url.lower()
    # 检查扩展名
    for ext in SENSITIVE_EXTENSIONS:
        if url_lower.endswith(ext) or f"{ext}?" in url_lower:
            return True
    # 检查关键词
    for kw in SENSITIVE_PATH_KEYWORDS:
        if f"/{kw}" in url_lower or f"/{kw}/" in url_lower:
            return True
    return False


def _extract_path(url: str, domain: str) -> str:
    """从完整 URL 中提取路径部分。"""
    try:
        # 去掉 scheme://domain 部分
        for prefix in (f"https://{domain}", f"http://{domain}",
                       f"https://www.{domain}", f"http://www.{domain}"):
            if url.lower().startswith(prefix.lower()):
                path = url[len(prefix):]
                return path if path else "/"
    except Exception:
        pass
    return url


def fetch_cdx(domain: str, limit: int = 500, timeout: float = 15.0) -> list[list[str]] | None:
    """
    查询 CDX API，返回原始记录列表。
    每条记录格式：[timestamp, original_url, statuscode]

    使用 collapse=urlkey 去重，避免同一路径的大量快照淹没结果。
    """
    params = {
        "url":      f"*.{domain}",   # 通配查询，包含子域
        "output":   "json",
        "fl":       "timestamp,original,statuscode",
        "collapse": "urlkey",        # 同一 URL 只保留最新一条
        "limit":    str(limit),
        "filter":   "statuscode:200", # 只关注曾经可访问的
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(CDX_API, params=params)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 1:
                    return data[1:]   # 第一行是字段名
    except Exception:
        pass
    return None


def run(domain: str) -> dict:
    """
    查询 Wayback Machine 历史数据。

    Returns:
        {
            "available":        True,
            "first_seen":       "2010-03-15",
            "last_seen":        "2026-01-10",
            "snapshot_count":   342,         # 去重后的唯一 URL 数
            "sensitive_urls":   [
                {"url": "http://example.com/backup.sql", "timestamp": "2019-05-20", "status": "200"},
                ...
            ],
            "interesting_paths": [...],      # 敏感路径去重列表（仅路径，不含域名）
            "error":            None,
        }
    """
    result: dict = {
        "available":         False,
        "first_seen":        None,
        "last_seen":         None,
        "snapshot_count":    0,
        "sensitive_urls":    [],
        "interesting_paths": [],
        "error":             None,
    }

    records = fetch_cdx(domain)

    if records is None:
        result["error"] = "Wayback Machine CDX API 不可达或无数据"
        return result

    if not records:
        result["error"] = "该域名在 Wayback Machine 中暂无记录"
        return result

    result["available"]      = True
    result["snapshot_count"] = len(records)

    # 解析时间戳（格式：YYYYMMDDHHmmss）
    timestamps = []
    for row in records:
        if len(row) >= 1:
            ts = row[0]
            if len(ts) >= 8:
                timestamps.append(ts)

    if timestamps:
        timestamps.sort()
        first = timestamps[0]
        last  = timestamps[-1]
        result["first_seen"] = f"{first[:4]}-{first[4:6]}-{first[6:8]}"
        result["last_seen"]  = f"{last[:4]}-{last[4:6]}-{last[6:8]}"

    # 筛选敏感 URL
    seen_paths: set[str] = set()
    for row in records:
        if len(row) < 3:
            continue
        ts, url, status = row[0], row[1], row[2]

        if _is_sensitive_url(url):
            path = _extract_path(url, domain)
            if path not in NOISE_PATHS and path not in seen_paths:
                seen_paths.add(path)
                date_str = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                result["sensitive_urls"].append({
                    "url":       url,
                    "path":      path,
                    "timestamp": date_str,
                    "status":    status,
                })

    # 整理唯一的有趣路径列表（用于摘要展示）
    result["interesting_paths"] = [item["path"] for item in result["sensitive_urls"]]

    # 按时间戳排序（最近的在前）
    result["sensitive_urls"].sort(key=lambda x: x["timestamp"], reverse=True)

    return result
