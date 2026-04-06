"""
Fuzz Module — 对目标 URL 进行异步路径枚举，发现暴露的文件和目录。
使用精简的高价值路径列表，优先检测敏感文件。
"""

import asyncio
import httpx
from typing import Callable


# 高价值路径列表 —— 参考 SecLists 精选，聚焦最常见暴露场景
HIGH_VALUE_PATHS = [
    # macOS 泄漏
    ".DS_Store",
    # Git 仓库暴露
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    # 环境变量 / 配置
    ".env",
    ".env.local",
    ".env.production",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.json",
    "app.config.js",
    # 常见前端部署产物
    "live.html",
    "index.html",
    "app.html",
    "staging.html",
    "beta.html",
    "preview.html",
    "test.html",
    # API 端点
    "api/",
    "api/v1/",
    "api/health",
    "api/status",
    "health",
    "status",
    "ping",
    # 后台管理
    "admin/",
    "admin/login",
    "wp-admin/",
    "dashboard/",
    # 备份文件
    "backup.sql",
    "backup.zip",
    "db.sql",
    "dump.sql",
    "database.sql",
    # 日志
    "error.log",
    "access.log",
    "debug.log",
    # 常见框架路径
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "security.txt",
    ".well-known/security.txt",
    # 包信息
    "package.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
    # AWS / 云相关
    "aws-exports.js",
    "firebase.json",
    ".firebaserc",
    # 内部工具
    "internal/",
    "dev/",
    "staging/",
    "test/",
    "debug/",
    "swagger/",
    "swagger.json",
    "openapi.json",
    "api-docs/",
    "graphql",
    "graphiql",
]


def _structural_fingerprint(body: str) -> str:
    """
    提取响应体的结构性指纹，去除动态内容（token、nonce、hash、timestamp）。
    用于识别 SPA catch-all 误报。
    """
    import re
    # 去除常见动态属性值
    s = re.sub(r'(?:nonce|token|csrf|timestamp|integrity|data-unique)="[^"]*"', '', body, flags=re.I)
    # 去除 32 位以上的 hex 字符串（hash/UUID）
    s = re.sub(r'\b[0-9a-f]{32,}\b', '', s, flags=re.I)
    # 去除数字（时间戳、计数器等）
    s = re.sub(r'\b\d{6,}\b', '', s)
    # 压缩空白
    s = re.sub(r'\s+', ' ', s).strip()
    return s[:600]


async def get_root_fingerprint(client: httpx.AsyncClient, base_url: str) -> tuple[int, str, str]:
    """
    向一个肯定不存在的路径发请求，检测是否为 SPA catch-all。
    返回 (canary_status, canary_content_type, canary_structural_fingerprint)
    """
    canary_url = f"{base_url.rstrip('/')}/__osint_canary_404_check__"
    try:
        resp = await client.get(canary_url, follow_redirects=True)
        content_type = resp.headers.get("content-type", "").split(";")[0].strip()
        if resp.status_code == 200 and "html" in content_type:
            fingerprint = _structural_fingerprint(resp.text[:8000])
            return (200, content_type, fingerprint)
    except Exception:
        pass
    return (404, "", "")


async def check_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    spa_fingerprint: tuple[int, str, str] | None = None,
) -> dict | None:
    """
    异步检查单个路径是否存在。
    返回 None 表示路径不存在或是 SPA 误报，否则返回发现信息。
    """
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = await client.get(url, follow_redirects=False)
        # 过滤掉明显的「找不到」响应
        if resp.status_code in (404, 410):
            return None

        content_length = int(resp.headers.get("content-length", 0))

        # SPA 过滤：若站点对所有路径返回 200，检查响应体结构是否与 canary 相同
        if spa_fingerprint and spa_fingerprint[0] == 200 and resp.status_code == 200:
            content_type = resp.headers.get("content-type", "").split(";")[0].strip()
            if "html" in content_type:
                page_fp = _structural_fingerprint(resp.text[:8000])
                # 计算相似度：公共前缀长度 / 指纹总长度
                canary_fp = spa_fingerprint[2]
                min_len = min(len(page_fp), len(canary_fp))
                if min_len > 50:
                    common = sum(a == b for a, b in zip(page_fp, canary_fp))
                    similarity = common / min_len
                    if similarity > 0.70:
                        return None  # 结构相似，是 SPA catch-all 误报

        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "content_length": content_length,
            "content_type": resp.headers.get("content-type", ""),
            "redirect_to": resp.headers.get("location", "") if resp.status_code in (301, 302, 307, 308) else "",
        }
    except Exception:
        return None


async def fuzz_async(
    base_url: str,
    paths: list[str],
    concurrency: int = 20,
    progress_callback: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """
    异步路径枚举主逻辑。

    Args:
        base_url: 目标基础 URL（例如 https://example.com）
        paths: 路径列表
        concurrency: 并发数
        progress_callback: 进度回调，接收 (completed, total)

    Returns:
        发现的路径列表
    """
    findings: list[dict] = []
    semaphore = asyncio.Semaphore(concurrency)
    completed = 0

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=10)
    async with httpx.AsyncClient(
        timeout=8.0,
        verify=False,
        limits=limits,
        headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
    ) as client:
        # 先获取根路径指纹，用于过滤 SPA 误报
        spa_fingerprint = await get_root_fingerprint(client, base_url)

        async def bounded_check(path: str) -> dict | None:
            nonlocal completed
            async with semaphore:
                result = await check_path(client, base_url, path, spa_fingerprint=spa_fingerprint)
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(paths))
                return result

        tasks = [bounded_check(path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    return findings


def run(base_url: str, extra_paths: list[str] | None = None,
        progress_callback: Callable[[int, int], None] | None = None) -> dict:
    """
    执行路径模糊测试。

    Args:
        base_url: 目标 URL（例如 https://example.com 或 CloudFront bucket URL）
        extra_paths: 额外的路径列表（追加到默认列表）

    Returns:
        {
            "base_url": str,
            "paths_tested": int,
            "findings": [{"path", "url", "status", "content_length", ...}, ...]
        }
    """
    paths = HIGH_VALUE_PATHS.copy()
    if extra_paths:
        paths.extend(extra_paths)

    # 去重
    paths = list(dict.fromkeys(paths))

    findings = asyncio.run(fuzz_async(base_url, paths, progress_callback=progress_callback))

    # 按状态码排序，200/成功的优先展示
    findings.sort(key=lambda x: (x["status"] != 200, x["status"]))

    return {
        "base_url": base_url,
        "paths_tested": len(paths),
        "findings": findings,
    }
