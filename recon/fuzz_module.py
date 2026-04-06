"""
Fuzz Module — 对目标 URL 进行异步路径枚举，发现暴露的文件和目录。
使用精简的高价值路径列表，优先检测敏感文件。
"""

import asyncio
import re
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


async def get_root_fingerprint(client: httpx.AsyncClient, base_url: str) -> tuple[int, str, str, str]:
    """
    检测两种常见误报模式：
    1. SPA catch-all：所有路径返回 200 + 同一份 HTML
    2. 全站 302 redirect：根路径本身就是 302（如 apex → www）

    返回 (canary_status, canary_content_type, canary_structural_fingerprint, redirect_location_prefix)
    redirect_location_prefix 非空时表示「全站统一跳转」模式，需过滤相同目标的 302
    """
    # 先检查根路径是否本身就是 302（全站跳转）
    root_redirect_prefix = ""
    try:
        root_resp = await client.get(base_url.rstrip("/") + "/", follow_redirects=False)
        if root_resp.status_code in (301, 302, 307, 308):
            loc = root_resp.headers.get("location", "")
            # 提取跳转目标的 origin 部分（如 https://www.anthropic.com）
            if loc:
                from urllib.parse import urlparse
                parsed = urlparse(loc)
                root_redirect_prefix = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass

    # 再检测 SPA catch-all（canary 路径返回 200）
    canary_url = f"{base_url.rstrip('/')}/__osint_canary_404_check__"
    try:
        resp = await client.get(canary_url, follow_redirects=True)
        content_type = resp.headers.get("content-type", "").split(";")[0].strip()
        if resp.status_code == 200 and "html" in content_type:
            fingerprint = _structural_fingerprint(resp.text[:8000])
            return (200, content_type, fingerprint, root_redirect_prefix)
    except Exception:
        pass
    return (404, "", "", root_redirect_prefix)


async def check_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    spa_fingerprint: tuple[int, str, str, str] | None = None,
) -> dict | None:
    """
    异步检查单个路径是否存在。
    返回 None 表示路径不存在或是已知误报，否则返回发现信息。
    """
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = await client.get(url, follow_redirects=False)

        if resp.status_code in (404, 410):
            return None

        content_length = int(resp.headers.get("content-length", 0))
        location = resp.headers.get("location", "") if resp.status_code in (301, 302, 307, 308) else ""

        # 过滤 1：全站统一 302 跳转（如 anthropic.com → www.anthropic.com）
        # 若根路径本身就是 302 到某个 origin，跳转目标也是同一个 origin → 误报
        if spa_fingerprint and spa_fingerprint[3] and resp.status_code in (301, 302, 307, 308):
            redirect_prefix = spa_fingerprint[3]
            if location.startswith(redirect_prefix):
                return None

        # 过滤 2：SPA catch-all（canary 路径返回 200，结构相似）
        if spa_fingerprint and spa_fingerprint[0] == 200 and resp.status_code == 200:
            content_type = resp.headers.get("content-type", "").split(";")[0].strip()
            if "html" in content_type:
                page_fp = _structural_fingerprint(resp.text[:8000])
                canary_fp = spa_fingerprint[2]
                min_len = min(len(page_fp), len(canary_fp))
                if min_len > 50:
                    common = sum(a == b for a, b in zip(page_fp, canary_fp))
                    if common / min_len > 0.70:
                        return None

        finding = {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "content_length": content_length,
            "content_type": resp.headers.get("content-type", ""),
            "redirect_to": location,
        }

        # 若发现可读的 .DS_Store，自动解析文件列表
        if resp.status_code == 200 and path.endswith(".DS_Store"):
            try:
                parsed_files = parse_ds_store(resp.content)
                if parsed_files:
                    finding["ds_store_files"] = parsed_files
            except Exception:
                pass

        return finding
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


def parse_ds_store(data: bytes) -> list[str]:
    """
    从 .DS_Store 二进制文件中提取目录内文件名列表。

    .DS_Store 是 macOS Finder 生成的目录元数据文件，以 Buddy Allocator 格式存储。
    核心思路：文件名以 4 字节大端长度 + UTF-16 BE 编码存储在记录块中。
    通过扫描整个二进制数据提取所有符合条件的字符串，准确率很高。
    """
    import struct

    filenames: set[str] = set()

    # 策略一：4字节长度前缀 + UTF-16 BE 字符串（DS_Store 主要存储格式）
    i = 0
    while i < len(data) - 4:
        try:
            length = struct.unpack(">I", data[i : i + 4])[0]
            if 1 <= length <= 255:
                end = i + 4 + length * 2
                if end <= len(data):
                    candidate = data[i + 4 : end].decode("utf-16-be", errors="ignore")
                    # 过滤：可打印字符，不含路径分隔符，不是纯数字/空白
                    if (
                        candidate
                        and candidate.isprintable()
                        and "/" not in candidate
                        and "\\" not in candidate
                        and not candidate.isspace()
                        and len(candidate.strip()) >= 2
                        and not candidate.strip().isdigit()
                    ):
                        filenames.add(candidate.strip())
        except Exception:
            pass
        i += 1

    # 策略二：直接提取 ASCII 可打印字符串（兜底，覆盖旧版 DS_Store 格式）
    ascii_names = re.findall(rb"[\x20-\x7e]{3,255}", data)
    for name_bytes in ascii_names:
        try:
            name = name_bytes.decode("ascii")
            # 只保留看起来像文件名/目录名的字符串（含扩展名或为简短词）
            if (
                "." in name or (name.isalnum() and len(name) >= 3)
            ) and len(name) <= 128:
                # 排除已知干扰字符串
                if not any(
                    kw in name.lower()
                    for kw in ["blob", "comp", "bool", "long", "shor", "dutc", "icc ", "bwsp"]
                ):
                    filenames.add(name)
        except Exception:
            pass

    # 排序后返回，过滤掉 .DS_Store 自身
    return sorted(f for f in filenames if f != ".DS_Store")


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
