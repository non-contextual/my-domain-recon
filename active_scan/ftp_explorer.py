"""
FTP 探测器: 对一批 FTP 端口尝试匿名登录, 列根目录, 用关键词匹配找目标文件夹

用法:
    python ftp_explorer.py 10.132.219.5 --keywords 现代数据库 现代化数据库 数据库
    python ftp_explorer.py 10.132.219.5 --port 925   # 单端口模式
    python ftp_explorer.py 10.132.219.5 --ports-file ftp_ports.txt

设计思路:
    - 高校课程 FTP 常见模式: 一台 Serv-U 同一个 IP 上开几十/上百个端口,
      每个端口对应一个老师/一门课, 匿名登录后根目录就能看到课程文件夹
    - 所以我们要做的: 并发对每个端口匿名登录 -> 列根目录 -> 看名字里有没有关键词
"""

import ftplib
import argparse
import concurrent.futures
import socket
import time
from typing import Optional


# 上一轮全端口扫描发现的所有 Serv-U FTP 端口（避免再扫一遍）
DEFAULT_FTP_PORTS = [
    201, 207, 303, 307, 757, 816, 925, 955, 1008, 1111, 1250, 1298, 1363,
    1560, 1659, 1780, 1910, 1960, 2000, 2001, 2006, 2012, 2017, 2018, 2019,
    2020, 2022, 2042, 2129, 2163, 2202, 2599, 2657, 2751, 2771, 2815, 2996,
    3182, 3535, 3655, 3721, 3750, 3909, 4007, 4248, 5000, 5029, 5110, 5190,
    5199, 5201, 5206, 5318, 5409, 5657, 5690, 5836, 5883, 5910, 5913, 5990,
    5992, 6198, 6239, 6284, 6345, 6455, 6469, 6475, 6507, 6588, 6717, 6727,
    6779, 6887, 7070, 7088, 7288, 7509, 7543, 7547, 7687, 7688, 7853, 8153,
    8261, 8366, 8380, 8680, 8888, 9467, 9511, 9888, 9966, 9999,
]


def list_dir(ftp: ftplib.FTP, path: str = "") -> list[str]:
    """LIST 一个目录, 拿到带文件类型/大小/日期的格式化条目"""
    listing: list[str] = []
    try:
        cmd = f"LIST {path}" if path else "LIST"
        ftp.retrlines(cmd, listing.append)
    except (ftplib.error_perm, ftplib.error_temp):
        pass
    return listing


def parse_dirs(listing: list[str]) -> list[str]:
    """从 UNIX 风格 LIST 输出里挑出目录名(以 d 开头, 排除 . 和 ..)"""
    dirs = []
    for line in listing:
        # UNIX LIST 格式: "drw-rw-rw-   1 user group  0 Jun 9 2019 dirname"
        if not line.startswith("d"):
            continue
        # 取最后一段做名字（处理含空格的目录名: "special English"）
        # 简单解析: 切 9 段, 第 9 段及以后拼回去
        parts = line.split(maxsplit=8)
        if len(parts) < 9:
            continue
        name = parts[8]
        if name in (".", ".."):
            continue
        dirs.append(name)
    return dirs


def explore_ftp(host: str, port: int, timeout: float = 6.0,
                recurse_depth: int = 2,
                credentials: Optional[list[tuple[str, str]]] = None) -> dict:
    """
    对单个 FTP 端口: 尝试一组凭据 -> 列根目录 -> 递归列子目录 -> 返回完整结构

    recurse_depth: 递归层数。1=只列根, 2=根+一级子目录, 3=再深一层。
    国内课程 FTP 一般 2 层就够（根目录里是课程文件夹, 课程文件夹里是讲义）。
    """
    if credentials is None:
        # 常见的匿名登录组合，按命中率排序
        credentials = [
            ("anonymous", "anonymous@example.com"),
            ("anonymous", ""),
            ("ftp", "ftp"),
            ("guest", "guest"),
        ]

    last_err = None
    perm_failed_for_all_creds = False  # 如果所有凭据都被 perm 拒, 没必要再重试

    # Serv-U 在并发高时会触发 per-IP 连接数限制, 拒掉刚发起的连接 -> 必须重试
    for attempt in range(4):
        if attempt > 0:
            time.sleep(0.6 + attempt * 0.4)
        if perm_failed_for_all_creds:
            break
        all_perm_this_round = True
        for user, pw in credentials:
            try:
                ftp = ftplib.FTP()
                # 国内 Serv-U 服务器的目录条目通常是 GBK 编码的中文文件名,
                # ftplib 默认 UTF-8 解码会爆 UnicodeDecodeError ->
                # 用 gb18030 (GBK 超集) 兼容性最好, 它能解 GBK / GB2312 / GB18030 全部
                ftp.encoding = "gb18030"
                ftp.connect(host, port, timeout=timeout)
                ftp.login(user, pw)
                welcome = ftp.getwelcome()
                root_listing = list_dir(ftp)
                tree: dict[str, list[str]] = {"/": root_listing}

                # 递归: 对根目录里的每个子目录进去再 LIST 一次
                if recurse_depth >= 2:
                    for d in parse_dirs(root_listing):
                        try:
                            ftp.cwd(f"/{d}")
                            sub = list_dir(ftp)
                            tree[f"/{d}"] = sub
                            if recurse_depth >= 3:
                                for d2 in parse_dirs(sub):
                                    try:
                                        ftp.cwd(f"/{d}/{d2}")
                                        tree[f"/{d}/{d2}"] = list_dir(ftp)
                                    except ftplib.error_perm:
                                        pass
                        except ftplib.error_perm:
                            pass
                try:
                    ftp.quit()
                except Exception:
                    pass
                return {"port": port, "user": user, "welcome": welcome, "tree": tree}
            except ftplib.error_perm as e:
                last_err = f"perm: {e}"
                continue  # 这组凭据被拒, 换下一组
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError,
                    EOFError, OSError) as e:
                # 网络层错误: Serv-U 限速/服务暂时不可达, 值得重试
                last_err = f"net({type(e).__name__}): {e}"
                all_perm_this_round = False
                break  # 跳出凭据循环, 让外层 attempt 重试
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                all_perm_this_round = False
                break
        else:
            # 所有凭据都跑完了, 全是 perm error -> 这是真的拒绝匿名, 不重试
            perm_failed_for_all_creds = True
        if all_perm_this_round:
            perm_failed_for_all_creds = True

    return {"port": port, "error": f"failed_after_retry: {last_err}"}


def matches_keyword(text: str, keywords: list[str]) -> bool:
    """
    名字里包含任一关键词就算命中。
    大小写不敏感。短关键词（≤3 字符的英文）必须前后是非字母数字, 避免误伤
    （比如 "DB" 不能命中 Server 里的 "rb"，"er" 不能命中 Server 里的 "er"）。
    中文关键词不做边界检查（中文里没有"单词边界"概念）。
    """
    import re
    text_lower = text.lower()
    for kw in keywords:
        kw_l = kw.lower()
        # 中文关键词或长英文词: 直接子串匹配
        if any(ord(c) > 127 for c in kw_l) or len(kw_l) >= 4:
            if kw_l in text_lower:
                return True
        else:
            # 短英文词: 加单词边界
            if re.search(r"(?<![a-z0-9])" + re.escape(kw_l) + r"(?![a-z0-9])", text_lower):
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description="FTP 匿名登录 + 关键词搜索")
    parser.add_argument("host", help="目标 IP")
    parser.add_argument("--port", type=int, help="只探测单个端口")
    parser.add_argument("--ports", help="逗号分隔的端口列表")
    parser.add_argument(
        "--keywords",
        nargs="+",
        default=[
            "现代", "数据库", "database", "modern",
            "sql", "mysql", "oracle", "关系数据", "数据",
            "数据库系统", "数据库原理", "DB2",
        ],
        help="目录名关键词，命中即输出",
    )
    parser.add_argument("--workers", type=int, default=30, help="并发数")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--depth", type=int, default=2, help="递归列目录的层数")
    parser.add_argument("--show-all", action="store_true",
                        help="即使没命中关键词也输出全部结果")
    parser.add_argument("--show-errors", action="store_true",
                        help="把每个失败端口的原因也打出来")
    parser.add_argument("--json", help="把所有端口的探测结果导出为 JSON 文件")
    args = parser.parse_args()

    # 决定要扫的端口列表
    if args.port:
        ports = [args.port]
    elif args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = DEFAULT_FTP_PORTS

    print(f"[*] 目标 {args.host}, 共 {len(ports)} 个 FTP 端口待探测")
    print(f"[*] 关键词: {args.keywords}")
    print("-" * 70)

    hits: list[dict] = []        # 命中关键词的端口
    accessible: list[dict] = []  # 能匿名登录但没命中的端口
    errors: list[dict] = []      # 各种失败的端口

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(explore_ftp, args.host, p, args.timeout, args.depth): p
            for p in ports
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            port = res["port"]
            if "error" in res:
                errors.append(res)
                continue

            # 收集所有目录条目和路径名做关键词匹配
            haystack_parts = [res["welcome"]]
            for path, lines in res["tree"].items():
                haystack_parts.append(path)
                haystack_parts.extend(lines)
            haystack = "\n".join(haystack_parts)

            if matches_keyword(haystack, args.keywords):
                hits.append(res)
                print(f"\n[!!!] 端口 {port} (登录身份: {res['user']}) 命中关键词")
                # 把每个命中关键词的目录或文件高亮打出来
                for path, lines in res["tree"].items():
                    matched_lines = [l for l in lines if matches_keyword(l, args.keywords)
                                     or matches_keyword(path, args.keywords)]
                    if matched_lines:
                        print(f"      [{path}]")
                        for line in matched_lines:
                            print(f"      >>> {line}")
            else:
                accessible.append(res)

    print("\n" + "=" * 70)
    print(f"[*] 命中关键词:        {len(hits)} 个端口")
    print(f"[*] 可登录未命中:      {len(accessible)} 个端口")
    print(f"[*] 失败/被拒:         {len(errors)} 个端口")

    if hits:
        print("\n[!] 推荐打开 (在浏览器里贴这个 URL 就行):")
        for h in hits:
            print(f"    ftp://{args.host}:{h['port']}/")

    # 没命中也打印能登的端口的全部树, 让用户肉眼找
    if accessible:
        header = "[!] 已命中目标, 下面是其它能登的端口供参考:" if hits else \
                 "[*] 没命中关键词, 下面是所有能匿名登录的端口的目录树:"
        print(f"\n{header}")
        for res in accessible:
            print(f"\n--- ftp://{args.host}:{res['port']}/ ---")
            for path, lines in res["tree"].items():
                print(f"  [{path}]")
                for line in lines[:50]:
                    print(f"    {line}")
                if len(lines) > 50:
                    print(f"    ... 还有 {len(lines) - 50} 个条目")

    # 失败原因分类: 看看是不是大部分被拒绝匿名 (这种情况下需要换凭据)
    if args.show_errors and errors:
        print(f"\n[*] 失败端口具体错误 (前 15 个):")
        for e in errors[:15]:
            print(f"    {e['port']:>5}: {e['error']}")
        if len(errors) > 15:
            print(f"    ... 还有 {len(errors) - 15} 个")

    # JSON 导出: 把所有能登的端口的完整树状数据存盘, 给可视化用
    if args.json:
        import json
        all_accessible = sorted(hits + accessible, key=lambda r: r["port"])
        out = {
            "host": args.host,
            "ports": [
                {
                    "port": r["port"],
                    "user": r["user"],
                    "welcome": r["welcome"],
                    "tree": r["tree"],
                }
                for r in all_accessible
            ],
            "errors": [{"port": e["port"], "error": e["error"]} for e in errors],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\n[*] JSON 已写入: {args.json} ({len(all_accessible)} 个可登录端口)")


if __name__ == "__main__":
    main()
