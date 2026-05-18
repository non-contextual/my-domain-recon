"""
端口扫描器 + FTP 识别工具

用法:
    python scanner.py 10.132.219.5                # 默认扫常见 FTP 端口 + 常见服务端口
    python scanner.py 10.132.219.5 --full         # 扫 1-65535 全端口
    python scanner.py 10.132.219.5 --ports 21,22,2121
    python scanner.py 10.132.219.5 --range 1-10000

策略:
    1. 用 socket connect 做 TCP 探测，多线程并发提速
    2. 对开放的端口尝试 banner grab，识别 FTP（看 220 响应码）
    3. 找到 FTP 后，再用 ftp_explorer.py 进一步登录列目录
"""

import socket
import sys
import argparse
import concurrent.futures
from datetime import datetime


# 常见 FTP 端口 + 常见服务端口（先扫这些，命中率高）
COMMON_PORTS = [
    20, 21,           # FTP 数据/控制
    22,               # SSH（很多管理员把 FTP 换到 SSH 上做 SFTP）
    80, 443, 8080,    # HTTP（可能藏着 Web FTP 入口）
    989, 990,         # FTPS
    2121, 2221,       # 备选 FTP（防止默认 21 被防火墙拦）
    8021, 8121,       # 备选 FTP
    3306, 5432,       # MySQL / PostgreSQL（数据库本体，万一你说的就是这个）
    27017,            # MongoDB
]


def scan_port(host: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
    """
    扫描单个端口。
    返回 (端口号, 是否开放, banner)。
    banner grab: 连上后等 1 秒看服务器是否主动发送数据（FTP/SSH 都会）。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result != 0:
            sock.close()
            return port, False, ""

        # 端口开着 → 试着抓 banner
        # 大部分服务（FTP/SSH/SMTP）连上就会主动 push welcome message
        banner = ""
        try:
            sock.settimeout(1.5)
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            # HTTP 这种不主动发，需要我们先发请求；这里不深挖
            pass
        sock.close()
        return port, True, banner
    except Exception as e:
        return port, False, f"ERR: {e}"


def parse_ports(args) -> list[int]:
    """根据命令行参数生成要扫的端口列表"""
    if args.full:
        return list(range(1, 65536))
    if args.range:
        lo, hi = args.range.split("-")
        return list(range(int(lo), int(hi) + 1))
    if args.ports:
        return [int(p) for p in args.ports.split(",")]
    return COMMON_PORTS


def main():
    parser = argparse.ArgumentParser(description="TCP 端口扫描器 + FTP 识别")
    parser.add_argument("host", help="目标 IP / 主机名")
    parser.add_argument("--full", action="store_true", help="扫 1-65535 全端口")
    parser.add_argument("--range", help="端口范围, 如 1-10000")
    parser.add_argument("--ports", help="指定端口列表, 如 21,22,2121")
    parser.add_argument("--workers", type=int, default=500, help="并发线程数")
    parser.add_argument("--timeout", type=float, default=0.8, help="单端口超时秒数")
    args = parser.parse_args()

    ports = parse_ports(args)
    print(f"[*] 目标: {args.host}")
    print(f"[*] 扫描端口数: {len(ports)}")
    print(f"[*] 并发: {args.workers}, 超时: {args.timeout}s")
    print(f"[*] 开始时间: {datetime.now().strftime('%H:%M:%S')}")
    print("-" * 60)

    open_ports: list[tuple[int, str]] = []
    ftp_candidates: list[tuple[int, str]] = []

    # 用线程池并发扫描，对端口扫描这种 IO 密集型任务非常合适
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_port, args.host, p, args.timeout): p for p in ports}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            port, is_open, banner = fut.result()
            if is_open:
                open_ports.append((port, banner))
                # FTP 标志: 响应以 "220" 开头, 或 banner 里有 FTP / FileZilla / vsftpd
                banner_lower = banner.lower()
                if (banner.startswith("220") or "ftp" in banner_lower
                        or "filezilla" in banner_lower or "vsftpd" in banner_lower
                        or "proftpd" in banner_lower or "pure-ftpd" in banner_lower):
                    ftp_candidates.append((port, banner))
                    print(f"[+] {port:>5}  开放  [FTP?] {banner[:120]}")
                else:
                    print(f"[+] {port:>5}  开放  {banner[:120]}")
            # 进度提示（每 1000 个端口打一次）
            if i % 1000 == 0:
                print(f"    ... {i}/{len(ports)} 已扫描", file=sys.stderr)

    print("-" * 60)
    print(f"[*] 完成时间: {datetime.now().strftime('%H:%M:%S')}")
    print(f"[*] 开放端口共 {len(open_ports)} 个")
    if ftp_candidates:
        print(f"\n[!] 发现 FTP 候选端口:")
        for port, banner in ftp_candidates:
            print(f"    - {args.host}:{port}  {banner[:200]}")
        print(f"\n[*] 下一步: python ftp_explorer.py {args.host} {ftp_candidates[0][0]}")
    else:
        print("\n[!] 未发现明显的 FTP 服务")
        if not args.full:
            print("    建议尝试全端口扫描: python scanner.py {} --full".format(args.host))


if __name__ == "__main__":
    main()
