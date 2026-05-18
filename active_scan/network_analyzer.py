"""
网络环境一键诊断工具
复刻 "校园网做了什么" 那份分析报告的全套测试：
  - 双层 NAT 检测（traceroute 分析）
  - DNS 投毒对比（多家 DNS 横向查同一批域名）
  - 端口封锁清单（SMTP/DoT/BT/NTP 等）
  - IPv6 可达性
  - HTTP 明文注入 / Captive Portal 检测
  - MTU 完整性（DF 位 ping 二分）
  - 公网 IP / 本机接口信息

纯 Python 标准库，无需 pip install。
Windows 10+ / macOS / Linux 通用。
用法：python network_analyzer.py
"""

import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# ============================================================
# 终端配色 —— 让报告可读
# ============================================================

# Windows 需要显式启用 VT100 才能渲染 ANSI 转义序列
if sys.platform == "win32":
    os.system("")  # 空 system() 调用会让 Win10+ 的终端切到 VT 模式
    # 旧 cmd.exe 的默认编码是 GBK，强制切 UTF-8 避免中文乱码
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

def hdr(text: str) -> None:
    """大标题"""
    bar = "─" * 72
    print(f"\n{C.CYAN}{bar}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {text}{C.RESET}")
    print(f"{C.CYAN}{bar}{C.RESET}")

def sub(text: str) -> None:
    """小节标题"""
    print(f"\n{C.BOLD}▸ {text}{C.RESET}")

def ok(text: str) -> None:
    print(f"  {C.GREEN}✓{C.RESET} {text}")

def warn(text: str) -> None:
    print(f"  {C.YELLOW}!{C.RESET} {text}")

def bad(text: str) -> None:
    print(f"  {C.RED}✗{C.RESET} {text}")

def info(text: str) -> None:
    print(f"  {C.GRAY}·{C.RESET} {text}")


# ============================================================
# 数据容器 —— 最后统一生成报告
# ============================================================

@dataclass
class Report:
    local_ips: list = field(default_factory=list)
    gateways: list = field(default_factory=list)
    system_dns: list = field(default_factory=list)
    public_ipv4: Optional[str] = None
    public_ipv6: Optional[str] = None
    hops: list = field(default_factory=list)  # traceroute 每一跳
    nat_layers: int = 0
    dns_table: dict = field(default_factory=dict)  # domain -> {server: [ips]}
    port_results: list = field(default_factory=list)  # (label, host, port, open, note)
    ipv6_reachable: Optional[bool] = None
    http_probe: dict = field(default_factory=dict)
    mtu: Optional[int] = None
    network_info: dict = field(default_factory=dict)

R = Report()


# ============================================================
# 工具函数
# ============================================================

def is_private_ip(ip: str) -> bool:
    """判断一个 IP 是否属于私网地址段（含 CGN 100.64/10）"""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return True
        # 100.64.0.0/10 是 RFC 6598 CGN 段，也视作"私网"
        if isinstance(addr, ipaddress.IPv4Address):
            return ipaddress.ip_network("100.64.0.0/10").supernet_of(
                ipaddress.ip_network(f"{ip}/32")
            )
    except ValueError:
        return False
    return False

def run_cmd(args: list, timeout: int = 30) -> str:
    """跑命令并返回 stdout+stderr 字符串。失败时返回空字符串。"""
    try:
        # Windows 下某些命令输出用 GBK；先尝试 utf-8，失败回退
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
        )
        out = result.stdout + result.stderr
        for enc in ("utf-8", "gbk", "cp936", "latin-1"):
            try:
                return out.decode(enc)
            except UnicodeDecodeError:
                continue
        return out.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# ============================================================
# 1. 本机接口 / 网关 / 系统 DNS
# ============================================================

def collect_local_info() -> None:
    sub("本机网络接口")

    # 本机 IP（所有网卡）
    try:
        hostname = socket.gethostname()
        # getaddrinfo 会拿到所有 IPv4/IPv6
        addrs = set()
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                for ai in socket.getaddrinfo(hostname, None, family):
                    ip = ai[4][0].split("%")[0]  # 去掉 IPv6 zone id
                    addrs.add(ip)
            except socket.gaierror:
                pass
        R.local_ips = sorted(addrs)
        for ip in R.local_ips:
            tag = f"{C.YELLOW}[私网]{C.RESET}" if is_private_ip(ip) else f"{C.GREEN}[公网]{C.RESET}"
            info(f"{tag} {ip}")
    except Exception as e:
        warn(f"本机 IP 查询失败：{e}")

    # 从 ipconfig/ip 解析网关和 DNS
    if sys.platform == "win32":
        out = run_cmd(["ipconfig", "/all"])
        gateways = re.findall(r"Default Gateway[^:]*:\s*([\d.:a-fA-F]+)", out)
        dns_servers = re.findall(r"DNS Servers[^:]*:\s*([\d.:a-fA-F]+)", out)
        # 中文系统
        if not gateways:
            gateways = re.findall(r"默认网关[^:]*:\s*([\d.:a-fA-F]+)", out)
        if not dns_servers:
            dns_servers = re.findall(r"DNS 服务器[^:]*:\s*([\d.:a-fA-F]+)", out)
        R.gateways = [g for g in gateways if g and g != "0.0.0.0"]
        R.system_dns = [d for d in dns_servers if d]
    else:
        # Unix: 尝试 /etc/resolv.conf 和 ip route
        try:
            with open("/etc/resolv.conf") as f:
                R.system_dns = re.findall(r"nameserver\s+(\S+)", f.read())
        except OSError:
            pass
        out = run_cmd(["ip", "route", "show", "default"])
        R.gateways = re.findall(r"default via (\S+)", out)

    for g in R.gateways:
        info(f"默认网关：{C.CYAN}{g}{C.RESET}")
    for d in R.system_dns:
        info(f"系统 DNS：{C.CYAN}{d}{C.RESET}")


# ============================================================
# 2. 公网 IP（IPv4 + IPv6）
# ============================================================

def http_get(url: str, timeout: float = 5.0) -> Optional[str]:
    """极简 HTTP GET，返回文本 body。失败返回 None。"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "network-analyzer/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
        return None

def detect_public_ip() -> None:
    sub("公网 IP 探测")

    # IPv4
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipv4.icanhazip.com"):
        ip = http_get(url, timeout=6)
        if ip:
            ip = ip.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                R.public_ipv4 = ip
                ok(f"公网 IPv4：{C.BOLD}{ip}{C.RESET}  (via {url})")
                break
    if not R.public_ipv4:
        bad("公网 IPv4 获取失败——可能整个出站都被卡，或者 ipify/ifconfig 都被封了")

    # IPv6
    for url in ("https://api6.ipify.org", "https://ipv6.icanhazip.com"):
        ip = http_get(url, timeout=4)
        if ip:
            ip = ip.strip()
            if ":" in ip:
                R.public_ipv6 = ip
                ok(f"公网 IPv6：{C.BOLD}{ip}{C.RESET}")
                R.ipv6_reachable = True
                break
    if not R.public_ipv6:
        warn("公网 IPv6 获取失败——链路可能没有 v6，或被禁")
        R.ipv6_reachable = False


# ============================================================
# 3. Traceroute —— 看 NAT 层数和骨干跳点
# ============================================================

def run_traceroute(target: str = "1.1.1.1") -> None:
    """
    跑 traceroute 并分析：
      - 前几跳是不是私网（判断 NAT 层数）
      - 中间是不是一堆 * * *（判断有没有 ICMP TTL exceeded 被丢）
      - 第一个公网跳点是谁
    """
    sub(f"路径追踪（目标 {target}）")

    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", "20", "-w", "1500", target]
    else:
        cmd = ["traceroute", "-n", "-w", "2", "-m", "20", target]

    print(f"  {C.DIM}跑命令：{' '.join(cmd)}  (约 30-60 秒){C.RESET}")
    out = run_cmd(cmd, timeout=120)
    if not out:
        bad("traceroute 未能执行（可能缺权限或该命令不存在）")
        return

    # 通用解析：抓每一行里的跳号 + IP
    hops = []
    for line in out.splitlines():
        # 匹配形如 " 1    2 ms    1 ms    1 ms  10.215.0.1" 或 " 3  * * *  Request timed out"
        m = re.match(r"\s*(\d+)\s+(.+)", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)", rest)
        if ip_match:
            ip = ip_match.group(1)
            hops.append((hop_num, ip, "private" if is_private_ip(ip) else "public"))
        else:
            # 全是 * —— 被静默丢了
            if "*" in rest:
                hops.append((hop_num, None, "timeout"))

    R.hops = hops

    # 分析：统计前几跳是私网
    nat_layers = 0
    first_public = None
    timeout_streak = 0
    max_timeout_streak = 0
    for hop_num, ip, kind in hops:
        if kind == "private":
            nat_layers = max(nat_layers, hop_num)
        if kind == "public" and first_public is None:
            first_public = (hop_num, ip)
        if kind == "timeout":
            timeout_streak += 1
            max_timeout_streak = max(max_timeout_streak, timeout_streak)
        else:
            timeout_streak = 0
    R.nat_layers = nat_layers

    for hop_num, ip, kind in hops:
        if kind == "private":
            print(f"  {C.YELLOW}{hop_num:>3}{C.RESET}  {ip:<40} {C.YELLOW}[私网 NAT]{C.RESET}")
        elif kind == "timeout":
            print(f"  {C.GRAY}{hop_num:>3}  * * *{' ' * 34}[静默丢弃]{C.RESET}")
        else:
            print(f"  {C.GREEN}{hop_num:>3}{C.RESET}  {ip:<40} {C.GREEN}[公网]{C.RESET}")

    if nat_layers >= 2:
        warn(f"检测到至少 {C.BOLD}{nat_layers} 层 NAT{C.RESET}——出口公网端口基本不可用")
        info("现实影响：无法开服务 / 反向代理 / P2P 直连")
    elif nat_layers == 1:
        info(f"检测到 1 层 NAT（家用路由器典型情况）")

    if max_timeout_streak >= 3:
        warn(f"中间有连续 {max_timeout_streak} 跳 * * *——骨干对 ICMP TTL exceeded 做了静默丢弃")

    if first_public:
        ok(f"第一个公网跳点：第 {first_public[0]} 跳 {C.BOLD}{first_public[1]}{C.RESET}")


# ============================================================
# 4. DNS 投毒对比 —— 复刻那张三列表
# ============================================================

# 自己发一个 DNS 查询包（UDP 53），避免依赖 nslookup 输出格式
def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """构造一个最小化的 DNS 查询报文"""
    tid = os.urandom(2)
    flags = b"\x01\x00"  # 标准查询，期望递归
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # QDCOUNT=1
    # QNAME: 每段前加长度字节，结尾 0x00
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in domain.split(".")
    ) + b"\x00"
    qtype_b = qtype.to_bytes(2, "big")
    qclass = b"\x00\x01"  # IN
    return tid + flags + counts + qname + qtype_b + qclass

def parse_dns_answers(pkt: bytes, qtype: int = 1) -> list:
    """简化的 DNS 响应解析，只提取答案段里的 A/AAAA 记录"""
    if len(pkt) < 12:
        return []
    # 跳过头（12 字节）
    ancount = int.from_bytes(pkt[6:8], "big")
    # 跳过 question 段
    i = 12
    while i < len(pkt) and pkt[i] != 0:
        i += pkt[i] + 1
    i += 1 + 4  # 跳过 QNAME 结尾 0x00 + QTYPE + QCLASS

    results = []
    for _ in range(ancount):
        if i >= len(pkt):
            break
        # NAME：可能是指针（最高两位 11）或正常 label
        if pkt[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while i < len(pkt) and pkt[i] != 0:
                i += pkt[i] + 1
            i += 1
        if i + 10 > len(pkt):
            break
        rtype = int.from_bytes(pkt[i:i+2], "big")
        rdlen = int.from_bytes(pkt[i+8:i+10], "big")
        rdata = pkt[i+10:i+10+rdlen]
        if rtype == 1 and rdlen == 4:  # A
            results.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and rdlen == 16:  # AAAA
            results.append(":".join(f"{rdata[j]*256+rdata[j+1]:x}" for j in range(0, 16, 2)))
        i += 10 + rdlen
    return results

def dns_query_udp(server: str, domain: str, qtype: int = 1, timeout: float = 3.0) -> list:
    """通过 UDP 53 向指定 DNS 服务器查询，返回解析到的 IP 列表；超时或失败返回空列表。"""
    try:
        pkt = build_dns_query(domain, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (server, 53))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_answers(resp, qtype)
    except (socket.timeout, socket.gaierror, OSError):
        return []

def dns_compare() -> None:
    """
    对关键域名在多家 DNS 服务器做并发解析，对比返回值，检测投毒。
    """
    sub("DNS 投毒对比（多家解析器横向比对）")

    # 关键域名 —— 第一组是被墙常见名单，最后一个 baidu 作为对照
    domains = [
        "www.google.com",
        "twitter.com",
        "facebook.com",
        "youtube.com",
        "www.wikipedia.org",
        "www.baidu.com",  # 对照组
    ]

    # 解析器清单。系统默认用 R.system_dns 的第一个，其余都是公共服务器。
    resolvers = []
    if R.system_dns:
        resolvers.append(("系统", R.system_dns[0]))
    resolvers += [
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("AliDNS", "223.5.5.5"),
        ("DNSPod", "119.29.29.29"),
    ]

    # 并发查询
    tasks = [(rname, rip, dom) for rname, rip in resolvers for dom in domains]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = {
            pool.submit(dns_query_udp, rip, dom): (rname, rip, dom)
            for rname, rip, dom in tasks
        }
        results = {}
        for fut in concurrent.futures.as_completed(futures):
            rname, rip, dom = futures[fut]
            ips = fut.result()
            results.setdefault(dom, {})[rname] = ips

    R.dns_table = results

    # 打印对比表
    col_w = 22
    header = "  " + "域名".ljust(22)
    for rname, _ in resolvers:
        header += rname.ljust(col_w)
    print(f"\n{C.BOLD}{header}{C.RESET}")
    print("  " + "─" * (22 + col_w * len(resolvers)))

    for dom in domains:
        row = "  " + dom.ljust(22)
        for rname, _ in resolvers:
            ips = results.get(dom, {}).get(rname, [])
            if not ips:
                cell = f"{C.RED}超时/失败{C.RESET}".ljust(col_w + len(C.RED) + len(C.RESET))
            else:
                # 只显示第一个 IP，多的用 +N 标注
                shown = ips[0]
                if len(ips) > 1:
                    shown += f" +{len(ips)-1}"
                # 粗粗判断：被墙域名解析到私网/保留地址是投毒
                if any(is_private_ip(ip) for ip in ips):
                    cell = f"{C.RED}{shown}{C.RESET}".ljust(col_w + len(C.RED) + len(C.RESET))
                else:
                    cell = shown.ljust(col_w)
            row += cell
        print(row)

    # 启发式分析
    print()
    # 找出"不同解析器给出完全不相交的 IP 集合"的域名
    for dom in domains:
        rset = results.get(dom, {})
        # 有效结果（非空）
        valid = {rname: set(ips) for rname, ips in rset.items() if ips}
        failed = [rname for rname, ips in rset.items() if not ips]

        if len(valid) >= 2:
            ip_sets = list(valid.values())
            # 两两检查是否有交集
            disjoint_pairs = 0
            total_pairs = 0
            for i in range(len(ip_sets)):
                for j in range(i+1, len(ip_sets)):
                    total_pairs += 1
                    if not (ip_sets[i] & ip_sets[j]):
                        disjoint_pairs += 1
            if total_pairs > 0 and disjoint_pairs == total_pairs:
                warn(f"{dom}: 所有解析器给出的 IP 两两不相交 —— 强烈疑似 DNS 投毒")

        if "Cloudflare" in failed and "Google" not in failed:
            warn(f"{dom}: Cloudflare (1.1.1.1) 查询失败但 Google DNS 通 —— 1.1.1.1:53 可能被封")


# ============================================================
# 5. 端口封锁清单
# ============================================================

def tcp_probe(host: str, port: int, timeout: float = 3.0) -> tuple:
    """TCP connect 测试。返回 (是否成功, 毫秒数)"""
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.time() - start) * 1000)
    except (socket.timeout, OSError):
        return False, int((time.time() - start) * 1000)

def port_scan() -> None:
    sub("端口封锁清单（TCP connect 实测）")

    # (标签, 目标主机, 端口, 用途说明)
    probes = [
        ("SMTP 明文",        "smtp.163.com",         25,   "明文邮件发送"),
        ("SMTP 提交",        "smtp.gmail.com",       587,  "正规邮件客户端"),
        ("SMTPS",            "smtp.gmail.com",       465,  "加密 SMTP"),
        ("DNS/TCP (Google)", "8.8.8.8",              53,   "TCP 承载 DNS"),
        ("DNS/TCP (CF)",     "1.1.1.1",              53,   "TCP 承载 DNS"),
        ("DoT (Google)",     "8.8.8.8",              853,  "DNS-over-TLS"),
        ("DoT (CF)",         "1.1.1.1",              853,  "DNS-over-TLS"),
        ("HTTPS 国内",       "www.baidu.com",        443,  "对照组"),
        ("HTTPS Google",     "www.google.com",       443,  "外网 HTTPS"),
        ("HTTPS GitHub",     "github.com",           443,  "代码托管"),
        ("SSH GitHub",       "github.com",           22,   "Git over SSH"),
        ("DoH Cloudflare",   "1.1.1.1",              443,  "加密 DNS over HTTPS"),
        ("DoH Google",       "8.8.8.8",              443,  "加密 DNS over HTTPS"),
        ("BT Tracker",       "tracker.opentrackr.org", 6969, "P2P 常用端口"),
        ("NTP/TCP",          "time.nist.gov",        123,  "时间同步（少见 TCP）"),
        ("IRC",              "irc.libera.chat",      6697, "即时聊天 / CTF"),
    ]

    # 并发扫，快
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(probes)) as pool:
        futures = {
            pool.submit(tcp_probe, host, port, 4.0): (label, host, port, note)
            for label, host, port, note in probes
        }
        results = []
        for fut in concurrent.futures.as_completed(futures):
            label, host, port, note = futures[fut]
            is_open, ms = fut.result()
            results.append((label, host, port, is_open, ms, note))

    # 保持原顺序展示
    order = {(lbl, h, p): i for i, (lbl, h, p, _) in enumerate(probes)}
    results.sort(key=lambda r: order[(r[0], r[1], r[2])])
    R.port_results = [(r[0], r[1], r[2], r[3], r[5]) for r in results]

    print(f"\n  {'端口/服务':<22} {'目标':<28} {'状态':<8} {'说明'}")
    print("  " + "─" * 78)
    for label, host, port, is_open, ms, note in results:
        target = f"{host}:{port}"
        if is_open:
            status = f"{C.GREEN}开  ({ms}ms){C.RESET}"
        else:
            status = f"{C.RED}封/拒{C.RESET}"
        print(f"  {label:<22} {target:<28} {status:<24} {C.GRAY}{note}{C.RESET}")

    # 规律分析
    print()
    closed = {(lbl, h, p) for lbl, h, p, o, _ in R.port_results if not o}
    open_ = {(lbl, h, p) for lbl, h, p, o, _ in R.port_results if o}

    # DoT vs DoH 对比
    dot_blocked = any(lbl.startswith("DoT") for lbl, _, _ in closed)
    doh_cf_blocked = ("DoH Cloudflare", "1.1.1.1", 443) in closed
    doh_g_open = ("DoH Google", "8.8.8.8", 443) in open_

    if dot_blocked:
        warn("DoT (853) 被封 —— 加密 DNS 最主流的路径被刻意堵上了")
    if doh_cf_blocked and doh_g_open:
        warn("Cloudflare DoH (1.1.1.1:443) 封 + Google DoH (8.8.8.8:443) 通 —— 精准针对 Cloudflare")
    if ("SMTP 明文", "smtp.163.com", 25) in open_ and ("SMTP 提交", "smtp.gmail.com", 587) in closed:
        warn("25 开 / 587 封的组合反常 —— 上游很可能按应用指纹 (SPI/DPI) 在过滤，不是按端口")


# ============================================================
# 6. HTTP 明文注入 / Captive Portal
# ============================================================

def http_probe() -> None:
    sub("HTTP 明文注入 / Captive Portal 检测")

    # Microsoft NCSI：标准正文应为 "Microsoft Connect Test"（22 字节）
    # 如果被劫持到认证门户，这里会是一大坨 HTML
    url = "http://www.msftconnecttest.com/connecttest.txt"
    body = http_get(url, timeout=6)
    R.http_probe["ncsi_body"] = body
    if body is None:
        bad("NCSI 探测失败 —— 连 Microsoft 的 HTTP 探活都不通，不正常")
    elif body.strip() == "Microsoft Connect Test":
        ok("NCSI 返回标准正文 —— 没有 HTTP 明文注入 / Captive Portal 劫持")
    else:
        snippet = body[:120].replace("\n", " ")
        bad(f"NCSI 正文被篡改：{snippet!r}")
        warn("你可能在一个会劫持 HTTP 的网络里（认证门户 / 广告注入）")

    # Google 204
    url2 = "http://connectivitycheck.gstatic.com/generate_204"
    try:
        req = urllib.request.Request(url2, headers={"User-Agent": "network-analyzer/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.status
            body2 = resp.read()
        R.http_probe["gstatic_code"] = code
        if code == 204 and len(body2) == 0:
            ok("Google generate_204 行为正常 —— HTTP 未被劫持")
        else:
            warn(f"Google generate_204 返回异常：code={code}, len={len(body2)}")
    except Exception as e:
        warn(f"Google generate_204 不可达：{type(e).__name__}")


# ============================================================
# 7. MTU 探测（DF 位 ping 二分）
# ============================================================

def mtu_probe(target: str = "8.8.8.8") -> None:
    sub(f"MTU 探测（DF 位 ping，目标 {target}）")

    def ping_size(size: int) -> bool:
        # Windows: ping -f -l size  /  Unix (Linux/macOS): ping -M do -s size 或 -D -s size
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-f", "-l", str(size), "-w", "1500", target]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-D", "-s", str(size), "-W", "1500", target]
        else:
            cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), "-W", "2", target]
        out = run_cmd(cmd, timeout=5)
        # 失败关键词：Packet needs to be fragmented / Message too long / 100% packet loss
        fail_markers = [
            "needs to be fragmented",
            "需要拆分",
            "Message too long",
            "100% packet loss",
            "100% 丢失",
            "Frag needed",
        ]
        if any(m in out for m in fail_markers):
            return False
        # 成功关键词
        return ("TTL=" in out) or ("ttl=" in out) or ("bytes from" in out)

    # 快速路径：先测 1472 (1500 MTU) 和 1464 (1492 PPPoE MTU)
    # 二分区间：[0, 1472]，payload 大小。实际 MTU = payload + 28 (IP 20 + ICMP 8)
    low, high = 0, 1472
    # 先试试 1472，通了就不用二分
    if ping_size(1472):
        R.mtu = 1500
        ok(f"DF 位 ping 1472 字节成功 —— MTU = {C.BOLD}1500{C.RESET}（完整以太网）")
        return

    # 二分
    info("DF 位 1472 失败，开始二分查找最大可达 payload...")
    best = 0
    while low <= high:
        mid = (low + high) // 2
        if ping_size(mid):
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    R.mtu = best + 28 if best > 0 else None
    if R.mtu:
        warn(f"链路 MTU ≈ {C.BOLD}{R.mtu}{C.RESET}（< 1500，可能是 PPPoE 或 VPN 封装）")
    else:
        bad("MTU 探测失败 —— 可能目标禁 ICMP echo")


# ============================================================
# 8. 最终总结报告 —— 学那份中文报告的口吻
# ============================================================

def final_summary() -> None:
    hdr("综合分析 · 一句话画像")

    conclusions = []

    if R.nat_layers >= 2:
        conclusions.append(
            f"{C.YELLOW}●{C.RESET} 你在 {C.BOLD}{R.nat_layers} 层 NAT{C.RESET} 后面，"
            f"出口没有公网端口。开服务 / 反向代理 / P2P 直连不可行，你只能做客户端。"
        )
    elif R.nat_layers == 1:
        conclusions.append(f"{C.GRAY}●{C.RESET} 1 层 NAT（典型家用场景）")

    # DNS 异常
    poisoned = []
    cf_failed_list = []
    for dom, rset in R.dns_table.items():
        valid = {rname: set(ips) for rname, ips in rset.items() if ips}
        if len(valid) >= 2:
            ip_sets = list(valid.values())
            disjoint = all(
                not (ip_sets[i] & ip_sets[j])
                for i in range(len(ip_sets))
                for j in range(i+1, len(ip_sets))
            )
            if disjoint:
                poisoned.append(dom)
        if "Cloudflare" in rset and not rset["Cloudflare"]:
            cf_failed_list.append(dom)

    if poisoned:
        conclusions.append(
            f"{C.RED}●{C.RESET} 检测到 DNS 投毒迹象：{C.BOLD}{', '.join(poisoned)}{C.RESET} "
            f"在不同解析器得到完全不相交的 IP —— GFW 级别的假应答"
        )
    if len(cf_failed_list) >= 3:
        conclusions.append(
            f"{C.RED}●{C.RESET} Cloudflare (1.1.1.1) 查询大面积失败 —— 53 端口可能被卡掉"
        )

    # 端口
    port_map = {(lbl, h, p): o for lbl, h, p, o, _ in R.port_results}
    dot_open = port_map.get(("DoT (Google)", "8.8.8.8", 853), False) or port_map.get(("DoT (CF)", "1.1.1.1", 853), False)
    doh_cf = port_map.get(("DoH Cloudflare", "1.1.1.1", 443), False)
    doh_g = port_map.get(("DoH Google", "8.8.8.8", 443), False)
    if not dot_open:
        conclusions.append(
            f"{C.RED}●{C.RESET} DoT (853) 全线封禁 —— 想换加密 DNS 躲投毒的路被堵死"
        )
    if not doh_cf and doh_g:
        conclusions.append(
            f"{C.YELLOW}●{C.RESET} Cloudflare DoH 封 / Google DoH 通 —— 封锁是精准针对 Cloudflare，不是禁所有 DoH"
        )

    # IPv6
    if R.ipv6_reachable is False:
        conclusions.append(
            f"{C.YELLOW}●{C.RESET} IPv6 缺席 —— 没 v6 地址或没 v6 路由。"
            f"有些网络会给 v6 留条活路绕开 v4 的墙，值得在本机或路由器确认一下是不是自己关了"
        )
    elif R.ipv6_reachable:
        conclusions.append(f"{C.GREEN}●{C.RESET} 你有可用的 IPv6")

    # MTU
    if R.mtu == 1500:
        conclusions.append(f"{C.GREEN}●{C.RESET} MTU 完整 (1500) —— 链路没被 PPPoE 或中间设备削")
    elif R.mtu and R.mtu < 1500:
        conclusions.append(f"{C.YELLOW}●{C.RESET} MTU = {R.mtu}（<1500），可能走 PPPoE/VPN 封装")

    # HTTP
    ncsi = R.http_probe.get("ncsi_body")
    if ncsi and ncsi.strip() == "Microsoft Connect Test":
        conclusions.append(
            f"{C.GREEN}●{C.RESET} HTTP 明文未被注入 —— 认证是 802.1X/WPA2-Ent 正规方式，"
            f"不是那种低级的 HTTP 重定向门户"
        )

    for c in conclusions:
        print(f"  {c}")

    print()
    # 如果前面几条都命中，就给一个类似原报告的整体画像
    hard_blocks = [R.nat_layers >= 2, bool(poisoned), not dot_open, not doh_cf]
    if sum(hard_blocks) >= 3:
        print(f"  {C.BOLD}画像：这是一张典型的受控网络 —— "
              f"让你做一个安分的客户端。{C.RESET}")
        print(f"  {C.GRAY}出站 80/443/22 随便走，加密 DNS 卡死，"
              f"P2P 堵死，公网可达性归零。{C.RESET}")

    # 保存 JSON 原始数据，方便以后 diff 或者二次处理
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_report.json")
    try:
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "platform": platform.platform(),
            "local_ips": R.local_ips,
            "gateways": R.gateways,
            "system_dns": R.system_dns,
            "public_ipv4": R.public_ipv4,
            "public_ipv6": R.public_ipv6,
            "hops": [{"hop": h, "ip": ip, "kind": k} for h, ip, k in R.hops],
            "nat_layers": R.nat_layers,
            "dns_table": {dom: {r: ips for r, ips in d.items()} for dom, d in R.dns_table.items()},
            "ports": [
                {"label": l, "host": h, "port": p, "open": o, "note": n}
                for l, h, p, o, n in R.port_results
            ],
            "ipv6_reachable": R.ipv6_reachable,
            "mtu": R.mtu,
            "http_probe": {k: (v[:200] if isinstance(v, str) else v) for k, v in R.http_probe.items()},
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"\n  {C.GRAY}原始数据已保存到：{report_path}{C.RESET}")
    except OSError as e:
        warn(f"保存 JSON 失败：{e}")


# ============================================================
# 主流程
# ============================================================

def main() -> None:
    hdr("网络环境一键诊断")
    print(f"  {C.GRAY}时间：{time.strftime('%Y-%m-%d %H:%M:%S')}   平台：{platform.platform()}{C.RESET}")

    try:
        collect_local_info()
        detect_public_ip()
        run_traceroute("1.1.1.1")
        dns_compare()
        port_scan()
        http_probe()
        mtu_probe("8.8.8.8")
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}被中断。已有的结果会进总结。{C.RESET}")

    final_summary()
    print()


if __name__ == "__main__":
    main()
