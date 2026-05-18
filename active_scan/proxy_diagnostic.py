"""
代理失灵诊断工具：对比"直连"与"经过代理"在校园网下的行为差异，
判断校园网对你两个代理做了什么（端口封 / SNI 识别 / TLS 指纹 / QoS / 主动 RST…）。

用法：
  1. 编辑下方 PROXIES 配置，把两个代理的远端服务器和本地监听端口填进去
  2. 确保两个代理客户端都在运行（Clash / v2rayN / sing-box 等）
  3. python proxy_diagnostic.py

测试分两部分：
  Part A —— 到代理服务器 IP:端口 的底层行为（TCP / TLS / UDP / traceroute）
  Part B —— 经过本地代理端口发真实 HTTP 请求（测代理链路是否能用、速度如何）

输出会保存到 proxy_diag_report.json 方便后续比对。
纯 Python 标准库，无需 pip install。
"""

import concurrent.futures
import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
# 【配置区】—— 把你的两个代理信息填进去
# ============================================================
#
# 字段说明：
#   name         代理起个名字，只用于显示
#   server       代理服务器的【远端】地址（域名或 IP）。例如 vps.example.com
#                → 留空会跳过 Part A（但 Part B 仍可测）
#   port         代理服务器的【远端】端口。例如 443、8443
#   protocol     "tls"（VLESS+TLS / Trojan / VMess+TLS 都算）/ "plain"（明文如 SS）/ "udp"（Hysteria / TUIC / WG）
#   sni          TLS 握手时客户端发送的 SNI。VLESS+TLS 通常填伪装域名，如 "www.apple.com"
#                → 只有 protocol="tls" 时才用
#   local_http   本地 HTTP 代理地址（含端口）。Clash 默认 "127.0.0.1:7890"
#                → 留空会跳过 Part B
#
# 两个代理都填完，脚本会跑完整对比。只填一个也能跑，另一个会被跳过。

PROXIES = [
    {
        "name":       "代理 A",
        "server":     "",                    # TODO: 填远端服务器，例如 "example.com" 或 "1.2.3.4"
        "port":       443,                   # TODO: 填远端端口
        "protocol":   "tls",                 # tls / plain / udp
        "sni":        "",                    # TODO: TLS 握手的 SNI（留空则用 server）
        "local_http": "127.0.0.1:7890",      # TODO: 本地 HTTP 代理端口
    },
    {
        "name":       "代理 B",
        "server":     "",                    # TODO: 填远端服务器
        "port":       443,                   # TODO: 填远端端口
        "protocol":   "tls",
        "sni":        "",                    # TODO
        "local_http": "127.0.0.1:7892",      # TODO: 第二个代理的本地 HTTP 端口（注意要和 A 不同）
    },
]

# Part B 用来测试真实流量的目标站点。不要改太多，6 个左右就够
HTTP_TARGETS = [
    "https://www.google.com/generate_204",   # Google 204，轻量
    "https://www.youtube.com/",              # YouTube 首页
    "https://github.com/",                   # GitHub（国内通）
    "https://www.cloudflare.com/",           # Cloudflare（看 CF 通路）
    "https://twitter.com/",                  # 墙外
    "https://www.baidu.com/",                # 对照组
]

# 持续下载测试用的文件（代理通路压力测试）
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=5242880"  # 5 MB


# ============================================================
# 终端配色
# ============================================================

if sys.platform == "win32":
    os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
    BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"; GRAY = "\033[90m"

def hdr(text):
    bar = "═" * 72
    print(f"\n{C.CYAN}{bar}{C.RESET}\n{C.BOLD}{C.CYAN}  {text}{C.RESET}\n{C.CYAN}{bar}{C.RESET}")
def sub(text):     print(f"\n{C.BOLD}▸ {text}{C.RESET}")
def ok(t):         print(f"  {C.GREEN}✓{C.RESET} {t}")
def warn(t):       print(f"  {C.YELLOW}!{C.RESET} {t}")
def bad(t):        print(f"  {C.RED}✗{C.RESET} {t}")
def info(t):       print(f"  {C.GRAY}·{C.RESET} {t}")


# ============================================================
# 结果容器
# ============================================================

@dataclass
class ScenarioResult:
    """一个场景（直连 / 代理 A / 代理 B）的所有测试数据"""
    label: str                                    # "直连" / "代理 A" ...
    # --- Part A: 对远端服务器的底层行为 ---
    server: Optional[str] = None
    server_resolved_ip: Optional[str] = None
    ping_loss: Optional[float] = None             # 百分比
    ping_rtt_avg: Optional[float] = None          # 毫秒
    ping_rtt_jitter: Optional[float] = None       # 毫秒
    tcp_success_rate: Optional[float] = None      # 0~1
    tcp_connect_ms: list = field(default_factory=list)
    tcp_hold_seconds: Optional[float] = None      # 一条连接能存活多久
    tls_real_sni: dict = field(default_factory=dict)
    tls_decoy_sni: dict = field(default_factory=dict)
    tls_repeat: list = field(default_factory=list)   # 连做 5 次 TLS 握手的成功/耗时
    udp_reach: Optional[str] = None
    traceroute_hops: int = 0
    # --- Part B: 经过本地代理的真实流量 ---
    http_results: list = field(default_factory=list)  # [(url, ok, ttfb_ms, bytes, err), ...]
    speed_kbps: Optional[float] = None
    speed_stalls: int = 0                             # 下载过程中停顿次数


# ============================================================
# 工具：子进程 / DNS 解析
# ============================================================

def run_cmd(args, timeout=30):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        raw = r.stdout + r.stderr
        for enc in ("utf-8", "gbk", "cp936", "latin-1"):
            try: return raw.decode(enc)
            except UnicodeDecodeError: continue
        return raw.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# ============================================================
# Part A1: ICMP ping —— 丢包率 + RTT 抖动
# ============================================================

def test_icmp_ping(host, count=10):
    """返回 (loss_pct, rtt_avg_ms, rtt_jitter_ms)"""
    if sys.platform == "win32":
        cmd = ["ping", "-n", str(count), "-w", "2000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    out = run_cmd(cmd, timeout=count * 3 + 5)
    if not out:
        return None, None, None

    # 抓所有 time=XXms
    rtts = [float(m) for m in re.findall(r"time[=<](\d+\.?\d*)\s*ms", out)]
    # 丢包率
    sent = count
    recv = len(rtts)
    loss = (sent - recv) / sent * 100 if sent else 100.0
    rtt_avg = statistics.mean(rtts) if rtts else None
    rtt_jit = statistics.stdev(rtts) if len(rtts) >= 2 else 0.0
    return loss, rtt_avg, rtt_jit


# ============================================================
# Part A2: TCP 连接成功率 + 握手延迟
# ============================================================

def test_tcp_connect(host, port, rounds=10, timeout=4.0):
    """连续 N 次 TCP 握手，返回 (成功率, 每次耗时列表ms)"""
    times = []
    successes = 0
    for _ in range(rounds):
        start = time.time()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            times.append(int((time.time() - start) * 1000))
            successes += 1
        except (socket.timeout, OSError):
            times.append(None)
        time.sleep(0.2)  # 避免太快被防火墙视为扫描
    rate = successes / rounds
    return rate, times


# ============================================================
# Part A3: TCP 连接保持时长 —— 检测主动 RST
# ============================================================

def test_tcp_hold(host, port, max_seconds=20, timeout=4.0):
    """
    建立 TCP 连接后保持空闲，看多久被关掉。
    校园网如果对"疑似代理连接"做主动 RST，这里会测到明显短于 max_seconds 的存活时间。
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(1.0)
        start = time.time()
        while time.time() - start < max_seconds:
            try:
                data = s.recv(1)
                if not data:
                    # 对端发了 FIN
                    s.close()
                    return time.time() - start
            except socket.timeout:
                # 连接还活着
                continue
            except OSError:
                # RST
                return time.time() - start
        s.close()
        return max_seconds  # 全程没事
    except (socket.timeout, OSError):
        return 0.0


# ============================================================
# Part A4/A5: TLS 握手，真 SNI vs 伪装 SNI
# ============================================================

def test_tls_handshake(host, port, sni, timeout=6.0):
    """
    返回 dict: {ok: bool, handshake_ms: int, error: str, peer_cert: str}
    peer_cert 是服务器证书的主题（方便你看到底连到谁了）
    """
    start = time.time()
    result = {"ok": False, "handshake_ms": 0, "error": None, "peer_cert": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # 我们只关心握手能否通，不校验
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        ssock = ctx.wrap_socket(raw, server_hostname=sni or host)
        cert = ssock.getpeercert(binary_form=False)  # 此处 cert 为空（因为 CERT_NONE）
        # 再取一次 DER 证书抽 subject
        try:
            der = ssock.getpeercert(binary_form=True)
            if der:
                import hashlib
                fp = hashlib.sha256(der).hexdigest()[:16]
                result["peer_cert"] = f"SHA256:{fp}"
        except Exception:
            pass
        result["ok"] = True
        result["handshake_ms"] = int((time.time() - start) * 1000)
        ssock.close()
    except ssl.SSLError as e:
        result["error"] = f"SSL: {e.reason or str(e)}"
        result["handshake_ms"] = int((time.time() - start) * 1000)
    except (socket.timeout, OSError) as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["handshake_ms"] = int((time.time() - start) * 1000)
    return result


def test_tls_repeat(host, port, sni, times=5, interval=0.5):
    """连做 N 次 TLS 握手。校园网某些设备会首握成功，后续拉黑 IP。"""
    results = []
    for i in range(times):
        r = test_tls_handshake(host, port, sni, timeout=6.0)
        results.append((r["ok"], r["handshake_ms"], r.get("error")))
        time.sleep(interval)
    return results


# ============================================================
# Part A6: UDP 可达性粗测
# ============================================================

def test_udp_port(host, port, attempts=5, timeout=3.0):
    """
    向 host:port 发 UDP，用 ICMP 不可达 / 超时 / 无响应来判断。
    浏览器代理协议（Hysteria/TUIC/WG/QUIC）都是 UDP，校园网常见 QoS 先砍。
    返回字符串描述。
    """
    ip = resolve_host(host)
    if not ip:
        return "DNS 解析失败"

    responses = 0
    timeouts = 0
    errors = 0
    for _ in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"\x00" * 16, (ip, port))
            try:
                s.recvfrom(1024)
                responses += 1
            except socket.timeout:
                timeouts += 1
            s.close()
        except OSError as e:
            # Windows 对封闭端口返回 WSAECONNRESET（ICMP 不可达被内核映射）
            if "10054" in str(e) or "Connection refused" in str(e) or "unreachable" in str(e).lower():
                errors += 1
            else:
                errors += 1
        time.sleep(0.2)

    if responses >= 1:
        return f"有应答 ({responses}/{attempts}) —— UDP 通"
    if errors >= attempts - 1:
        return f"ICMP 不可达 ({errors}/{attempts}) —— 端口关/IP 封"
    if timeouts >= attempts - 1:
        return f"全超时 ({timeouts}/{attempts}) —— 可能被静默丢弃 (UDP 限速/QoS)"
    return f"混合 (应答 {responses} / 超时 {timeouts} / 错误 {errors})"


# ============================================================
# Part A7: traceroute 到代理服务器
# ============================================================

def test_traceroute_hops(host, max_hops=20):
    """跑一次 tracert，返回能看到的跳数和最后一跳是否到达"""
    if sys.platform == "win32":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1500", host]
    else:
        cmd = ["traceroute", "-n", "-w", "2", "-m", str(max_hops), host]
    out = run_cmd(cmd, timeout=max_hops * 4)
    if not out:
        return 0
    # 简单数一下有多少行带 IP
    lines = [l for l in out.splitlines() if re.search(r"\d+\.\d+\.\d+\.\d+", l)]
    return len(lines)


# ============================================================
# Part B: 通过本地 HTTP 代理发请求
# ============================================================

def http_get_via(local_proxy, url, timeout=8.0, read_body=True):
    """
    local_proxy 形如 "127.0.0.1:7890"。留空就是直连。
    返回 dict: {ok, status, ttfb_ms, total_ms, bytes, error}
    """
    res = {"ok": False, "status": None, "ttfb_ms": 0, "total_ms": 0, "bytes": 0, "error": None}
    if local_proxy:
        proxy_handler = urllib.request.ProxyHandler({
            "http":  f"http://{local_proxy}",
            "https": f"http://{local_proxy}",
        })
        opener = urllib.request.build_opener(proxy_handler)
    else:
        # 显式禁用系统代理
        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)

    start = time.time()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (proxy-diag)"}
        )
        resp = opener.open(req, timeout=timeout)
        res["status"] = resp.status
        # TTFB 近似：首次 read 之前
        res["ttfb_ms"] = int((time.time() - start) * 1000)
        if read_body:
            body = resp.read()
            res["bytes"] = len(body)
        res["total_ms"] = int((time.time() - start) * 1000)
        res["ok"] = 200 <= resp.status < 400 or resp.status == 204
    except urllib.error.HTTPError as e:
        res["status"] = e.code
        res["error"] = f"HTTP {e.code}"
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    return res


def run_http_batch(local_proxy, urls):
    out = []
    for url in urls:
        r = http_get_via(local_proxy, url, timeout=10)
        out.append({
            "url": url, "ok": r["ok"], "status": r["status"],
            "ttfb_ms": r["ttfb_ms"], "bytes": r["bytes"], "error": r["error"]
        })
    return out


def run_speed_test(local_proxy, url=SPEED_TEST_URL):
    """下载 5 MB，测平均速度 + 停顿次数。"""
    if local_proxy:
        proxy_handler = urllib.request.ProxyHandler({
            "http":  f"http://{local_proxy}",
            "https": f"http://{local_proxy}",
        })
    else:
        proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (proxy-diag)"})
        resp = opener.open(req, timeout=10)
    except Exception as e:
        return None, 0, f"{type(e).__name__}: {e}"

    total = 0
    stalls = 0
    last_byte_time = time.time()
    start = time.time()
    try:
        while True:
            now = time.time()
            if now - start > 30:
                break
            chunk = resp.read(16384)
            if not chunk:
                break
            if time.time() - last_byte_time > 1.5:
                stalls += 1
            last_byte_time = time.time()
            total += len(chunk)
    except Exception as e:
        return None, stalls, f"中断: {type(e).__name__}: {e}"

    elapsed = time.time() - start
    kbps = (total / elapsed) / 1024 if elapsed > 0 else 0
    return kbps, stalls, None


# ============================================================
# 场景执行器：跑完一个代理（或直连）的全套测试
# ============================================================

def run_scenario(proxy_cfg, is_direct=False):
    """
    proxy_cfg: PROXIES 里的一项；is_direct=True 时只跑 Part B，不经代理
    返回 ScenarioResult
    """
    label = "直连" if is_direct else proxy_cfg["name"]
    R = ScenarioResult(label=label)

    # ---- Part A（直连模式下跳过，只有测代理才需要） ----
    if not is_direct and proxy_cfg.get("server"):
        server = proxy_cfg["server"]
        port = proxy_cfg["port"]
        proto = proxy_cfg.get("protocol", "tls")
        sni_real = proxy_cfg.get("sni") or server

        R.server = server
        R.server_resolved_ip = resolve_host(server)

        sub(f"[{label}] Part A · 到代理服务器 {server}:{port} 的底层行为")
        if R.server_resolved_ip:
            info(f"DNS 解析：{server} → {C.CYAN}{R.server_resolved_ip}{C.RESET}")
        else:
            bad(f"DNS 解析 {server} 失败 —— 可能被 DNS 投毒到不可达地址")

        # A1 ping
        print(f"  {C.DIM}跑 ICMP ping（10 次）...{C.RESET}")
        loss, avg, jit = test_icmp_ping(server, count=10)
        R.ping_loss = loss; R.ping_rtt_avg = avg; R.ping_rtt_jitter = jit
        if loss is None:
            bad("ping 未能执行")
        elif loss == 100:
            bad(f"100% 丢包 —— ICMP 到代理服务器完全不通（可能禁 ping 或 IP 被封）")
        elif loss > 0:
            warn(f"ICMP 丢包 {loss:.0f}% · 平均 RTT {avg:.1f}ms · 抖动 {jit:.1f}ms")
        else:
            ok(f"ICMP 通畅 · 平均 RTT {avg:.1f}ms · 抖动 {jit:.1f}ms")

        # A2 TCP 握手成功率
        print(f"  {C.DIM}跑 TCP 连接测试（10 次）...{C.RESET}")
        rate, times = test_tcp_connect(server, port, rounds=10)
        R.tcp_success_rate = rate
        R.tcp_connect_ms = times
        good_times = [t for t in times if t is not None]
        if rate == 0:
            bad(f"TCP {port} 端口 0% 可达 —— 端口级封锁")
        elif rate < 1.0:
            warn(f"TCP 握手成功率 {rate*100:.0f}% —— 间歇性丢包/封锁")
        else:
            avg_ms = statistics.mean(good_times) if good_times else 0
            jit_ms = statistics.stdev(good_times) if len(good_times) >= 2 else 0
            ok(f"TCP 100% 可达 · 平均 {avg_ms:.0f}ms · 抖动 {jit_ms:.0f}ms")

        # A3 TCP 保持连接时长
        if rate > 0:
            print(f"  {C.DIM}保持 TCP 连接 20 秒看是否被 RST...{C.RESET}")
            hold = test_tcp_hold(server, port, max_seconds=20)
            R.tcp_hold_seconds = hold
            if hold >= 19:
                ok(f"TCP 连接保持 20 秒无事 —— 没有主动 RST")
            elif hold >= 5:
                warn(f"TCP 连接仅保持 {hold:.1f} 秒后被关 —— 可疑")
            else:
                bad(f"TCP 连接 {hold:.1f} 秒内被中断 —— 强烈疑似主动 RST")

        # A4/A5 TLS 握手（真 SNI + 伪装 SNI）
        if proto == "tls" and rate > 0:
            print(f"  {C.DIM}TLS 握手测试（真 SNI = {sni_real}）...{C.RESET}")
            R.tls_real_sni = test_tls_handshake(server, port, sni_real)
            if R.tls_real_sni["ok"]:
                ok(f"TLS 真 SNI 握手成功（{R.tls_real_sni['handshake_ms']}ms · {R.tls_real_sni.get('peer_cert')}）")
            else:
                bad(f"TLS 真 SNI 握手失败：{R.tls_real_sni.get('error')}")

            # 换一个 SNI（常见伪装域名）看看是不是 SNI 拦截
            decoy_sni = "www.bing.com" if sni_real != "www.bing.com" else "www.apple.com"
            print(f"  {C.DIM}TLS 握手测试（伪装 SNI = {decoy_sni}）...{C.RESET}")
            R.tls_decoy_sni = test_tls_handshake(server, port, decoy_sni)
            if R.tls_decoy_sni["ok"]:
                ok(f"TLS 伪装 SNI 握手成功（{R.tls_decoy_sni['handshake_ms']}ms）")
            else:
                info(f"TLS 伪装 SNI 握手失败：{R.tls_decoy_sni.get('error')}")

            # SNI 对比分析
            if R.tls_real_sni["ok"] and not R.tls_decoy_sni["ok"]:
                info(f"真 SNI 通 / 伪装 SNI 不通 —— 是服务器要求 SNI 匹配（正常）")
            elif not R.tls_real_sni["ok"] and R.tls_decoy_sni["ok"]:
                warn(f"真 SNI 不通 / 伪装 SNI 通 —— {C.BOLD}校园网按 SNI 做关键词阻断{C.RESET}")
            elif not R.tls_real_sni["ok"] and not R.tls_decoy_sni["ok"]:
                warn(f"两种 SNI 都不通 —— 可能是 TLS 指纹识别 / 端口被封 / IP 被墙")

            # A 重复 TLS 握手
            print(f"  {C.DIM}连做 5 次 TLS 握手，看是否触发拉黑...{C.RESET}")
            R.tls_repeat = test_tls_repeat(server, port, sni_real, times=5, interval=0.8)
            successes = sum(1 for s, _, _ in R.tls_repeat if s)
            if successes == 5:
                ok(f"5/5 次 TLS 握手都通 —— 没有触发连续阻断")
            elif successes >= 1:
                warn(f"{successes}/5 次 TLS 握手通 —— {C.BOLD}可能存在主动探测后拉黑{C.RESET}")
                for i, (s, ms, err) in enumerate(R.tls_repeat, 1):
                    status = f"{C.GREEN}通{C.RESET}" if s else f"{C.RED}{err}{C.RESET}"
                    info(f"第 {i} 次：{status} ({ms}ms)")

        # A6 UDP 可达性
        if proto == "udp":
            print(f"  {C.DIM}UDP 端口可达性测试...{C.RESET}")
            R.udp_reach = test_udp_port(server, port, attempts=5)
            info(f"UDP {port}: {R.udp_reach}")

        # A7 traceroute（可选，慢）
        # 默认跳过，取消注释开启
        # print(f"  {C.DIM}traceroute（慢，跳过可在代码里注释）...{C.RESET}")
        # R.traceroute_hops = test_traceroute_hops(server)

    # ---- Part B: 经过本地代理发真实 HTTP 请求 ----
    local_proxy = None if is_direct else proxy_cfg.get("local_http", "")

    if is_direct or local_proxy:
        where = "不经任何代理" if is_direct else f"经 {local_proxy}"
        sub(f"[{label}] Part B · HTTP 流量测试（{where}）")

        # 本地代理端口先探测一下是否真的在跑
        if local_proxy:
            try:
                host, p = local_proxy.split(":")
                s = socket.create_connection((host, int(p)), timeout=2)
                s.close()
                ok(f"本地代理端口 {local_proxy} 在线")
            except OSError:
                bad(f"本地代理端口 {local_proxy} 连不上 —— 代理客户端没跑起来？")
                return R

        # B1: 逐站 HTTP 请求
        print(f"  {C.DIM}请求 {len(HTTP_TARGETS)} 个目标站点...{C.RESET}")
        R.http_results = run_http_batch(local_proxy, HTTP_TARGETS)
        for r in R.http_results:
            url = r["url"]
            short = re.sub(r"^https?://", "", url)[:40]
            if r["ok"]:
                ok(f"{short:<42} {r['status']}  TTFB {r['ttfb_ms']}ms  {r['bytes']} 字节")
            else:
                bad(f"{short:<42} 失败：{r.get('error') or r.get('status')}")

        # B2: 持续下载测速
        print(f"  {C.DIM}下载 5MB 测速...{C.RESET}")
        kbps, stalls, err = run_speed_test(local_proxy)
        R.speed_kbps = kbps
        R.speed_stalls = stalls
        if err:
            bad(f"下载失败：{err}")
        else:
            if kbps and kbps < 100:
                bad(f"下载速度 {kbps:.0f} KB/s · 停顿 {stalls} 次 —— 疑似 QoS 限速")
            elif stalls > 2:
                warn(f"下载速度 {kbps:.0f} KB/s · 停顿 {stalls} 次 —— 链路不稳")
            else:
                ok(f"下载速度 {kbps:.0f} KB/s · 停顿 {stalls} 次")

    return R


# ============================================================
# 横向对比报告
# ============================================================

def cross_report(results):
    hdr("横向对比：三个场景一起看")

    # 每个场景的 Part B 可用性（基于"墙外站点能访问几个"）
    wall_sites = ["google.com", "youtube.com", "twitter.com", "cloudflare.com"]
    inland_sites = ["baidu.com", "github.com"]

    def count_ok(results_list, host_keywords):
        return sum(
            1 for r in results_list
            if r["ok"] and any(kw in r["url"] for kw in host_keywords)
        )

    print(f"\n  {'场景':<12} {'墙外通过':<10} {'国内通过':<10} {'下载速度':<14} {'停顿'}")
    print("  " + "─" * 64)
    for R in results:
        wall_ok = count_ok(R.http_results, wall_sites)
        in_ok = count_ok(R.http_results, inland_sites)
        speed = f"{R.speed_kbps:.0f} KB/s" if R.speed_kbps else "—"
        stalls = R.speed_stalls if R.speed_kbps else "—"
        print(f"  {R.label:<12} {wall_ok}/{len(wall_sites):<10} {in_ok}/{len(inland_sites):<10} {speed:<14} {stalls}")

    # Part A 的代理服务器可达性（直连场景没有 Part A）
    proxy_results = [r for r in results if r.label != "直连"]
    if proxy_results:
        print(f"\n  {'代理':<12} {'TCP 成功率':<12} {'TCP 保活':<12} {'TLS 真SNI':<12} {'TLS 伪SNI':<12}")
        print("  " + "─" * 64)
        for R in proxy_results:
            tcp_rate = f"{R.tcp_success_rate*100:.0f}%" if R.tcp_success_rate is not None else "—"
            hold = f"{R.tcp_hold_seconds:.0f}s" if R.tcp_hold_seconds else "—"
            real = "通" if R.tls_real_sni.get("ok") else "失败"
            decoy = "通" if R.tls_decoy_sni.get("ok") else "失败" if R.tls_decoy_sni else "—"
            print(f"  {R.label:<12} {tcp_rate:<12} {hold:<12} {real:<12} {decoy:<12}")

    # 关键判断 —— 复盘"代理挂在哪一层"
    print(f"\n{C.BOLD}🔍 诊断结论{C.RESET}")

    for R in proxy_results:
        print(f"\n  {C.BOLD}{R.label}{C.RESET}")
        reasons = []

        # 分层定位
        if R.tcp_success_rate == 0:
            reasons.append(f"{C.RED}●{C.RESET} TCP 到服务器端口 0% 成功 → {C.BOLD}端口级封锁或 IP 被墙{C.RESET}。换端口 / 换服务器 IP")
        elif R.tcp_success_rate and R.tcp_success_rate < 0.8:
            reasons.append(f"{C.YELLOW}●{C.RESET} TCP 间歇失败 ({R.tcp_success_rate*100:.0f}%) → 链路质量差或间歇性干扰")

        if R.tcp_hold_seconds is not None and R.tcp_hold_seconds < 5 and R.tcp_success_rate and R.tcp_success_rate > 0:
            reasons.append(f"{C.RED}●{C.RESET} TCP 建立后 {R.tcp_hold_seconds:.0f}s 内被切 → {C.BOLD}主动 RST 干预{C.RESET}")

        real_ok = R.tls_real_sni.get("ok")
        decoy_ok = R.tls_decoy_sni.get("ok") if R.tls_decoy_sni else None

        if R.tcp_success_rate and R.tcp_success_rate > 0 and real_ok is False:
            if decoy_ok:
                reasons.append(f"{C.RED}●{C.RESET} 真 SNI 失败 / 伪 SNI 成功 → {C.BOLD}SNI 黑名单{C.RESET}。"
                               f"代理 SNI 被校园网识别。换个伪装域名（如 www.apple.com / gateway.icloud.com）")
            else:
                reasons.append(f"{C.RED}●{C.RESET} TCP 通但 TLS 失败 → 可能是 {C.BOLD}TLS 指纹识别{C.RESET}（utls 绕过）或对端服务器问题")

        # TLS 重复 5 次的连续性
        if R.tls_repeat:
            succ = sum(1 for s, _, _ in R.tls_repeat if s)
            if 0 < succ < 5:
                reasons.append(f"{C.YELLOW}●{C.RESET} 5 次 TLS 握手只通过 {succ} 次 → 可能 {C.BOLD}主动探测后临时拉黑{C.RESET}")

        # Part B 现象
        wall_ok = sum(1 for r in R.http_results if r["ok"] and any(kw in r["url"] for kw in wall_sites))
        if R.http_results and wall_ok == 0:
            reasons.append(f"{C.RED}●{C.RESET} 墙外网站 0 个能访问 → 代理链路根本没建起来")

        if R.speed_kbps is not None and R.speed_kbps < 100 and R.speed_kbps > 0:
            reasons.append(f"{C.YELLOW}●{C.RESET} 下载仅 {R.speed_kbps:.0f} KB/s → 可能 {C.BOLD}QoS 限速{C.RESET}（常见对加密流量的应对）")

        if R.speed_stalls > 3:
            reasons.append(f"{C.YELLOW}●{C.RESET} 下载过程停顿 {R.speed_stalls} 次 → 链路被间歇性干扰")

        if not reasons:
            if R.tcp_success_rate == 1.0 and real_ok:
                ok(f"底层通路一切正常，代理若仍失灵，问题在代理客户端配置或上层协议")
            else:
                info(f"没有采到数据（是不是 server 字段没填？）")
        else:
            for r in reasons:
                print(f"  {r}")

    # 保存
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_diag_report.json")
    try:
        data = []
        for R in results:
            data.append({
                "label": R.label,
                "server": R.server,
                "server_ip": R.server_resolved_ip,
                "ping": {"loss_pct": R.ping_loss, "rtt_avg_ms": R.ping_rtt_avg, "jitter_ms": R.ping_rtt_jitter},
                "tcp": {"success_rate": R.tcp_success_rate, "connect_ms": R.tcp_connect_ms, "hold_s": R.tcp_hold_seconds},
                "tls_real_sni": R.tls_real_sni,
                "tls_decoy_sni": R.tls_decoy_sni,
                "tls_repeat": R.tls_repeat,
                "udp": R.udp_reach,
                "http": R.http_results,
                "speed_kbps": R.speed_kbps,
                "speed_stalls": R.speed_stalls,
            })
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        print(f"\n  {C.GRAY}原始数据已保存到：{report_path}{C.RESET}")
    except OSError as e:
        warn(f"保存 JSON 失败：{e}")


# ============================================================
# 主入口
# ============================================================

def main():
    hdr("代理失灵诊断：直连 vs 代理 A vs 代理 B")

    # 校验配置
    if all(not p.get("server") and not p.get("local_http") for p in PROXIES):
        print(f"\n{C.RED}错误：PROXIES 配置里两个代理的 server 和 local_http 都是空。请先编辑脚本顶部的配置区。{C.RESET}\n")
        print("至少需要填一项才能测：")
        print(f"  · 填 {C.BOLD}server{C.RESET} + {C.BOLD}port{C.RESET} 能跑 Part A（底层行为）")
        print(f"  · 填 {C.BOLD}local_http{C.RESET} 能跑 Part B（实际流量）")
        sys.exit(1)

    all_results = []

    # 1. 先跑直连对照（只有 Part B，因为 Part A 是打代理服务器的）
    hdr("场景 1 · 直连（不经任何代理）")
    direct_result = run_scenario({"local_http": ""}, is_direct=True)
    all_results.append(direct_result)

    # 2. 每个代理跑一遍
    for i, cfg in enumerate(PROXIES, 1):
        if not cfg.get("server") and not cfg.get("local_http"):
            print(f"\n{C.GRAY}跳过代理 {i}（配置为空）{C.RESET}")
            continue
        hdr(f"场景 {i+1} · {cfg['name']}")
        r = run_scenario(cfg, is_direct=False)
        all_results.append(r)

    # 3. 横向对比
    cross_report(all_results)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}被中断。{C.RESET}")
