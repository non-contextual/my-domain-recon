"""主动扫描 SSE 流 — 端口扫描 + 网络环境诊断。"""
import asyncio
import concurrent.futures
import json
import socket
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017,
    989, 990, 2121, 2221, 8021, 8121,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
    989: "FTPS-Data", 990: "FTPS", 2121: "FTP-Alt", 2221: "FTP-Alt",
}


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _scan_port(host: str, port: int, timeout: float = 0.8):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return port, False, ""
        banner = ""
        try:
            sock.settimeout(1.5)
            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass
        sock.close()
        return port, True, banner
    except Exception:
        return port, False, ""


async def ports_stream(host: str, mode: str = "common"):
    loop = asyncio.get_running_loop()

    if mode == "full":
        ports = list(range(1, 65536))
    elif mode == "common":
        ports = COMMON_PORTS
    else:
        try:
            lo, hi = mode.split("-")
            ports = list(range(int(lo), int(hi) + 1))
        except Exception:
            ports = COMMON_PORTS

    total = len(ports)
    queue: asyncio.Queue = asyncio.Queue()

    yield _sse({"type": "start", "host": host, "total": total, "mode": mode})

    def run_scan():
        scanned = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(500, total)) as ex:
            futures = {ex.submit(_scan_port, host, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                port, is_open, banner = fut.result()
                scanned += 1
                if is_open:
                    loop.call_soon_threadsafe(queue.put_nowait, {
                        "type": "open",
                        "port": port,
                        "service": SERVICE_NAMES.get(port, ""),
                        "banner": banner[:120],
                        "is_ftp": banner.startswith("220") or "ftp" in banner.lower(),
                    })
                if scanned % max(1, total // 20) == 0 or scanned == total:
                    loop.call_soon_threadsafe(queue.put_nowait, {
                        "type": "progress",
                        "scanned": scanned,
                        "total": total,
                    })
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "done"})

    scan_future = loop.run_in_executor(None, run_scan)

    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=300.0)
            yield _sse(item)
            if item["type"] == "done":
                break
        except asyncio.TimeoutError:
            yield _sse({"type": "error", "message": "Scan timed out"})
            break

    await scan_future


async def network_stream():
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    script = str(BASE / "active_scan" / "network_analyzer.py")

    yield _sse({"type": "start", "label": "Network Environment Diagnosis"})

    def run():
        try:
            proc = subprocess.Popen(
                [sys.executable, script],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    # strip ANSI escape codes
                    import re
                    clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
                    loop.call_soon_threadsafe(queue.put_nowait, {"type": "line", "text": clean})
            proc.wait()
        except Exception as e:
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "line", "text": f"Error: {e}"})
        loop.call_soon_threadsafe(queue.put_nowait, {"type": "done"})

    run_future = loop.run_in_executor(None, run)

    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=120.0)
            yield _sse(item)
            if item["type"] == "done":
                break
        except asyncio.TimeoutError:
            yield _sse({"type": "error", "message": "Analysis timed out"})
            break

    await run_future
