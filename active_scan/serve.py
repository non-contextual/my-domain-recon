"""
本地 FTP→HTTP 代理服务器

启动后:
    1. 监听 http://localhost:8765/
    2. GET /              → 返回 ftp_tree.html (静态)
    3. GET /dl/<port>/<path>  → 从 ftp://10.132.219.5:<port>/<path> 流式拉取并转为 HTTP 下载
    4. GET /ls/<port>/<path>  → 实时调用 FTP LIST, 返回该目录条目的 JSON

为什么需要这个代理:
    现代浏览器 (Chrome/Edge/Firefox) 已经移除了 ftp:// 协议支持,
    所以不能在 HTML 里直接 <a href="ftp://..."> 让用户点击下载。
    我们用一个本地 HTTP 服务做透明转发:
        浏览器 → http://localhost:8765/dl/9966/foo.pdf
        代理   → ftp://10.132.219.5:9966/foo.pdf  (流式拉)
        代理   → 把字节流写回 HTTP 响应
        浏览器 → 触发下载 (因为带 Content-Disposition: attachment)
"""

import ftplib
import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, quote, urlparse

# ---- 配置 ----
TARGET_HOST = "10.132.219.5"
LISTEN_PORT = 8765
FTP_TIMEOUT = 15
HTML_FILE = os.path.join(os.path.dirname(__file__) or ".", "ftp_tree.html")
ANON_USER = "anonymous"
ANON_PASS = "anonymous@example.com"


def make_ftp(port: int) -> ftplib.FTP:
    """新建一个匿名登录的 FTP 连接, GBK 编码兼容中文路径"""
    ftp = ftplib.FTP()
    ftp.encoding = "gb18030"  # 国内 Serv-U 服务器的中文路径都是 GBK
    ftp.connect(TARGET_HOST, port, timeout=FTP_TIMEOUT)
    ftp.login(ANON_USER, ANON_PASS)
    return ftp


def parse_listing_line(line: str) -> dict | None:
    """把 LIST 输出一行解析成结构化条目, . / .. 跳过"""
    if not line or line[0] not in "d-l":
        return None
    parts = line.split(maxsplit=8)
    if len(parts) < 9:
        return None
    name = parts[8]
    if name in (".", ".."):
        return None
    try:
        size = int(parts[4])
    except ValueError:
        size = 0
    return {
        "is_dir": line.startswith("d"),
        "size": size,
        "date": " ".join(parts[5:8]),
        "name": name,
    }


class Handler(BaseHTTPRequestHandler):
    # 让 server 日志安静一点(每个文件下载都打一行太吵)
    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def do_GET(self):
        u = urlparse(self.path)
        path = unquote(u.path)

        # 静态首页
        if path in ("/", "/index.html", "/ftp_tree.html"):
            return self._serve_static_html()

        # 下载: /dl/<port>/<rest of path>
        if path.startswith("/dl/"):
            return self._handle_download(path[len("/dl/"):])

        # 实时列目录: /ls/<port>/<rest of path>
        if path.startswith("/ls/"):
            return self._handle_list(path[len("/ls/"):])

        self.send_error(404, "Not Found")

    def _serve_static_html(self):
        if not os.path.exists(HTML_FILE):
            self._text_error(404, "ftp_tree.html 还没生成, 先运行 python generate_tree.py")
            return
        with open(HTML_FILE, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _split_port_path(self, rest: str) -> tuple[int, str] | None:
        """'9966/download/foo.pdf' → (9966, '/download/foo.pdf'); 路径必须以 / 开头"""
        if "/" in rest:
            port_str, sub = rest.split("/", 1)
            ftp_path = "/" + sub
        else:
            port_str, ftp_path = rest, "/"
        try:
            return int(port_str), ftp_path
        except ValueError:
            return None

    def _handle_download(self, rest: str):
        parsed = self._split_port_path(rest)
        if not parsed:
            self._text_error(400, "URL 格式: /dl/<port>/<path>")
            return
        port, ftp_path = parsed

        # 连 FTP
        try:
            ftp = make_ftp(port)
        except Exception as e:
            self._text_error(502, f"FTP 连接失败: {e}")
            return

        # 切换到二进制模式 + 取大小
        try:
            ftp.voidcmd("TYPE I")
        except ftplib.error_perm as e:
            self._text_error(502, f"TYPE I 失败: {e}")
            try: ftp.quit()
            except: pass
            return

        size = None
        try:
            size = ftp.size(ftp_path)
        except Exception:
            pass

        # 文件名做 RFC 5987 编码, 让浏览器能保留中文文件名
        # HTTP header 是 latin-1 编码的, 不能塞中文进 filename="...",
        # 必须用 filename*=UTF-8''<percent-encoded>; filename="" 部分给 ASCII fallback
        filename = ftp_path.rsplit("/", 1)[-1] or "download"
        filename_encoded = quote(filename, safe="")
        # ASCII fallback: 老浏览器用, 不含中文就不会崩
        filename_ascii = filename.encode("ascii", "replace").decode("ascii")

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition",
            f"attachment; filename=\"{filename_ascii}\"; filename*=UTF-8''{filename_encoded}",
        )
        if size is not None:
            self.send_header("Content-Length", str(size))
        self.end_headers()

        # 流式拉取 → 流式写回 (FTP RETR 内部用 retrbinary 回调)
        # blocksize 64KB 平衡内存和上下文切换
        try:
            ftp.retrbinary(f"RETR {ftp_path}", self.wfile.write, blocksize=64 * 1024)
        except (ConnectionResetError, BrokenPipeError):
            # 用户中断下载 — 浏览器关连接, 这是正常的
            pass
        except Exception as e:
            sys.stderr.write(f"[!] 下载出错 {ftp_path}: {e}\n")
        finally:
            try: ftp.quit()
            except: pass

    def _handle_list(self, rest: str):
        parsed = self._split_port_path(rest)
        if not parsed:
            self._text_error(400, "URL format: /ls/<port>/<path>")
            return
        port, ftp_path = parsed

        try:
            ftp = make_ftp(port)
        except Exception as e:
            return self._json_error(502, f"FTP 连接失败: {e}")

        try:
            ftp.cwd(ftp_path)
        except Exception as e:
            try: ftp.quit()
            except: pass
            return self._json_error(404, f"无法 cwd 到 {ftp_path}: {e}")

        listing: list[str] = []
        try:
            ftp.retrlines("LIST", listing.append)
        except Exception as e:
            return self._json_error(502, f"LIST 失败: {e}")
        finally:
            try: ftp.quit()
            except: pass

        # 解析 + 按目录优先, 然后按名字排序
        items = [it for it in (parse_listing_line(l) for l in listing) if it]
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

        body = json.dumps(
            {"port": port, "path": ftp_path, "items": items},
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 跨域无所谓, 但允许从 file:// 访问也加上
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _json_error(self, code: int, msg: str):
        body = json.dumps({"error": msg}, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _text_error(self, code: int, msg: str):
        """中文兼容的错误响应: status line 用通用 reason, body 写中文消息"""
        body = msg.encode("utf-8")
        # 用 send_response_only 避免触发默认的 latin-1 message
        self.send_response(code, "Error")  # ASCII reason
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), Handler)
    print(f"[*] 代理已启动: http://localhost:{LISTEN_PORT}/")
    print(f"[*] 浏览器请打开:  http://localhost:{LISTEN_PORT}/")
    print(f"[*] Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 收到 Ctrl+C, 退出")
        server.shutdown()


if __name__ == "__main__":
    main()
