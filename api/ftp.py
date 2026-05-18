"""FTP 代理 — 把 FTP 目录浏览和文件下载转成 HTTP 接口。"""
import asyncio
import ftplib
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

FTP_TIMEOUT = 15


def _make_ftp(host: str, port: int) -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.encoding = "gb18030"  # 国内服务器中文路径兼容
    ftp.connect(host, port, timeout=FTP_TIMEOUT)
    ftp.login("anonymous", "anonymous@example.com")
    return ftp


def _parse_line(line: str) -> dict | None:
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


def ftp_list(host: str, port: int, path: str = "/") -> dict:
    try:
        ftp = _make_ftp(host, port)
    except Exception as e:
        raise HTTPException(502, f"FTP 连接失败: {e}")
    try:
        ftp.cwd(path)
    except Exception as e:
        try: ftp.quit()
        except: pass
        raise HTTPException(404, f"无法进入 {path}: {e}")
    listing: list[str] = []
    try:
        ftp.retrlines("LIST", listing.append)
    except Exception as e:
        raise HTTPException(502, f"LIST 失败: {e}")
    finally:
        try: ftp.quit()
        except: pass

    items = [it for it in (_parse_line(l) for l in listing) if it]
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return {"host": host, "port": port, "path": path, "items": items}


async def ftp_download(host: str, port: int, path: str) -> StreamingResponse:
    loop = asyncio.get_running_loop()
    # 先同步连接取 size + filename，再异步流式传输
    try:
        ftp_info = await loop.run_in_executor(None, lambda: _connect_for_dl(host, port, path))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, str(e))

    size, filename = ftp_info
    filename_encoded = quote(filename, safe="")
    filename_ascii = filename.encode("ascii", "replace").decode("ascii")

    queue: asyncio.Queue = asyncio.Queue(maxsize=64)

    def _stream():
        try:
            ftp = _make_ftp(host, port)
            ftp.voidcmd("TYPE I")
            ftp.retrbinary(
                f"RETR {path}",
                lambda chunk: loop.call_soon_threadsafe(queue.put_nowait, chunk),
                blocksize=65536,
            )
            ftp.quit()
        except Exception:
            pass
        loop.call_soon_threadsafe(queue.put_nowait, None)

    loop.run_in_executor(None, _stream)

    async def body():
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            yield chunk

    headers = {
        "Content-Disposition": (
            f'attachment; filename="{filename_ascii}"; '
            f"filename*=UTF-8''{filename_encoded}"
        ),
        "Access-Control-Allow-Origin": "*",
    }
    if size is not None:
        headers["Content-Length"] = str(size)

    return StreamingResponse(body(), media_type="application/octet-stream", headers=headers)


def _connect_for_dl(host: str, port: int, path: str):
    try:
        ftp = _make_ftp(host, port)
        ftp.voidcmd("TYPE I")
        size = None
        try:
            size = ftp.size(path)
        except Exception:
            pass
        ftp.quit()
    except Exception as e:
        raise HTTPException(502, f"FTP 连接失败: {e}")
    filename = path.rsplit("/", 1)[-1] or "download"
    return size, filename
