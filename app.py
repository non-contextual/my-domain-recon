"""
OSINT Web Console
启动: python app.py
访问: http://localhost:8080
"""
import os
import sys
from pathlib import Path

BASE = Path(__file__).parent
os.chdir(str(BASE))  # reports 保存到 osint 目录
sys.path.insert(0, str(BASE))

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from api.passive import passive_stream
from api.active import ports_stream, network_stream
from api.ftp import ftp_list, ftp_download

app = FastAPI(title="OSINT Console")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/", response_class=HTMLResponse)
async def root():
    return (BASE / "web" / "index.html").read_text(encoding="utf-8")


@app.get("/api/passive/scan")
async def passive_scan(domain: str, no_fuzz: bool = False, proxy: str = ""):
    return StreamingResponse(
        passive_stream(domain.strip().replace("https://", "").replace("http://", "").rstrip("/"), no_fuzz, proxy),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/active/ports")
async def active_ports(host: str, mode: str = "common", proxy: str = ""):
    return StreamingResponse(
        ports_stream(host.strip(), mode),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/active/network")
async def active_network():
    return StreamingResponse(
        network_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/ftp/ls")
async def api_ftp_ls(host: str, port: int = 21, path: str = "/"):
    return ftp_list(host, port, path)


@app.get("/api/ftp/dl")
async def api_ftp_dl(host: str, port: int = 21, path: str = "/"):
    return await ftp_download(host, port, path)


@app.get("/api/reports")
async def list_reports():
    reports = []
    for f in sorted(BASE.glob("*_report.html"), key=lambda p: p.stat().st_mtime, reverse=True):
        reports.append({"name": f.name, "mtime": int(f.stat().st_mtime)})
    return reports


@app.get("/reports/{filename}")
async def serve_report(filename: str):
    path = BASE / filename
    if path.exists() and path.suffix == ".html" and path.parent.resolve() == BASE.resolve():
        return FileResponse(str(path), media_type="text/html")
    return HTMLResponse("Not found", status_code=404)


if __name__ == "__main__":
    print("OSINT Console → http://localhost:8080")
    uvicorn.run("app:app", host="127.0.0.1", port=8080, reload=False)
