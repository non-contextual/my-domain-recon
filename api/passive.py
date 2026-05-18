"""被动侦察 SSE 流 — 依次调用各 recon 模块，实时推送进度事件。"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE))

from recon import (
    dns_module, cdn_module, cert_module, fuzz_module, whois_module,
    tech_module, shodan_module, headers_module, tls_module, ip_module, wayback_module,
)
from report import renderer


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _call(fn, proxy: str, *args, **kwargs):
    """Call fn with HTTP_PROXY env vars set, clean up after."""
    if proxy:
        os.environ["HTTP_PROXY"]  = proxy
        os.environ["HTTPS_PROXY"] = proxy
        os.environ["ALL_PROXY"]   = proxy
    try:
        return fn(*args, **kwargs)
    finally:
        if proxy:
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                os.environ.pop(k, None)


async def passive_stream(domain: str, no_fuzz: bool = False, proxy: str = ""):
    loop = asyncio.get_running_loop()
    results: dict = {}

    async def run(fn, *args, **kwargs):
        return await loop.run_in_executor(None, lambda: _call(fn, proxy, *args, **kwargs))

    # ── DNS ──────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "DNS", "status": "running", "label": "DNS Reconnaissance"})
    t0 = time.time()
    try:
        results["dns"] = await run(dns_module.run, domain)
        d = results["dns"]
        escore = d.get("email_security", {}).get("score", "?")
        cdn_hint = d.get("cdn_hint") or ""
        yield _sse({"type": "progress", "module": "DNS", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": f"{len(d.get('a_records', []))} A  ·  email-sec: {escore}"
                               + (f"  ·  {cdn_hint}" if cdn_hint else "")})
    except Exception as e:
        results["dns"] = {"a_records": [], "aaaa_records": [], "cname_chain": [], "email_security": {}}
        yield _sse({"type": "progress", "module": "DNS", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── CDN ───────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "CDN", "status": "running", "label": "CDN Fingerprinting"})
    t0 = time.time()
    try:
        results["cdn"] = await run(cdn_module.run, domain, dns_result=results["dns"])
        d = results["cdn"]
        yield _sse({"type": "progress", "module": "CDN", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": d.get("cdn_detected") or f"None  (HTTP {d.get('status_code', 'N/A')})"})
    except Exception as e:
        results["cdn"] = {}
        yield _sse({"type": "progress", "module": "CDN", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── Tech ──────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "Tech", "status": "running", "label": "Tech Fingerprinting"})
    t0 = time.time()
    try:
        results["tech"] = await run(tech_module.run, domain,
                                    cdn_headers=results.get("cdn", {}).get("key_headers"))
        techs = results["tech"].get("techs", [])
        yield _sse({"type": "progress", "module": "Tech", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": ", ".join(techs[:5]) or "None detected"})
    except Exception as e:
        results["tech"] = {"techs": []}
        yield _sse({"type": "progress", "module": "Tech", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── Certs ─────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "Cert", "status": "running", "label": "Certificate Transparency"})
    t0 = time.time()
    try:
        results["cert"] = await run(cert_module.run, domain)
        d = results["cert"]
        yield _sse({"type": "progress", "module": "Cert", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": f"{d.get('total_certs', 0)} certs  ·  {len(d.get('subdomains', []))} subdomains"})
    except Exception as e:
        results["cert"] = {"subdomains": [], "total_certs": 0}
        yield _sse({"type": "progress", "module": "Cert", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "WHOIS", "status": "running", "label": "WHOIS"})
    t0 = time.time()
    try:
        results["whois"] = await run(whois_module.run, domain)
        yield _sse({"type": "progress", "module": "WHOIS", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": results["whois"].get("registrar") or "N/A"})
    except Exception as e:
        results["whois"] = {"registrar": None}
        yield _sse({"type": "progress", "module": "WHOIS", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── Security Headers ──────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "Headers", "status": "running", "label": "Security Headers"})
    t0 = time.time()
    try:
        results["headers"] = await run(headers_module.run, domain)
        h = results["headers"]
        leaks = len([l for l in h.get("leaks", []) if l.get("has_version")])
        yield _sse({"type": "progress", "module": "Headers", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": f"Grade {h.get('grade', '?')}  ({h.get('score', 0)}/100)"
                               + (f"  ·  {leaks} version leaks" if leaks else "")})
    except Exception as e:
        results["headers"] = {}
        yield _sse({"type": "progress", "module": "Headers", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── TLS ───────────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "TLS", "status": "running", "label": "TLS / SSL"})
    t0 = time.time()
    try:
        results["tls"] = await run(tls_module.run, domain)
        t = results["tls"]
        days = t.get("days_until_expiry")
        yield _sse({"type": "progress", "module": "TLS", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": (t.get("protocol") or t.get("error") or "N/A")
                               + (f"  ·  cert {days}d" if days is not None else "")})
    except Exception as e:
        results["tls"] = {}
        yield _sse({"type": "progress", "module": "TLS", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── IP Intelligence ───────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "IP", "status": "running", "label": "IP Intelligence"})
    t0 = time.time()
    try:
        results["ip"] = await run(ip_module.run,
                                  a_records=results["dns"].get("a_records", []),
                                  aaaa_records=results["dns"].get("aaaa_records", []))
        first = next(iter(results["ip"].get("ips", {}).values()), {})
        isp = first.get("isp") or first.get("org") or "N/A"
        leaks_v6 = len(results["ip"].get("ipv6_leaks", []))
        yield _sse({"type": "progress", "module": "IP", "status": "done",
                    "elapsed": round(time.time() - t0, 1),
                    "summary": isp + (f"  ·  {leaks_v6} IPv6 leaks" if leaks_v6 else "")})
    except Exception as e:
        results["ip"] = {}
        yield _sse({"type": "progress", "module": "IP", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── Wayback ───────────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "Wayback", "status": "running", "label": "Wayback Machine"})
    t0 = time.time()
    try:
        results["wayback"] = await run(wayback_module.run, domain)
        w = results["wayback"]
        if w.get("available"):
            summary = f"{w['snapshot_count']} URLs  ·  {w['first_seen']} → {w['last_seen']}"
            sens = len(w.get("sensitive_urls", []))
            if sens:
                summary += f"  ·  {sens} sensitive"
        else:
            summary = "No data"
        yield _sse({"type": "progress", "module": "Wayback", "status": "done",
                    "elapsed": round(time.time() - t0, 1), "summary": summary})
    except Exception as e:
        results["wayback"] = {}
        yield _sse({"type": "progress", "module": "Wayback", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})

    # ── Shodan (optional) ─────────────────────────────────────────────────────
    shodan_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if shodan_key:
        yield _sse({"type": "progress", "module": "Shodan", "status": "running", "label": "Shodan"})
        t0 = time.time()
        try:
            results["shodan"] = await run(shodan_module.run, results["dns"].get("a_records", []))
            s = results["shodan"]
            ports_str = ", ".join(str(p) for p in s.get("all_ports", [])[:8]) or "none"
            vulns = len(s.get("all_vulns", []))
            yield _sse({"type": "progress", "module": "Shodan", "status": "done",
                        "elapsed": round(time.time() - t0, 1),
                        "summary": f"ports: {ports_str}" + (f"  ·  {vulns} CVEs" if vulns else "")})
        except Exception as e:
            results["shodan"] = {}
            yield _sse({"type": "progress", "module": "Shodan", "status": "error",
                        "elapsed": round(time.time() - t0, 1), "summary": str(e)})
    else:
        results["shodan"] = shodan_module.run([])
        yield _sse({"type": "progress", "module": "Shodan", "status": "skipped",
                    "label": "Shodan", "summary": "Set SHODAN_API_KEY to enable"})

    # ── Path Fuzzing ──────────────────────────────────────────────────────────
    if no_fuzz:
        results["fuzz"] = {"base_url": f"https://{domain}", "paths_tested": 0, "findings": []}
        yield _sse({"type": "progress", "module": "Fuzz", "status": "skipped",
                    "label": "Path Discovery", "summary": "Skipped"})
    else:
        yield _sse({"type": "progress", "module": "Fuzz", "status": "running",
                    "label": "Path Discovery", "summary": "Starting..."})
        t0 = time.time()
        queue: asyncio.Queue = asyncio.Queue()

        def run_fuzz():
            def cb(completed: int, total: int):
                loop.call_soon_threadsafe(queue.put_nowait,
                    {"type": "fuzz_progress", "completed": completed, "total": total})
            result = _call(fuzz_module.run, proxy, f"https://{domain}", progress_callback=cb)
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "fuzz_done", "result": result})

        fuzz_future = loop.run_in_executor(None, run_fuzz)
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=120.0)
                if item["type"] == "fuzz_progress":
                    c, total_paths = item["completed"], item["total"]
                    pct = int(c / total_paths * 100) if total_paths else 0
                    yield _sse({"type": "progress", "module": "Fuzz", "status": "running",
                                "label": "Path Discovery", "summary": f"{c}/{total_paths}  ({pct}%)"})
                elif item["type"] == "fuzz_done":
                    results["fuzz"] = item["result"]
                    findings = item["result"].get("findings", [])
                    exposed = len([f for f in findings if f["status"] == 200])
                    yield _sse({"type": "progress", "module": "Fuzz", "status": "done",
                                "elapsed": round(time.time() - t0, 1),
                                "summary": f"{item['result']['paths_tested']} tested  ·  {exposed} exposed"})
                    break
            except asyncio.TimeoutError:
                results["fuzz"] = {"base_url": f"https://{domain}", "paths_tested": 0, "findings": []}
                yield _sse({"type": "progress", "module": "Fuzz", "status": "error",
                            "elapsed": round(time.time() - t0, 1), "summary": "Timeout"})
                break
        await fuzz_future

    # ── Render report ─────────────────────────────────────────────────────────
    yield _sse({"type": "progress", "module": "Report", "status": "running", "label": "Generating Report"})
    t0 = time.time()
    try:
        safe = domain.replace(".", "_").replace("/", "_")
        out_path = str(BASE / f"{safe}_report.html")
        html_path, _ = await loop.run_in_executor(None, lambda: renderer.render(
            domain=domain,
            dns=results.get("dns", {}),
            cdn=results.get("cdn", {}),
            cert=results.get("cert", {}),
            fuzz=results.get("fuzz", {}),
            whois_data=results.get("whois", {}),
            tech=results.get("tech", {}),
            shodan=results.get("shodan", {}),
            headers=results.get("headers"),
            tls=results.get("tls"),
            ip=results.get("ip"),
            wayback=results.get("wayback"),
            diff=None,
            output_path=out_path,
        ))
        report_filename = Path(html_path).name
        yield _sse({"type": "progress", "module": "Report", "status": "done",
                    "elapsed": round(time.time() - t0, 1), "summary": report_filename})
        yield _sse({"type": "done", "domain": domain,
                    "report_url": f"/reports/{report_filename}",
                    "summary": _summarize(domain, results)})
    except Exception as e:
        yield _sse({"type": "progress", "module": "Report", "status": "error",
                    "elapsed": round(time.time() - t0, 1), "summary": str(e)})
        yield _sse({"type": "done", "domain": domain, "summary": _summarize(domain, results)})


def _summarize(domain: str, results: dict) -> dict:
    dns     = results.get("dns", {})
    cdn     = results.get("cdn", {})
    cert    = results.get("cert", {})
    fuzz    = results.get("fuzz", {})
    tech    = results.get("tech", {})
    headers = results.get("headers", {})
    tls     = results.get("tls", {})
    ip      = results.get("ip", {})
    wayback = results.get("wayback", {})
    shodan  = results.get("shodan", {})
    whois   = results.get("whois", {})

    findings   = fuzz.get("findings", [])
    exposed    = [f for f in findings if f.get("status") == 200]
    restricted = [f for f in findings if f.get("status") in (401, 403)]
    first_ip   = next(iter(ip.get("ips", {}).values()), {}) if ip else {}

    return {
        "domain": domain,
        "a_records": dns.get("a_records", []),
        "cdn": cdn.get("cdn_detected"),
        "http_status": cdn.get("status_code"),
        "techs": tech.get("techs", []),
        "email_security": dns.get("email_security", {}),
        "subdomains": cert.get("subdomains", [])[:30],
        "subdomains_count": len(cert.get("subdomains", [])),
        "wildcards": cert.get("wildcards", []),
        "exposed_paths": [{"path": f["path"], "url": f.get("url", "")} for f in exposed[:30]],
        "restricted_paths": [{"path": f["path"]} for f in restricted[:30]],
        "paths_tested": fuzz.get("paths_tested", 0),
        "headers_grade": headers.get("grade"),
        "headers_score": headers.get("score"),
        "tls_protocol": tls.get("protocol"),
        "tls_days": tls.get("days_until_expiry"),
        "tls_critical": tls.get("expiry_critical", False),
        "isp": first_ip.get("isp") or first_ip.get("org"),
        "country": first_ip.get("country"),
        "ipv6_leaks": len(ip.get("ipv6_leaks", [])) if ip else 0,
        "wayback_count": wayback.get("snapshot_count", 0),
        "wayback_first": wayback.get("first_seen"),
        "sensitive_urls": len(wayback.get("sensitive_urls", [])),
        "shodan_ports": shodan.get("all_ports", []) if shodan.get("enabled") else [],
        "shodan_vulns": shodan.get("all_vulns", []) if shodan.get("enabled") else [],
        "registrar": whois.get("registrar"),
        "whois_created": str(whois.get("creation_date", "")) if whois.get("creation_date") else None,
    }
