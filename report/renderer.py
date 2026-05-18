"""
Renderer — 将各模块输出的数据渲染成 HTML 报告和 Markdown 报告。
"""

import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


TEMPLATE_DIR = Path(__file__).parent
TEMPLATE_FILE = "template.html.j2"


def _safe_domain(domain: str) -> str:
    return domain.replace(".", "_").replace("/", "_")


def render(
    domain: str,
    dns: dict,
    cdn: dict,
    cert: dict,
    fuzz: dict,
    whois_data: dict,
    tech: dict | None = None,
    shodan: dict | None = None,
    headers: dict | None = None,
    tls: dict | None = None,
    ip: dict | None = None,
    wayback: dict | None = None,
    diff: dict | None = None,
    output_path: str | None = None,
) -> tuple[str, str]:
    """
    同时渲染 HTML 和 Markdown 两份报告。

    Returns:
        (html_path, md_path) 两个文件的绝对路径
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    base = _safe_domain(domain)

    html_path = os.path.abspath(output_path if output_path else f"{base}_report.html")
    md_path = html_path.replace(".html", ".md")

    tech    = tech    or {}
    shodan  = shodan  or {}
    headers = headers or {}
    tls     = tls     or {}
    ip      = ip      or {}
    wayback = wayback or {}

    # 预分类 fuzz findings
    fuzz_exposed    = [f for f in fuzz.get("findings", []) if f["status"] == 200]
    fuzz_restricted = [f for f in fuzz.get("findings", []) if f["status"] in (401, 403)]
    fuzz_other      = [f for f in fuzz.get("findings", []) if f["status"] not in (200, 401, 403)]

    # --- HTML ---
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    html = env.get_template(TEMPLATE_FILE).render(
        domain=domain, generated_at=generated_at,
        dns=dns, cdn=cdn, cert=cert, fuzz=fuzz, whois_data=whois_data,
        tech=tech, shodan=shodan,
        headers=headers, tls=tls, ip=ip, wayback=wayback,
        diff=diff,
        fuzz_exposed=fuzz_exposed, fuzz_restricted=fuzz_restricted, fuzz_other=fuzz_other,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # --- Markdown ---
    md = _render_markdown(domain, generated_at, dns, cdn, cert, fuzz, whois_data,
                          tech, shodan, headers, tls, ip, wayback,
                          diff, fuzz_exposed, fuzz_restricted)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    return html_path, md_path


def _render_markdown(
    domain: str,
    generated_at: str,
    dns: dict,
    cdn: dict,
    cert: dict,
    fuzz: dict,
    whois_data: dict,
    tech: dict | None = None,
    shodan: dict | None = None,
    headers: dict | None = None,
    tls: dict | None = None,
    ip: dict | None = None,
    wayback: dict | None = None,
    diff: dict | None = None,
    fuzz_exposed: list | None = None,
    fuzz_restricted: list | None = None,
) -> str:
    tech    = tech    or {}
    shodan  = shodan  or {}
    headers = headers or {}
    tls     = tls     or {}
    ip      = ip      or {}
    wayback = wayback or {}

    if fuzz_exposed is None:
        fuzz_exposed = [f for f in fuzz.get("findings", []) if f["status"] == 200]
    if fuzz_restricted is None:
        fuzz_restricted = [f for f in fuzz.get("findings", []) if f["status"] in (401, 403)]

    lines = []
    w = lines.append  # 简写

    w(f"# OSINT Report — {domain}")
    w(f"\n**Generated:** {generated_at}  ")
    w(f"**Target:** `{domain}`\n")

    # --- Summary ---
    w("## Summary\n")
    w("| Field | Value |")
    w("|---|---|")
    w(f"| CDN / Provider | {cdn.get('cdn_detected') or 'Unknown'} |")
    w(f"| Origin IPs | {', '.join(dns.get('a_records', [])) or 'None'} |")
    w(f"| HTTP Status | {cdn.get('status_code') or 'N/A'} |")
    w(f"| Subdomains (cert) | {len(cert.get('subdomains', []))} |")
    w(f"| Exposed Paths (200) | {len(fuzz_exposed)} |")
    w(f"| Restricted Paths (403/401) | {len(fuzz_restricted)} |")
    # Tech
    techs = tech.get("techs", [])
    if techs:
        w(f"| Tech Stack | {', '.join(techs[:6])} |")
    # Email security
    esec = dns.get("email_security", {})
    if esec:
        w(f"| Email Security | {esec.get('score', 'N/A')} |")
    # Security Headers
    if headers.get("grade"):
        w(f"| Security Headers | Grade {headers['grade']} ({headers.get('score', 0)}/100) |")
    # TLS
    if tls.get("protocol"):
        w(f"| TLS Protocol | {tls['protocol']} |")
    # ASN
    first_ip_info = next(iter(ip.get("ips", {}).values()), {})
    if first_ip_info.get("isp"):
        w(f"| ISP / ASN | {first_ip_info['isp']} |")
    # Wayback
    if wayback.get("available"):
        w(f"| Wayback First Seen | {wayback.get('first_seen') or 'N/A'} |")
    w(f"| Registrar | {whois_data.get('registrar') or 'N/A'} |")
    w("")

    # --- Alerts ---
    alerts = []
    if fuzz_exposed:
        paths = ", ".join(f"`{f['path']}`" for f in fuzz_exposed[:3])
        more = f" (+{len(fuzz_exposed)-3} more)" if len(fuzz_exposed) > 3 else ""
        alerts.append(f"**EXPOSED PATHS (200 — readable):** {paths}{more}")
    if fuzz_restricted:
        paths = ", ".join(f"`{f['path']}`" for f in fuzz_restricted[:3])
        more = f" (+{len(fuzz_restricted)-3} more)" if len(fuzz_restricted) > 3 else ""
        alerts.append(f"**RESTRICTED PATHS (403/401 — exists, blocked):** {paths}{more}")
    if cdn.get("fastly_direct"):
        alerts.append(f"**Fastly origin URL:** `{cdn['fastly_direct']}`")
    if cdn.get("cloudfront_bucket"):
        alerts.append(f"**CloudFront bucket exposed:** `{cdn['cloudfront_bucket']}`")
    # Shodan CVEs
    if shodan.get("all_vulns"):
        cves = ", ".join(shodan["all_vulns"][:3])
        more = f" (+{len(shodan['all_vulns'])-3} more)" if len(shodan["all_vulns"]) > 3 else ""
        alerts.append(f"**SHODAN CVEs DETECTED:** {cves}{more}")
    # Email security missing
    if esec.get("score") == "missing":
        alerts.append("**EMAIL SECURITY MISSING:** No SPF or DMARC configured — domain may be spoofable")
    # Security headers grade F/C
    if headers.get("grade") in ("F", "C"):
        missing = ", ".join(f"`{h}`" for h in headers.get("missing_critical", []))
        alerts.append(f"**SECURITY HEADERS Grade {headers['grade']}:** Missing critical headers: {missing or 'see details'}")
    if headers.get("leaks"):
        version_leaks = [l for l in headers["leaks"] if l["has_version"]]
        if version_leaks:
            leaked = ", ".join(f"`{l['header']}: {l['value']}`" for l in version_leaks[:3])
            alerts.append(f"**VERSION LEAK IN HEADERS:** {leaked}")
    # TLS warnings
    if tls.get("expiry_critical"):
        alerts.append(f"**CERT EXPIRY CRITICAL:** Certificate expires in {tls['days_until_expiry']} day(s)!")
    elif tls.get("expiry_warning"):
        alerts.append(f"**CERT EXPIRY WARNING:** Certificate expires in {tls['days_until_expiry']} days")
    if tls.get("protocol_risk") in ("critical", "high"):
        alerts.append(f"**WEAK TLS PROTOCOL:** {tls.get('protocol')} is deprecated")
    if tls.get("self_signed"):
        alerts.append("**SELF-SIGNED CERTIFICATE:** Certificate is self-signed")
    # IPv6 leaks
    if ip.get("ipv6_leaks"):
        for leak in ip["ipv6_leaks"]:
            alerts.append(f"**IPv6 INTERNAL IP LEAK:** `{leak['ipv6']}` embeds private IP `{leak['embedded_private_ip']}`")
    # Wayback sensitive
    if wayback.get("sensitive_urls"):
        paths = ", ".join(f"`{u['path']}`" for u in wayback["sensitive_urls"][:3])
        more  = f" (+{len(wayback['sensitive_urls'])-3} more)" if len(wayback["sensitive_urls"]) > 3 else ""
        alerts.append(f"**WAYBACK SENSITIVE PATHS:** {paths}{more}")
    if alerts:
        w("## Alerts\n")
        for a in alerts:
            w(f"> {a}\n")

    # --- DNS ---
    w("## DNS Records\n")
    if dns.get("cname_chain"):
        chain = " → ".join([f"`{domain}`"] + [f"`{c}`" for c in dns["cname_chain"]])
        w(f"**CNAME Chain:** {chain}\n")

    rows = (
        [("A", r) for r in dns.get("a_records", [])]
        + [("AAAA", r) for r in dns.get("aaaa_records", [])]
        + [("MX", r) for r in dns.get("mx_records", [])]
        + [("NS", r) for r in dns.get("ns_records", [])]
        + [("TXT", r) for r in dns.get("txt_records", [])]
    )
    if rows:
        w("| Type | Value |")
        w("|---|---|")
        for rtype, val in rows:
            w(f"| {rtype} | `{val}` |")
        w("")
    else:
        w("_No records resolved._\n")

    # --- Email Security ---
    if esec:
        w("## Email Security\n")
        score = esec.get("score", "unknown")
        score_emoji = {"strong": "✅", "partial": "⚠️", "missing": "❌"}.get(score, "")
        w(f"**Overall Score:** {score_emoji} `{score}`\n")
        w("| Protocol | Status | Details |")
        w("|---|---|---|")
        spf = esec.get("spf")
        w(f"| SPF | {'✅ configured' if spf else '❌ missing'} | {spf['record'][:80] if spf else 'No SPF record found'} |")
        dmarc = esec.get("dmarc")
        w(f"| DMARC | {'✅ policy: ' + dmarc['policy'] if dmarc else '❌ missing'} | {dmarc['record'][:80] if dmarc else 'No DMARC record found'} |")
        dkim = esec.get("dkim", {})
        selectors = dkim.get("selectors_found", [])
        w(f"| DKIM | {'✅ ' + ', '.join(selectors) if selectors else '⚠️ no common selectors found'} | {len(selectors)} selector(s) detected |")
        w("")

    # --- CDN ---
    w("## CDN & Infrastructure\n")
    w("| Field | Value |")
    w("|---|---|")
    method = f" _(via {cdn['detection_method']})_" if cdn.get("detection_method") else ""
    w(f"| CDN Provider | {cdn.get('cdn_detected') or 'Not detected'}{method} |")
    w(f"| HTTP Status | {cdn.get('status_code') or 'N/A'} |")
    w(f"| Final URL | {cdn.get('final_url') or 'N/A'} |")
    if cdn.get("fastly_direct"):
        w(f"| Fastly Direct | `{cdn['fastly_direct']}` |")
    if cdn.get("cloudfront_bucket"):
        w(f"| CloudFront Bucket | `{cdn['cloudfront_bucket']}` |")
    w("")
    if cdn.get("key_headers"):
        w("**Key Response Headers:**\n")
        w("| Header | Value |")
        w("|---|---|")
        for k, v in cdn["key_headers"].items():
            w(f"| `{k}` | `{v}` |")
        w("")

    # --- Tech Stack ---
    if tech.get("techs") or tech.get("generator"):
        w("## Technology Stack\n")
        if tech.get("generator"):
            w(f"**Generator:** `{tech['generator']}`\n")
        if tech.get("techs"):
            w("| Technology | Detected via |")
            w("|---|---|")
            details = tech.get("details", {})
            from_headers = set(details.get("from_headers", []))
            from_html = set(details.get("from_html", []))
            from_cookies = set(details.get("from_cookies", []))
            for t in tech["techs"]:
                via = []
                if t in from_headers: via.append("headers")
                if t in from_html: via.append("HTML")
                if t in from_cookies: via.append("cookies")
                w(f"| {t} | {', '.join(via) or '—'} |")
        w("")

    # --- Shodan ---
    if shodan.get("enabled") and shodan.get("results"):
        w("## Shodan Intelligence\n")
        w(f"**Open Ports (all IPs):** {', '.join(str(p) for p in shodan.get('all_ports', []))}\n")
        if shodan.get("all_vulns"):
            w(f"**CVEs Found:** {', '.join(shodan['all_vulns'][:10])}\n")
        for ip, info in shodan["results"].items():
            if "error" in info:
                w(f"**{ip}:** _{info['error']}_\n")
                continue
            w(f"**{ip}**")
            if info.get("geo"):
                geo = info["geo"]
                geo_str = ", ".join(f"{k}: {v}" for k, v in geo.items())
                w(f"  — {geo_str}")
            if info.get("os"):
                w(f"  — OS: {info['os']}")
            if info.get("services"):
                w("\n| Port | Product | Banner |")
                w("|---|---|---|")
                for svc in info["services"][:10]:
                    product = f"{svc.get('product', '')} {svc.get('version', '')}".strip() or "—"
                    banner = (svc.get("banner") or "")[:60]
                    w(f"| {svc['port']}/{svc['transport']} | {product} | {banner} |")
            w("")

    # --- Fuzz ---
    w(f"## Path Discovery\n\n_{fuzz.get('paths_tested', 0)} paths tested._\n")
    if fuzz_exposed:
        w(f"### Exposed — 200 OK ({len(fuzz_exposed)})\n")
        w("| Status | Path | Content-Type | Size | URL |")
        w("|---|---|---|---|---|")
        for f in fuzz_exposed:
            ct = f.get("content_type", "").split(";")[0]
            size = f.get("content_length") or ""
            w(f"| {f['status']} | `{f['path']}` | {ct} | {size} | {f['url']} |")
            # DS_Store 解析结果
            if f.get("ds_store_files"):
                w(f"\n> **`.DS_Store` directory listing ({len(f['ds_store_files'])} entries):**")
                w("> " + "  ".join(f"`{fn}`" for fn in f["ds_store_files"][:30]))
                if len(f["ds_store_files"]) > 30:
                    w(f"> _...and {len(f['ds_store_files'])-30} more_")
                w("")
        w("")
    if fuzz_restricted:
        w(f"### Restricted — 403/401 ({len(fuzz_restricted)})\n")
        w("> Path exists on server but access is blocked.\n")
        w("| Status | Path | Content-Type | Size | URL |")
        w("|---|---|---|---|---|")
        for f in fuzz_restricted:
            ct = f.get("content_type", "").split(";")[0]
            size = f.get("content_length") or ""
            w(f"| {f['status']} | `{f['path']}` | {ct} | {size} | {f['url']} |")
        w("")
    fuzz_other = [f for f in fuzz.get("findings", []) if f["status"] not in (200, 401, 403)]
    if fuzz_other:
        w(f"### Other ({len(fuzz_other)})\n")
        w("| Status | Path | Content-Type | Size | URL |")
        w("|---|---|---|---|---|")
        for f in fuzz_other:
            ct = f.get("content_type", "").split(";")[0]
            size = f.get("content_length") or ""
            w(f"| {f['status']} | `{f['path']}` | {ct} | {size} | {f['url']} |")
        w("")
    if not fuzz.get("findings"):
        w("_No paths found._\n")

    # --- Security Headers ---
    if headers.get("security"):
        grade = headers.get("grade", "?")
        score = headers.get("score", 0)
        w(f"## Security Headers\n\n**Grade:** `{grade}` ({score}/100)\n")
        w("| Header | Present | Value | Note |")
        w("|---|---|---|---|")
        for key, info in headers["security"].items():
            present = "✅" if info["present"] else "❌"
            val = f"`{info['value'][:60]}`" if info["value"] else "—"
            w(f"| {info['friendly']} | {present} | {val} | {info['note']} |")
        w("")
        if headers.get("leaks"):
            w("**Info Leakage in Headers:**\n")
            w("| Header | Value | Version Exposed |")
            w("|---|---|---|")
            for leak in headers["leaks"]:
                flag = "⚠️ YES" if leak["has_version"] else "—"
                w(f"| `{leak['header']}` | `{leak['value'][:80]}` | {flag} |")
            w("")

    # --- TLS ---
    if tls and not tls.get("error"):
        w("## TLS / SSL Analysis\n")
        w("| Field | Value |")
        w("|---|---|")
        proto_risk = tls.get("protocol_risk", "ok")
        proto_note = {"best": "✅", "ok": "✓", "high": "⚠️ deprecated", "critical": "❌ insecure"}.get(proto_risk, "")
        w(f"| Protocol | `{tls.get('protocol') or 'N/A'}` {proto_note} |")
        w(f"| Cipher | `{tls.get('cipher_name') or 'N/A'}` ({tls.get('cipher_bits') or '?'} bits) |")
        w(f"| Cipher Strength | {tls.get('cipher_note') or '—'} |")
        w(f"| Certificate Subject | `{tls.get('cert_subject') or '—'}` |")
        w(f"| Issuer | {tls.get('cert_issuer_org') or ''} ({tls.get('cert_issuer_cn') or '—'}) |")
        w(f"| CA Type | {tls.get('ca_type') or '—'} |")
        w(f"| Self-Signed | {'⚠️ YES' if tls.get('self_signed') else 'No'} |")
        days = tls.get("days_until_expiry")
        if days is not None:
            exp_flag = ("❌ CRITICAL" if tls.get("expiry_critical") else
                        ("⚠️ WARNING" if tls.get("expiry_warning") else "✓"))
            w(f"| Cert Expiry | `{tls.get('cert_not_after') or '—'}` ({days} days) {exp_flag} |")
        w("")
    elif tls.get("error"):
        w(f"## TLS / SSL Analysis\n\n_Error: {tls['error']}_\n")

    # --- IP Intelligence ---
    if ip.get("ips"):
        w("## IP Intelligence\n")
        for addr, info in ip["ips"].items():
            if info.get("error"):
                w(f"**{addr}:** _{info['error']}_\n")
                continue
            w(f"**{addr}**\n")
            w("| Field | Value |")
            w("|---|---|")
            for field, label in [
                ("country", "Country"), ("region", "Region"), ("city", "City"),
                ("isp", "ISP"), ("org", "Organization"), ("asn", "ASN"),
                ("reverse_dns", "Reverse DNS"),
            ]:
                val = info.get(field)
                if val:
                    w(f"| {label} | {val} |")
            flags = []
            if info.get("is_hosting"): flags.append("hosting provider")
            if info.get("is_proxy"):   flags.append("⚠️ proxy/VPN")
            if flags:
                w(f"| Tags | {', '.join(flags)} |")
            w("")
        if ip.get("ipv6_leaks"):
            w("### IPv6 Internal IP Leakage\n")
            for leak in ip["ipv6_leaks"]:
                w(f"> ⚠️ **{leak['ipv6']}** → embedded private IP: `{leak['embedded_private_ip']}`")
                w(f"> {leak['note']}\n")
            w("")

    # --- Wayback Machine ---
    if wayback.get("available"):
        w("## Wayback Machine\n")
        w("| Field | Value |")
        w("|---|---|")
        w(f"| First Seen | {wayback.get('first_seen') or '—'} |")
        w(f"| Last Seen  | {wayback.get('last_seen') or '—'} |")
        w(f"| Unique URLs (archived) | {wayback.get('snapshot_count', 0)} |")
        w("")
        if wayback.get("sensitive_urls"):
            w(f"### Historically Exposed Sensitive Paths ({len(wayback['sensitive_urls'])})\n")
            w("> 以下路径曾在历史快照中以 HTTP 200 出现，即使当前已删除，可能仍有残留或备份。\n")
            w("| Last Seen | Path | Full URL |")
            w("|---|---|---|")
            for item in wayback["sensitive_urls"][:30]:
                w(f"| {item['timestamp']} | `{item['path']}` | {item['url']} |")
            if len(wayback["sensitive_urls"]) > 30:
                w(f"\n_...and {len(wayback['sensitive_urls'])-30} more_\n")
            w("")
    elif wayback.get("error"):
        w(f"## Wayback Machine\n\n_{wayback['error']}_\n")

    # --- Cert ---
    w(f"## Certificate Transparency\n\n_{cert.get('total_certs', 0)} certificates found._\n")
    if cert.get("wildcards"):
        wildcards = " ".join(f"`*.{w_}`" for w_ in cert["wildcards"])
        w(f"**Wildcards:** {wildcards}\n")
    subs = cert.get("subdomains", [])
    if subs:
        w(f"**Subdomains ({len(subs)}):**\n")
        for i in range(0, len(subs), 4):
            w("  ".join(f"`{s}`" for s in subs[i:i+4]) + "  ")
        w("")
    else:
        w(f"_{'No subdomains found.' if not cert.get('error') else cert['error']}_\n")
    if cert.get("issuers"):
        w("**CA Issuers:**\n")
        for issuer in cert["issuers"][:5]:
            w(f"- {issuer}")
        w("")

    # --- WHOIS ---
    w("## WHOIS\n")
    fields = [
        ("Registrar", whois_data.get("registrar")),
        ("Registrant Org", whois_data.get("registrant_org")),
        ("Created", whois_data.get("creation_date")),
        ("Expires", whois_data.get("expiration_date")),
        ("Updated", whois_data.get("updated_date")),
    ]
    has_data = any(v for _, v in fields)
    if has_data:
        w("| Field | Value |")
        w("|---|---|")
        for label, val in fields:
            if val:
                w(f"| {label} | {val} |")
        if whois_data.get("name_servers"):
            ns = " ".join(f"`{n}`" for n in whois_data["name_servers"])
            w(f"| Name Servers | {ns} |")
        if whois_data.get("emails"):
            emails = " ".join(f"`{e}`" for e in whois_data["emails"])
            w(f"| Emails | {emails} |")
        w("")
    else:
        w(f"_{whois_data.get('error') or 'No WHOIS data available.'}_\n")

    # --- Diff ---
    if diff:
        w("## Change Detection (Diff)\n")
        w(f"_Compared with snapshot from: {diff.get('old_timestamp', 'unknown')}_\n")

        def diff_section(title: str, items: list, sign: str):
            if items:
                w(f"**{title}:**")
                for item in items:
                    w(f"- {sign} `{item}`")
                w("")

        diff_section("New paths", diff.get("new_paths", []), "+")
        diff_section("Removed paths", diff.get("removed_paths", []), "-")
        diff_section("New subdomains", diff.get("new_subdomains", []), "+")
        diff_section("Removed subdomains", diff.get("removed_subdomains", []), "-")
        diff_section("New IPs", diff.get("new_ips", []), "+")
        diff_section("Removed IPs", diff.get("removed_ips", []), "-")
        diff_section("New techs", diff.get("new_techs", []), "+")
        if diff.get("cdn_changed"):
            w(f"**CDN changed:** `{diff['old_cdn']}` → `{diff['new_cdn']}`\n")

    w("---")
    w(f"_OSINT Recon Tool — passive reconnaissance only_")

    return "\n".join(lines)
