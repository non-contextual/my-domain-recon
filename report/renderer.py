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

    # --- HTML ---
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    html = env.get_template(TEMPLATE_FILE).render(
        domain=domain, generated_at=generated_at,
        dns=dns, cdn=cdn, cert=cert, fuzz=fuzz, whois_data=whois_data,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # --- Markdown ---
    md = _render_markdown(domain, generated_at, dns, cdn, cert, fuzz, whois_data)
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
) -> str:
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
    w(f"| Exposed Paths | {len(fuzz.get('findings', []))} |")
    w(f"| Registrar | {whois_data.get('registrar') or 'N/A'} |")
    w("")

    # --- Alerts ---
    alerts = []
    if fuzz.get("findings"):
        paths = ", ".join(f"`{f['path']}`" for f in fuzz["findings"][:3])
        more = f" (+{len(fuzz['findings'])-3} more)" if len(fuzz["findings"]) > 3 else ""
        alerts.append(f"**EXPOSED PATHS FOUND:** {paths}{more}")
    if cdn.get("fastly_direct"):
        alerts.append(f"**Fastly origin URL:** `{cdn['fastly_direct']}`")
    if cdn.get("cloudfront_bucket"):
        alerts.append(f"**CloudFront bucket exposed:** `{cdn['cloudfront_bucket']}`")
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

    # --- Fuzz ---
    w(f"## Path Discovery\n\n_{fuzz.get('paths_tested', 0)} paths tested._\n")
    if fuzz.get("findings"):
        w("| Status | Path | Content-Type | Size | URL |")
        w("|---|---|---|---|---|")
        for f in fuzz["findings"]:
            ct = f.get("content_type", "").split(";")[0]
            size = f.get("content_length") or ""
            w(f"| {f['status']} | `{f['path']}` | {ct} | {size} | {f['url']} |")
        w("")
    else:
        w("_No exposed paths found._\n")

    # --- Cert ---
    w(f"## Certificate Transparency\n\n_{cert.get('total_certs', 0)} certificates found._\n")
    if cert.get("wildcards"):
        wildcards = " ".join(f"`*.{w_}`" for w_ in cert["wildcards"])
        w(f"**Wildcards:** {wildcards}\n")
    subs = cert.get("subdomains", [])
    if subs:
        w(f"**Subdomains ({len(subs)}):**\n")
        # 每行最多 4 个，便于阅读
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

    w("---")
    w(f"_OSINT Recon Tool — passive reconnaissance only_")

    return "\n".join(lines)
