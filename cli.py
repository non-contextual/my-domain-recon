"""
CLI 入口 — python cli.py <domain> [options]
或者   — python -m osint <domain>

用法示例：
  python cli.py github.com
  python cli.py github.com --no-fuzz
  python cli.py github.com -o report.html
  python cli.py github.com --snapshot          # 保存 JSON 快照
  python cli.py github.com --diff snapshot.json  # 与旧快照对比
  python cli.py -f domains.txt                 # 批量扫描
"""

import argparse
import sys
import os
import io
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

# 强制 stdout/stderr 使用 UTF-8（Windows 默认 GBK 会导致 spinner 字符报错）
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# 屏蔽 SSL 警告（HTTPS 验证已关闭，属于预期行为）
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import print as rprint

# 模块导入
sys.path.insert(0, os.path.dirname(__file__))
from recon import dns_module, cdn_module, cert_module, fuzz_module, whois_module
from recon import tech_module, shodan_module
from report import renderer


console = Console(force_terminal=True, file=sys.stdout)


def print_banner():
    console.print(Panel.fit(
        "[bold cyan][ OSINT Recon Tool ][/bold cyan]\n"
        "[dim]Passive infrastructure reconnaissance[/dim]",
        border_style="cyan",
    ))


def run_recon(domain: str, skip_fuzz: bool = False, output: str | None = None,
              save_snapshot: bool = False, diff_path: str | None = None) -> dict:
    """
    对单个域名执行完整侦察，返回所有模块结果的字典。
    """
    console.print(f"\n[bold]Target:[/bold] [cyan]{domain}[/cyan]\n")

    results = {}

    with Progress(
        SpinnerColumn(spinner_name="line"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as progress:

        # --- DNS ---
        task = progress.add_task("[cyan]DNS Reconnaissance...", total=None)
        dns_result = dns_module.run(domain)
        results["dns"] = dns_result
        email_score = dns_result.get("email_security", {}).get("score", "?")
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] DNS — "
            f"{len(dns_result['a_records'])} A record(s)"
            f"{', CDN hint: ' + dns_result['cdn_hint'] if dns_result['cdn_hint'] else ''}"
            f"  [dim]email-sec: {email_score}[/dim]"
        ))

        # --- CDN ---
        task = progress.add_task("[cyan]CDN Fingerprinting...", total=None)
        cdn_result = cdn_module.run(domain, dns_result=dns_result)
        results["cdn"] = cdn_result
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] CDN — "
            f"{cdn_result['cdn_detected'] or 'Unknown'} "
            f"(HTTP {cdn_result['status_code'] or 'N/A'})"
        ))

        # --- Tech Fingerprinting ---
        task = progress.add_task("[cyan]Tech Fingerprinting...", total=None)
        tech_result = tech_module.run(domain, cdn_headers=cdn_result.get("key_headers"))
        results["tech"] = tech_result
        techs_str = ", ".join(tech_result["techs"][:5]) or "None detected"
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] Tech — {techs_str}"
        ))

        # --- Certificate Transparency ---
        task = progress.add_task("[cyan]Certificate Transparency (crt.sh)...", total=None)
        cert_result = cert_module.run(domain)
        results["cert"] = cert_result
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] Certs — "
            f"{cert_result['total_certs']} cert(s), "
            f"{len(cert_result['subdomains'])} subdomain(s) discovered"
        ))

        # --- WHOIS ---
        task = progress.add_task("[cyan]WHOIS Lookup...", total=None)
        whois_result = whois_module.run(domain)
        results["whois"] = whois_result
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] WHOIS — "
            f"{whois_result['registrar'] or 'N/A'}"
        ))

        # --- Shodan (optional) ---
        shodan_key = os.environ.get("SHODAN_API_KEY", "").strip()
        if shodan_key:
            task = progress.add_task("[cyan]Shodan Lookup...", total=None)
            shodan_result = shodan_module.run(dns_result["a_records"])
            results["shodan"] = shodan_result
            ports_str = ", ".join(str(p) for p in shodan_result["all_ports"][:8]) or "none"
            vulns_count = len(shodan_result["all_vulns"])
            progress.update(task, completed=True, description=(
                f"[green]✓[/green] Shodan — ports: {ports_str}"
                + (f"  [red]{vulns_count} CVE(s)[/red]" if vulns_count else "")
            ))
        else:
            results["shodan"] = shodan_module.run([])  # disabled, empty result
            console.print("[dim]⏭  Shodan skipped (set SHODAN_API_KEY to enable)[/dim]")

        # --- Fuzzing ---
        fuzz_result: dict
        if skip_fuzz:
            fuzz_result = {"base_url": f"https://{domain}", "paths_tested": 0, "findings": []}
            console.print("[dim]⏭  Path fuzzing skipped (--no-fuzz)[/dim]")
        else:
            fuzz_counter = {"done": 0, "total": 0}
            fuzz_task = progress.add_task("[cyan]Path Discovery...", total=100)

            def update_fuzz_progress(completed: int, total: int):
                fuzz_counter["done"] = completed
                fuzz_counter["total"] = total
                pct = int((completed / total) * 100) if total else 0
                progress.update(fuzz_task, completed=pct, description=(
                    f"[cyan]Path Discovery... [{completed}/{total}][/cyan]"
                ))

            # 若检测到 CDN bucket URL，也对其进行模糊测试
            fuzz_targets = [f"https://{domain}"]
            if cdn_result.get("fastly_direct"):
                fuzz_targets.append(cdn_result["fastly_direct"])
            if cdn_result.get("cloudfront_bucket"):
                fuzz_targets.append(cdn_result["cloudfront_bucket"])

            fuzz_result = fuzz_module.run(
                fuzz_targets[0],
                progress_callback=update_fuzz_progress,
            )

            for extra_url in fuzz_targets[1:]:
                extra = fuzz_module.run(extra_url)
                for f in extra["findings"]:
                    f["path"] = f"[{extra_url.split('//')[-1].split('/')[0]}] {f['path']}"
                fuzz_result["findings"].extend(extra["findings"])
                fuzz_result["paths_tested"] += extra["paths_tested"]

            findings_count = len(fuzz_result["findings"])
            color = "red" if findings_count > 0 else "green"
            progress.update(fuzz_task, completed=100, description=(
                f"[{color}]✓[/{color}] Path Discovery — "
                f"{fuzz_result['paths_tested']} paths tested, "
                f"[{color}]{findings_count} finding(s)[/{color}]"
            ))

        results["fuzz"] = fuzz_result

    # --- Diff 对比 ---
    diff_result: dict | None = None
    if diff_path:
        diff_result = _compute_diff(diff_path, results)
        if diff_result:
            _print_diff(diff_result)

    # --- 打印摘要 ---
    console.print()
    _print_summary(domain, results)

    # --- 渲染 HTML + Markdown ---
    console.print()
    html_path, md_path = renderer.render(
        domain=domain,
        dns=results["dns"],
        cdn=results["cdn"],
        cert=results["cert"],
        fuzz=results["fuzz"],
        whois_data=results["whois"],
        tech=results["tech"],
        shodan=results["shodan"],
        diff=diff_result,
        output_path=output,
    )
    console.print(f"[bold green]✓ HTML report:[/bold green] {html_path}")
    console.print(f"[bold green]✓ MD report:  [/bold green] {md_path}")
    console.print(f"[dim]Open in browser: file:///{html_path.replace(chr(92), '/')}[/dim]")

    # --- 保存快照 ---
    if save_snapshot:
        snap_path = _save_snapshot(domain, results)
        console.print(f"[bold green]✓ Snapshot:    [/bold green] {snap_path}")

    return results


def _save_snapshot(domain: str, results: dict) -> str:
    """将当前扫描结果保存为 JSON 快照文件。"""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_").replace("/", "_")
    path = f"{safe_domain}_{ts}_snapshot.json"

    snapshot = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "a_records": results["dns"]["a_records"],
        "cdn": results["cdn"].get("cdn_detected"),
        "subdomains": results["cert"].get("subdomains", []),
        "fuzz_findings": [
            {"path": f["path"], "status": f["status"], "url": f["url"]}
            for f in results["fuzz"].get("findings", [])
        ],
        "techs": results["tech"].get("techs", []),
    }

    with open(path, "w", encoding="utf-8") as fp:
        json.dump(snapshot, fp, indent=2, ensure_ascii=False)
    return os.path.abspath(path)


def _compute_diff(old_snapshot_path: str, current: dict) -> dict | None:
    """对比旧快照和当前扫描结果，返回差异报告。"""
    try:
        with open(old_snapshot_path, "r", encoding="utf-8") as fp:
            old = json.load(fp)
    except Exception as e:
        console.print(f"[red]⚠ Could not load snapshot: {e}[/red]")
        return None

    old_paths = {f["path"] for f in old.get("fuzz_findings", [])}
    new_paths = {f["path"] for f in current["fuzz"].get("findings", [])}
    old_subs = set(old.get("subdomains", []))
    new_subs = set(current["cert"].get("subdomains", []))
    old_ips = set(old.get("a_records", []))
    new_ips = set(current["dns"]["a_records"])

    return {
        "old_timestamp": old.get("timestamp", "unknown"),
        "new_paths": sorted(new_paths - old_paths),
        "removed_paths": sorted(old_paths - new_paths),
        "new_subdomains": sorted(new_subs - old_subs),
        "removed_subdomains": sorted(old_subs - new_subs),
        "new_ips": sorted(new_ips - old_ips),
        "removed_ips": sorted(old_ips - new_ips),
        "cdn_changed": old.get("cdn") != current["cdn"].get("cdn_detected"),
        "old_cdn": old.get("cdn"),
        "new_cdn": current["cdn"].get("cdn_detected"),
        "new_techs": sorted(
            set(current["tech"].get("techs", [])) - set(old.get("techs", []))
        ),
    }


def _print_diff(diff: dict):
    """在终端打印 diff 摘要。"""
    console.print(Panel.fit(
        f"[bold yellow]DIFF vs snapshot from {diff['old_timestamp']}[/bold yellow]",
        border_style="yellow",
    ))

    def show(label: str, items: list, color: str):
        if items:
            console.print(f"  [{color}]{label}:[/{color}]")
            for item in items:
                console.print(f"    [dim]•[/dim] {item}")

    show("New paths found", diff["new_paths"], "red")
    show("Paths disappeared", diff["removed_paths"], "green")
    show("New subdomains", diff["new_subdomains"], "yellow")
    show("Subdomains gone", diff["removed_subdomains"], "dim")
    show("New IPs", diff["new_ips"], "yellow")
    show("IPs gone", diff["removed_ips"], "dim")
    show("New techs detected", diff["new_techs"], "cyan")

    if diff["cdn_changed"]:
        console.print(
            f"  [yellow]CDN changed:[/yellow] "
            f"[dim]{diff['old_cdn']}[/dim] → [cyan]{diff['new_cdn']}[/cyan]"
        )

    has_changes = any([
        diff["new_paths"], diff["removed_paths"],
        diff["new_subdomains"], diff["cdn_changed"],
        diff["new_ips"], diff["new_techs"],
    ])
    if not has_changes:
        console.print("  [green]No significant changes detected.[/green]")
    console.print()


def _print_summary(domain: str, results: dict):
    """在终端打印简洁摘要表格。"""
    table = Table(show_header=True, header_style="bold dim", box=None, pad_edge=False)
    table.add_column("Module", style="dim", width=22)
    table.add_column("Result")

    dns = results["dns"]
    cdn = results["cdn"]
    cert = results["cert"]
    fuzz = results["fuzz"]
    whois_r = results["whois"]
    tech = results["tech"]
    shodan = results["shodan"]

    fuzz_exposed = [f for f in fuzz["findings"] if f["status"] == 200]
    fuzz_restricted = [f for f in fuzz["findings"] if f["status"] in (401, 403)]

    table.add_row("A Records", ", ".join(dns["a_records"]) or "[dim]None[/dim]")
    table.add_row("CNAME Chain", " → ".join([domain] + dns["cname_chain"]) if dns["cname_chain"] else "[dim]None[/dim]")
    table.add_row("CDN", f"[magenta]{cdn['cdn_detected']}[/magenta]" if cdn["cdn_detected"] else "[dim]Unknown[/dim]")
    table.add_row("HTTP Status", str(cdn["status_code"]) if cdn["status_code"] else "[dim]N/A[/dim]")

    # Email security
    esec = dns.get("email_security", {})
    score_color = {"strong": "green", "partial": "yellow", "missing": "red"}.get(esec.get("score", ""), "dim")
    table.add_row("Email Security", f"[{score_color}]{esec.get('score', 'N/A')}[/{score_color}]"
                  + (f"  [dim]DMARC: {esec['dmarc']['policy']}[/dim]" if esec.get("dmarc") else ""))

    # Tech stack
    techs = tech.get("techs", [])
    table.add_row("Tech Stack", ", ".join(techs[:6]) if techs else "[dim]None detected[/dim]")

    table.add_row("Subdomains (cert)", str(len(cert["subdomains"])))

    # Fuzz findings split
    exposed_str = f"[red]{len(fuzz_exposed)} exposed[/red]" if fuzz_exposed else "[green]0 exposed[/green]"
    restricted_str = f"  [yellow]{len(fuzz_restricted)} restricted[/yellow]" if fuzz_restricted else ""
    table.add_row("Path Discovery", exposed_str + restricted_str)

    # Shodan
    if shodan.get("enabled"):
        ports_str = ", ".join(str(p) for p in shodan["all_ports"][:6]) or "none"
        vulns_count = len(shodan["all_vulns"])
        shodan_val = f"ports: {ports_str}"
        if vulns_count:
            shodan_val += f"  [red]{vulns_count} CVE(s)[/red]"
        table.add_row("Shodan", shodan_val)

    table.add_row("Registrar", whois_r["registrar"] or "[dim]N/A[/dim]")

    console.print(Panel(table, title=f"[bold]{domain}[/bold]", border_style="cyan", expand=False))


def run_batch(domains_file: str, skip_fuzz: bool = False):
    """批量扫描模式：读取域名列表文件，逐个扫描。"""
    path = Path(domains_file)
    if not path.exists():
        console.print(f"[red]File not found: {domains_file}[/red]")
        sys.exit(1)

    domains = [
        line.strip().replace("https://", "").replace("http://", "").rstrip("/")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not domains:
        console.print("[red]No domains found in file.[/red]")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold cyan][ OSINT Batch Mode ][/bold cyan]\n"
        f"[dim]{len(domains)} domains loaded from {domains_file}[/dim]",
        border_style="cyan",
    ))

    all_results: list[dict] = []
    for i, domain in enumerate(domains, 1):
        console.rule(f"[bold cyan]{i}/{len(domains)}: {domain}[/bold cyan]")
        try:
            result = run_recon(domain, skip_fuzz=skip_fuzz)
            all_results.append({"domain": domain, "results": result, "error": None})
        except Exception as e:
            console.print(f"[red]✗ {domain} failed: {e}[/red]")
            all_results.append({"domain": domain, "results": None, "error": str(e)})

    # --- 汇总报告 ---
    console.rule("[bold cyan]BATCH SUMMARY[/bold cyan]")
    summary_table = Table(show_header=True, header_style="bold dim", box=None)
    summary_table.add_column("Domain", style="cyan", width=35)
    summary_table.add_column("CDN", width=18)
    summary_table.add_column("Tech", width=28)
    summary_table.add_column("Email Sec", width=10)
    summary_table.add_column("Exposed", width=8)
    summary_table.add_column("Subdomains", width=10)
    summary_table.add_column("Status")

    for entry in all_results:
        domain = entry["domain"]
        if entry["error"]:
            summary_table.add_row(domain, "-", "-", "-", "-", "-", f"[red]ERROR: {entry['error'][:40]}[/red]")
            continue
        r = entry["results"]
        cdn_name = r["cdn"].get("cdn_detected") or "—"
        techs = ", ".join(r["tech"].get("techs", [])[:3]) or "—"
        esec = r["dns"].get("email_security", {}).get("score", "—")
        score_color = {"strong": "green", "partial": "yellow", "missing": "red"}.get(esec, "dim")
        exposed = len([f for f in r["fuzz"].get("findings", []) if f["status"] == 200])
        subs = len(r["cert"].get("subdomains", []))
        summary_table.add_row(
            domain, cdn_name, techs,
            f"[{score_color}]{esec}[/{score_color}]",
            f"[red]{exposed}[/red]" if exposed else "[green]0[/green]",
            str(subs),
            "[green]OK[/green]",
        )

    console.print(summary_table)
    console.print(f"\n[dim]Individual reports saved as <domain>_report.html[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Recon Tool — passive infrastructure reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py github.com\n"
            "  python cli.py github.com --no-fuzz -o report.html\n"
            "  python cli.py github.com --snapshot\n"
            "  python cli.py github.com --diff github_com_20260101_snapshot.json\n"
            "  python cli.py -f domains.txt\n"
            "\nEnvironment variables:\n"
            "  SHODAN_API_KEY   Enable Shodan integration"
        ),
    )
    parser.add_argument("domain", nargs="?", help="Target domain (e.g. github.com)")
    parser.add_argument("-f", "--file", help="File containing list of domains (batch mode)")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip path fuzzing")
    parser.add_argument("-o", "--output", help="Output HTML file path")
    parser.add_argument("--snapshot", action="store_true", help="Save JSON snapshot after scan")
    parser.add_argument("--diff", metavar="SNAPSHOT", help="Compare with a previous JSON snapshot")
    args = parser.parse_args()

    if args.file:
        run_batch(args.file, skip_fuzz=args.no_fuzz)
        return

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    print_banner()
    domain = args.domain.replace("https://", "").replace("http://", "").rstrip("/")
    run_recon(
        domain,
        skip_fuzz=args.no_fuzz,
        output=args.output,
        save_snapshot=args.snapshot,
        diff_path=args.diff,
    )


if __name__ == "__main__":
    main()
