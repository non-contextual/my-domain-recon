"""
CLI 入口 — python cli.py <domain> [options]
或者   — python -m osint <domain>

用法示例：
  python cli.py github.com
  python cli.py github.com --no-fuzz
  python cli.py github.com -o report.html
"""

import argparse
import sys
import os
import io
import warnings

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
from report import renderer


console = Console(force_terminal=True, file=sys.stdout)


def print_banner():
    console.print(Panel.fit(
        "[bold cyan][ OSINT Recon Tool ][/bold cyan]\n"
        "[dim]Passive infrastructure reconnaissance[/dim]",
        border_style="cyan",
    ))


def run_recon(domain: str, skip_fuzz: bool = False, output: str | None = None):
    print_banner()
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
        progress.update(task, completed=True, description=(
            f"[green]✓[/green] DNS — "
            f"{len(dns_result['a_records'])} A record(s)"
            f"{', CDN hint: ' + dns_result['cdn_hint'] if dns_result['cdn_hint'] else ''}"
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

        # --- Fuzzing ---
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

            # 以主目标为主，额外目标单独运行
            fuzz_result = fuzz_module.run(
                fuzz_targets[0],
                progress_callback=update_fuzz_progress,
            )

            # 若有 CDN bucket，追加模糊测试结果
            for extra_url in fuzz_targets[1:]:
                extra = fuzz_module.run(extra_url)
                # 标记来源 URL
                for f in extra["findings"]:
                    f["path"] = f"[{extra_url.split('//')[-1].split('/')[0]}] {f['path']}"
                fuzz_result["findings"].extend(extra["findings"])
                fuzz_result["paths_tested"] += extra["paths_tested"]

            results["fuzz"] = fuzz_result
            findings_count = len(fuzz_result["findings"])
            color = "red" if findings_count > 0 else "green"
            progress.update(fuzz_task, completed=100, description=(
                f"[{color}]✓[/{color}] Path Discovery — "
                f"{fuzz_result['paths_tested']} paths tested, "
                f"[{color}]{findings_count} finding(s)[/{color}]"
            ))

    results.setdefault("fuzz", fuzz_result)

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
        output_path=output,
    )
    console.print(f"[bold green]✓ HTML report:[/bold green] {html_path}")
    console.print(f"[bold green]✓ MD report:  [/bold green] {md_path}")
    console.print(f"[dim]Open in browser: file:///{html_path.replace(chr(92), '/')}[/dim]")


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

    table.add_row("A Records", ", ".join(dns["a_records"]) or "[dim]None[/dim]")
    table.add_row("CNAME Chain", " → ".join([domain] + dns["cname_chain"]) if dns["cname_chain"] else "[dim]None[/dim]")
    table.add_row("CDN", f"[magenta]{cdn['cdn_detected']}[/magenta]" if cdn["cdn_detected"] else "[dim]Unknown[/dim]")
    table.add_row("HTTP Status", str(cdn["status_code"]) if cdn["status_code"] else "[dim]N/A[/dim]")
    table.add_row("Subdomains (cert)", str(len(cert["subdomains"])))
    table.add_row("Exposed Paths", f"[red]{len(fuzz['findings'])}[/red]" if fuzz["findings"] else "[green]0[/green]")
    table.add_row("Registrar", whois_r["registrar"] or "[dim]N/A[/dim]")

    console.print(Panel(table, title=f"[bold]{domain}[/bold]", border_style="cyan", expand=False))


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Recon Tool — passive infrastructure reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python cli.py github.com\n  python cli.py github.com --no-fuzz -o report.html",
    )
    parser.add_argument("domain", help="Target domain (e.g. github.com)")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip path fuzzing")
    parser.add_argument("-o", "--output", help="Output HTML file path")
    args = parser.parse_args()

    # 清理域名：去掉协议头
    domain = args.domain.replace("https://", "").replace("http://", "").rstrip("/")

    run_recon(domain, skip_fuzz=args.no_fuzz, output=args.output)


if __name__ == "__main__":
    main()
