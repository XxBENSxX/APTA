#!/usr/bin/env python3
import argparse, sys, os, time
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
load_dotenv()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanners import run_nmap, get_nmap_summary, run_nikto, get_nikto_summary, run_whatweb, get_whatweb_summary
from core import correlate_findings, analyze_with_ai, enrich_nmap_with_cves, enrich_whatweb_with_cves
from reports import generate_report
console = Console()

def banner():
    console.print(Text("\n  ╔═══════════════════════════════════════╗\n  ║   APTA — AI Penetration Testing       ║\n  ║   Assistant v1.0 — EMSI PFA 2025      ║\n  ╚═══════════════════════════════════════╝\n","cyan"))
    console.print("  [red bold]⚠  AUTHORIZED USE ONLY — Only scan systems you own or have permission to test.[/red bold]\n")

def args():
    p=argparse.ArgumentParser(description="APTA — AI-Powered Penetration Testing Assistant")
    p.add_argument("--target","-t",required=True,help="Target IP or URL")
    p.add_argument("--output","-o",default=None,help="Output report name (no extension)")
    p.add_argument("--skip-nikto",action="store_true")
    p.add_argument("--skip-whatweb",action="store_true")
    p.add_argument("--no-ai",action="store_true")
    p.add_argument("--no-cve",action="store_true")
    return p.parse_args()

def confirm(target):
    console.print(Panel(f"[yellow]Target:[/yellow] [bold white]{target}[/bold white]\n\n[red]Confirm you have explicit written authorization to scan this target.[/red]",title="⚠  Authorization",border_style="red"))
    return input("\n  Proceed? [yes/no]: ").strip().lower() in ["yes","y"]

def main():
    banner()
    a=args()
    target=a.target.strip()
    if not confirm(target):
        console.print("\n[red]Aborted.[/red]"); sys.exit(0)
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    rname=a.output or f"apta_report_{ts}"
    os.makedirs("reports",exist_ok=True)
    rpath=f"reports/{rname}.pdf"
    console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[dim]Report: {rpath}[/dim]\n")
    t0=time.time()

    console.print(Panel("[bold]Phase 1 — Scanning[/bold]",style="cyan"))
    nmap=run_nmap(target)
    if nmap: console.print(get_nmap_summary(nmap))
    nikto=None
    if not a.skip_nikto:
        nikto=run_nikto(target)
        if nikto: console.print(get_nikto_summary(nikto))
    else:
        console.print("[dim][*] Nikto skipped[/dim]")
    whatweb=None
    if not a.skip_whatweb:
        whatweb=run_whatweb(target)
        if whatweb: console.print(get_whatweb_summary(whatweb))
    else:
        console.print("[dim][*] WhatWeb skipped[/dim]")

    console.print(Panel("[bold]Phase 2 — CVE Enrichment[/bold]",style="cyan"))
    if not a.no_cve:
        if nmap: nmap=enrich_nmap_with_cves(nmap)
        if whatweb: whatweb=enrich_whatweb_with_cves(whatweb)
    else:
        console.print("[dim][*] CVE lookup skipped[/dim]")

    console.print(Panel("[bold]Phase 3 — Correlation[/bold]",style="cyan"))
    corr=correlate_findings(nmap,nikto,whatweb)
    if corr.get("compound_risks"):
        console.print("\n[bold red]⚠  Compound Risks:[/bold red]")
        for r in corr["compound_risks"]: console.print(f"  [red]• {r['risk']}[/red]")

    console.print(Panel("[bold]Phase 4 — AI Analysis[/bold]",style="cyan"))
    if not a.no_ai:
        ai=analyze_with_ai(corr,nmap,nikto,whatweb)
    else:
        from core.ai_analyzer import _fallback
        ai=_fallback(corr)

    console.print(Panel("[bold]Phase 5 — PDF Report[/bold]",style="cyan"))
    generate_report(target=target,correlation=corr,nmap_findings=nmap or {},
                    nikto_findings=nikto or {},whatweb_findings=whatweb or {},
                    ai_analysis=ai,output_path=rpath)

    elapsed=time.time()-t0
    console.print(Panel(
        f"[green bold]✓ Done![/green bold]\n\n"
        f"  Target     : {target}\n"
        f"  Risk Level : [bold]{corr.get('risk_level','UNKNOWN')}[/bold]\n"
        f"  Open Ports : {len(corr.get('open_ports',[]))}\n"
        f"  CVEs Found : {len(corr.get('cve_summary',[]))}\n"
        f"  Report     : {rpath}\n"
        f"  Duration   : {int(elapsed//60)}m {int(elapsed%60)}s",
        title="Scan Complete",border_style="green"))

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: console.print("\n[yellow]Interrupted.[/yellow]"); sys.exit(0)
