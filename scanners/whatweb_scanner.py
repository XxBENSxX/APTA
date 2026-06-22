import subprocess, json, os, tempfile
from typing import Optional
from rich.console import Console
console = Console()

def run_whatweb(target):
    if not target.startswith("http"): target = f"http://{target}"
    console.print(f"[cyan][*] Starting WhatWeb on {target}...[/cyan]")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w') as tmp:
        jp = tmp.name
    try:
        cmd=["whatweb","--log-json",jp,"-a","3","--no-errors",target]
        console.print(f"[dim]    Running: {' '.join(cmd)}[/dim]")
        subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        findings=parse_whatweb(jp,target)
        console.print(f"[green][+] WhatWeb complete — {len(findings['technologies'])} technologies[/green]")
        return findings
    except subprocess.TimeoutExpired:
        console.print("[red][-] WhatWeb timed out[/red]"); return None
    except FileNotFoundError:
        console.print("[red][-] WhatWeb not installed[/red]"); return None
    finally:
        if os.path.exists(jp): os.unlink(jp)

def parse_whatweb(json_path, target):
    findings={"tool":"whatweb","target":target,"technologies":[],"http_status":None}
    try:
        if not os.path.exists(json_path) or os.path.getsize(json_path)==0: return findings
        with open(json_path) as f: content=f.read().strip()
        for line in content.split("\n"):
            line=line.strip()
            if not line: continue
            try:
                data=json.loads(line)
                findings["http_status"]=data.get("http_status")
                for name, pdata in data.get("plugins",{}).items():
                    tech={"name":name,"version":None,"cves":[]}
                    if isinstance(pdata,dict):
                        vl=pdata.get("version",[])
                        if vl and isinstance(vl,list): tech["version"]=vl[0]
                    findings["technologies"].append(tech)
            except: continue
    except Exception as e:
        console.print(f"[yellow][!] WhatWeb parse warning: {e}[/yellow]")
    return findings

def get_whatweb_summary(findings):
    lines=[f"\n{'='*50}","  WHATWEB RESULTS — "+findings['target'],f"{'='*50}"]
    if findings["http_status"]: lines.append(f"  HTTP Status : {findings['http_status']}")
    lines.append(f"  Technologies: {len(findings['technologies'])}\n")
    for t in findings["technologies"]:
        v=f" v{t['version']}" if t.get("version") else ""
        lines.append(f"  • {t['name']}{v}")
    return "\n".join(lines)
