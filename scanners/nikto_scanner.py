import subprocess, json, os, tempfile
from typing import Optional
from rich.console import Console
console = Console()

def run_nikto(target):
    if not target.startswith("http"): target = f"http://{target}"
    console.print(f"[cyan][*] Starting Nikto scan on {target}...[/cyan]")
    console.print("[dim]    (This may take 2-5 minutes)[/dim]")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode='w') as tmp:
        jp = tmp.name
    try:
        cmd=["nikto","-h",target,"-Format","json","-output",jp,"-nointeractive"]
        console.print(f"[dim]    Running: {' '.join(cmd)}[/dim]")
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=400)
        findings=parse_nikto_output(jp,result.stdout,target)
        console.print(f"[green][+] Nikto complete — {len(findings['vulnerabilities'])} findings[/green]")
        return findings
    except subprocess.TimeoutExpired:
        console.print("[red][-] Nikto timed out[/red]"); return None
    except FileNotFoundError:
        console.print("[red][-] Nikto not installed[/red]"); return None
    finally:
        if os.path.exists(jp): os.unlink(jp)

def parse_nikto_output(json_path, stdout, target):
    findings={"tool":"nikto","target":target,"vulnerabilities":[],"server_info":{}}
    try:
        if os.path.exists(json_path) and os.path.getsize(json_path)>0:
            with open(json_path) as f: content=f.read().strip()
            if content:
                data=json.loads(content)
                if isinstance(data,list) and data: data=data[0]
                host=data.get("host",{})
                findings["server_info"]={"ip":host.get("ip",target),"banner":host.get("banner","")}
                for v in data.get("vulnerabilities",[]):
                    findings["vulnerabilities"].append({
                        "id":v.get("id",""),"method":v.get("method","GET"),
                        "url":v.get("url",""),"msg":v.get("msg",""),
                        "severity":classify_severity(v.get("msg",""))})
                return findings
    except: pass
    findings["vulnerabilities"]=parse_stdout(stdout)
    return findings

def parse_stdout(stdout):
    vulns=[]
    for line in stdout.split("\n"):
        line=line.strip()
        if line.startswith("+ ") and len(line)>10:
            if any(s in line for s in ["Target IP","Target Hostname","Target Port","Start Time","End Time"]): continue
            msg=line[2:].strip()
            if msg: vulns.append({"id":"","method":"GET","url":"/","msg":msg,"severity":classify_severity(msg)})
    return vulns

def classify_severity(msg):
    ml=msg.lower()
    if any(k in ml for k in ["sql injection","xss","rfi","lfi","rce","backdoor","admin","password","bypass"]): return "HIGH"
    if any(k in ml for k in ["outdated","deprecated","misconfiguration","directory listing","disclosure","csrf"]): return "MEDIUM"
    return "LOW"

def get_nikto_summary(findings):
    lines=[f"\n{'='*50}","  NIKTO RESULTS — "+findings['target'],f"{'='*50}"]
    si=findings.get("server_info",{})
    if si.get("banner"): lines.append(f"  Server: {si['banner']}")
    h=[v for v in findings["vulnerabilities"] if v["severity"]=="HIGH"]
    m=[v for v in findings["vulnerabilities"] if v["severity"]=="MEDIUM"]
    l=[v for v in findings["vulnerabilities"] if v["severity"]=="LOW"]
    lines+=[f"  Total: {len(findings['vulnerabilities'])} findings",
            f"    HIGH: {len(h)}  MEDIUM: {len(m)}  LOW: {len(l)}",""]
    for v in findings["vulnerabilities"][:10]:
        ico={"HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵"}.get(v["severity"],"⚪")
        lines.append(f"  {ico} {v['msg'][:100]}")
    return "\n".join(lines)
