import subprocess, xml.etree.ElementTree as ET, os, tempfile
from typing import Optional
from rich.console import Console
console = Console()

def run_nmap(target: str) -> Optional[dict]:
    console.print(f"[cyan][*] Starting Nmap scan on {target}...[/cyan]")
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    try:
        cmd = ["nmap","-sV","-sC","-O","--open","-oX",xml_path,"--script=banner,http-title",target]
        console.print(f"[dim]    Running: {' '.join(cmd)}[/dim]")
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = parse_nmap_xml(xml_path, target)
        console.print(f"[green][+] Nmap complete — {len(findings['ports'])} open ports found[/green]")
        return findings
    except subprocess.TimeoutExpired:
        console.print("[red][-] Nmap timed out[/red]"); return None
    except FileNotFoundError:
        console.print("[red][-] Nmap not installed[/red]"); return None
    finally:
        if os.path.exists(xml_path): os.unlink(xml_path)

def parse_nmap_xml(xml_path, target):
    findings = {"tool":"nmap","target":target,"host_status":"unknown","os_detection":[],"ports":[],"raw_summary":""}
    try:
        root = ET.parse(xml_path).getroot()
        rs = root.find("runstats/finished")
        if rs is not None: findings["raw_summary"] = rs.get("summary","")
        for host in root.findall("host"):
            s = host.find("status")
            if s is not None: findings["host_status"] = s.get("state","unknown")
            os_el = host.find("os")
            if os_el is not None:
                for om in os_el.findall("osmatch"):
                    findings["os_detection"].append({"name":om.get("name","Unknown"),"accuracy":om.get("accuracy","0")+"%"})
            pe = host.find("ports")
            if pe is not None:
                for port in pe.findall("port"):
                    st = port.find("state")
                    if st is None or st.get("state") != "open": continue
                    svc = port.find("service")
                    pd = {"port":port.get("portid"),"protocol":port.get("protocol","tcp"),"state":"open",
                          "service":"unknown","product":"","version":"","extra_info":"","scripts":[],"cves":[]}
                    if svc is not None:
                        pd["service"]=svc.get("name","unknown"); pd["product"]=svc.get("product","")
                        pd["version"]=svc.get("version",""); pd["extra_info"]=svc.get("extrainfo","")
                    for sc in port.findall("script"):
                        pd["scripts"].append({"id":sc.get("id",""),"output":sc.get("output","")[:300]})
                    findings["ports"].append(pd)
    except Exception as e:
        console.print(f"[yellow][!] Nmap parse warning: {e}[/yellow]")
    return findings

def get_nmap_summary(findings):
    lines=[f"\n{'='*50}","  NMAP RESULTS — "+findings['target'],f"{'='*50}",
           f"  Host Status : {findings['host_status'].upper()}"]
    if findings["os_detection"]:
        lines.append(f"  OS : {findings['os_detection'][0]['name']} ({findings['os_detection'][0]['accuracy']})")
    lines.append(f"  Open Ports  : {len(findings['ports'])}\n")
    for p in findings["ports"]:
        svc=p["service"]
        if p["product"]: svc+=f" ({p['product']}{' '+p['version'] if p['version'] else ''})"
        lines.append(f"  [{p['port']}/{p['protocol']}]  {svc}")
    return "\n".join(lines)
