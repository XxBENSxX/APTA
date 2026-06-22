from rich.console import Console
console = Console()

RULES = [
    {"ports":[22],"services":["ssh"],"risk":"SSH Exposed","description":"SSH is a common brute force target.","severity":"MEDIUM"},
    {"ports":[23],"services":["telnet"],"risk":"Telnet — Cleartext Protocol","description":"Telnet transmits credentials in cleartext.","severity":"HIGH"},
    {"ports":[21],"services":["ftp"],"risk":"FTP — Potential Anonymous Access","description":"FTP may allow anonymous login and uses cleartext.","severity":"HIGH"},
    {"ports":[80,8080,8000],"services":["http"],"risk":"HTTP — Unencrypted Web","description":"Unencrypted HTTP exposes data and web attack surface.","severity":"MEDIUM"},
    {"ports":[445,139],"services":["smb","microsoft-ds","netbios"],"risk":"SMB Exposed — EternalBlue Risk","description":"SMB exposure linked to critical exploits (MS17-010/WannaCry).","severity":"CRITICAL"},
    {"ports":[3389],"services":["rdp","ms-wbt-server"],"risk":"RDP Exposed","description":"RDP is a frequent brute force and BlueKeep target.","severity":"HIGH"},
    {"ports":[1433,3306,5432,27017,6379],"services":["mysql","mssql","postgresql","mongodb","redis"],"risk":"Database Exposed","description":"Database services should never be directly exposed.","severity":"CRITICAL"},
    {"ports":[161],"services":["snmp"],"risk":"SNMP Exposed","description":"SNMP v1/v2 uses weak community strings, leaks network info.","severity":"HIGH"},
]

def correlate_findings(nmap, nikto, whatweb):
    console.print("[cyan][*] Running correlation engine...[/cyan]")
    corr={"target":_get_target(nmap,nikto,whatweb),"risk_level":"LOW","open_ports":[],
          "detected_technologies":[],"triggered_rules":[],"compound_risks":[],"cve_summary":[],
          "attack_surface_score":0,"recommended_next_steps":[]}
    if nmap: corr["open_ports"]=nmap.get("ports",[])
    if whatweb: corr["detected_technologies"]=whatweb.get("technologies",[])
    _apply_rules(corr)
    _compound(corr,nmap,nikto,whatweb)
    _aggregate_cves(corr)
    _score(corr)
    _next_steps(corr,nmap,nikto,whatweb)
    console.print(f"[{'red' if corr['risk_level'] in ['CRITICAL','HIGH'] else 'yellow'}][+] Correlation done — Risk: {corr['risk_level']}[/{'red' if corr['risk_level'] in ['CRITICAL','HIGH'] else 'yellow'}]")
    return corr

def _get_target(nmap,nikto,whatweb):
    for f in [nmap,nikto,whatweb]:
        if f and "target" in f: return f["target"]
    return "unknown"

def _apply_rules(corr):
    pnums=[int(p["port"]) for p in corr["open_ports"]]
    svcs=[p["service"].lower() for p in corr["open_ports"]]
    for rule in RULES:
        if any(p in pnums for p in rule["ports"]) or any(s in svcs for s in rule["services"]):
            corr["triggered_rules"].append({"risk":rule["risk"],"description":rule["description"],"severity":rule["severity"]})

def _compound(corr,nmap,nikto,whatweb):
    pnums=[int(p["port"]) for p in corr["open_ports"]]
    svcs=[p["service"].lower() for p in corr["open_ports"]]
    has_ssh=22 in pnums or "ssh" in svcs
    has_web=any(p in pnums for p in [80,443,8080,8000])
    has_db=any(p in pnums for p in [1433,3306,5432,27017,6379])
    has_outdated=nikto and any("outdated" in v.get("msg","").lower() for v in nikto.get("vulnerabilities",[]))
    if has_ssh and has_web:
        corr["compound_risks"].append({"risk":"Web + SSH pivot path","description":"Web compromise could enable SSH lateral movement.","severity":"HIGH"})
    if has_db and has_web:
        corr["compound_risks"].append({"risk":"Database + Web = Critical SQLi impact","description":"Exposed DB + web app amplifies SQL injection impact.","severity":"CRITICAL"})
    if has_outdated and len(pnums)>3:
        corr["compound_risks"].append({"risk":"Outdated software + wide attack surface","description":"Outdated versions + multiple open ports = high exploit probability.","severity":"HIGH"})
    if nikto:
        hi=[v for v in nikto.get("vulnerabilities",[]) if v["severity"]=="HIGH"]
        if hi and len(pnums)>2:
            corr["compound_risks"].append({"risk":f"Web HIGH findings + multi-service","description":f"{len(hi)} high-severity web finding(s) with {len(pnums)} open ports.","severity":"HIGH"})

def _aggregate_cves(corr):
    seen=set()
    for p in corr["open_ports"]:
        for c in p.get("cves",[]):
            if c["cve_id"] not in seen:
                seen.add(c["cve_id"]); c["context"]=f"Port {p['port']} ({p['service']})"
                corr["cve_summary"].append(c)
    for t in corr["detected_technologies"]:
        for c in t.get("cves",[]):
            if c["cve_id"] not in seen:
                seen.add(c["cve_id"]); c["context"]=f"Tech: {t['name']}"
                corr["cve_summary"].append(c)
    corr["cve_summary"].sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

def _score(corr):
    s=len(corr["open_ports"])*2
    sp={"CRITICAL":20,"HIGH":12,"MEDIUM":6,"LOW":2}
    for r in corr["triggered_rules"]: s+=sp.get(r["severity"],2)
    for r in corr["compound_risks"]: s+={"CRITICAL":25,"HIGH":15,"MEDIUM":8,"LOW":3}.get(r["severity"],3)
    crit=[c for c in corr["cve_summary"] if c["severity"]=="CRITICAL"]
    hi=[c for c in corr["cve_summary"] if c["severity"]=="HIGH"]
    s+=len(crit)*10+len(hi)*5
    corr["attack_surface_score"]=s
    if s>=60 or crit: corr["risk_level"]="CRITICAL"
    elif s>=35: corr["risk_level"]="HIGH"
    elif s>=15: corr["risk_level"]="MEDIUM"
    else: corr["risk_level"]="LOW"

def _next_steps(corr,nmap,nikto,whatweb):
    steps=[]; pnums=[int(p["port"]) for p in corr["open_ports"]]; svcs={p["service"].lower() for p in corr["open_ports"]}
    if 22 in pnums or "ssh" in svcs: steps.append("Check SSH version against known CVEs and test for weak credentials")
    if any(p in pnums for p in [80,443,8080]): steps.append("Run full web app scan (OWASP ZAP/Burp Suite) and enumerate directories")
    if 21 in pnums or "ftp" in svcs: steps.append("Test FTP anonymous access: ftp <target> with user 'anonymous'")
    if any(p in pnums for p in [1433,3306,5432]): steps.append("Database exposed — check for default credentials")
    if any(p in pnums for p in [445,139]): steps.append("Enumerate SMB shares and check MS17-010 (EternalBlue)")
    if 3389 in pnums: steps.append("Check RDP for BlueKeep (CVE-2019-0708)")
    if not steps: steps.append("Run aggressive scan: nmap -A -p- <target>")
    corr["recommended_next_steps"]=steps
