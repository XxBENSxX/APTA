import requests, time, os
from rich.console import Console
console = Console()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves(product, version, max_results=5):
    if not product: return []
    query = product.strip()
    if version: query += f" {version.strip()}"
    params={"keywordSearch":query,"resultsPerPage":max_results,"startIndex":0}
    headers={}
    key=os.getenv("NVD_API_KEY","")
    if key: headers["apiKey"]=key
    try:
        r=requests.get(NVD_URL,params=params,headers=headers,timeout=15)
        if r.status_code==200:
            cves=[]
            for v in r.json().get("vulnerabilities",[]):
                cd=v.get("cve",{})
                cid=cd.get("id","")
                desc=""
                for d in cd.get("descriptions",[]):
                    if d.get("lang")=="en": desc=d.get("value",""); break
                sev="UNKNOWN"; score=None
                for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                    ml=cd.get("metrics",{}).get(mk,[])
                    if ml:
                        cvd=ml[0].get("cvssData",{})
                        score=cvd.get("baseScore")
                        sev=ml[0].get("baseSeverity",cvd.get("baseSeverity","UNKNOWN"))
                        break
                cves.append({"cve_id":cid,"description":desc[:400],"severity":sev,"cvss_score":score,
                             "url":f"https://nvd.nist.gov/vuln/detail/{cid}"})
            return cves
        elif r.status_code==429:
            console.print("[yellow][!] NVD rate limit — waiting...[/yellow]")
            time.sleep(6); return search_cves(product,version,max_results)
    except Exception as e:
        console.print(f"[yellow][!] CVE lookup failed: {e}[/yellow]")
    return []

def enrich_nmap_with_cves(nmap_findings):
    if not nmap_findings: return nmap_findings
    console.print("[cyan][*] Enriching with CVE data from NIST NVD...[/cyan]")
    seen=set()
    for port in nmap_findings.get("ports",[]):
        prod=port.get("product",""); ver=port.get("version",""); svc=port.get("service","")
        key=prod or svc
        if key and key not in seen:
            seen.add(key)
            console.print(f"[dim]    Searching CVEs: {key} {ver}[/dim]")
            cves=search_cves(key,ver)
            port["cves"]=cves
            if cves:
                hi=[c for c in cves if c["severity"] in ["CRITICAL","HIGH"]]
                console.print(f"[{'red' if hi else 'yellow'}]    [{port['port']}] {len(cves)} CVEs{', '+str(len(hi))+' HIGH/CRIT' if hi else ''}[/{'red' if hi else 'yellow'}]")
            time.sleep(1.5 if not os.getenv("NVD_API_KEY") else 0.2)
        else:
            port["cves"]=[]
    console.print("[green][+] CVE enrichment complete[/green]")
    return nmap_findings

def enrich_whatweb_with_cves(whatweb_findings):
    if not whatweb_findings: return whatweb_findings
    HIGH_VALUE=["WordPress","Drupal","Joomla","Apache","Nginx","PHP","jQuery","Tomcat","OpenSSL","Laravel","Django"]
    seen=set()
    for t in whatweb_findings.get("technologies",[]):
        name=t.get("name",""); ver=t.get("version","")
        if name in HIGH_VALUE and name not in seen:
            seen.add(name)
            cves=search_cves(name,ver,max_results=3)
            t["cves"]=cves
            time.sleep(1.5 if not os.getenv("NVD_API_KEY") else 0.2)
        else:
            t["cves"]=[]
    return whatweb_findings
