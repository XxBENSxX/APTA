import anthropic, json, os
from rich.console import Console
console = Console()

def analyze_with_ai(correlation, nmap, nikto, whatweb):
    key=os.getenv("ANTHROPIC_API_KEY","")
    if not key:
        console.print("[red][-] No API key found in .env — using fallback[/red]")
        return _fallback(correlation)
    console.print("[cyan][*] Sending findings to Claude AI...[/cyan]")
    client=anthropic.Anthropic(api_key=key)
    model=os.getenv("ANTHROPIC_MODEL","claude-sonnet-4-6")
    system="""You are APTA's AI security analyst. You receive pre-processed, structured scan data.

STRICT RULES:
1. ONLY analyze findings present in the provided data. Never invent vulnerabilities.
2. Do NOT suggest exploit code or attack payloads.
3. If citing a CVE, it must be in the input data.
4. Frame findings as theoretical risks requiring human verification.

Respond ONLY with a JSON object:
{
  "executive_summary": "2-3 sentence overview",
  "risk_narrative": "3-4 paragraph professional narrative",
  "key_findings": [{"title":"","severity":"CRITICAL|HIGH|MEDIUM|LOW","explanation":"","evidence":""}],
  "attack_paths": ["theoretical path 1","theoretical path 2"],
  "remediation_priorities": [{"priority":1,"action":"","rationale":""}],
  "analyst_notes": "additional observations"
}
Return ONLY the JSON, no markdown, no preamble."""

    scan_data={
        "target":correlation.get("target"),
        "overall_risk":correlation.get("risk_level"),
        "score":correlation.get("attack_surface_score"),
        "open_ports":[{"port":p["port"],"service":p["service"],"product":p.get("product",""),
                        "version":p.get("version",""),"top_cves":[{"id":c["cve_id"],"severity":c["severity"],
                        "score":c.get("cvss_score"),"summary":c["description"][:150]} for c in p.get("cves",[])[:3]]}
                       for p in correlation.get("open_ports",[])],
        "technologies":[{"name":t["name"],"version":t.get("version")} for t in correlation.get("detected_technologies",[])],
        "rules_triggered":correlation.get("triggered_rules",[]),
        "compound_risks":correlation.get("compound_risks",[]),
        "web_findings":[{"severity":v["severity"],"msg":v["msg"][:200]}
                        for v in (nikto.get("vulnerabilities",[]) if nikto else [])][:15],
        "total_cves":len(correlation.get("cve_summary",[])),
        "critical_cves":[c for c in correlation.get("cve_summary",[]) if c.get("severity") in ["CRITICAL","HIGH"]][:5]
    }
    user=f"Analyze this penetration testing reconnaissance data for target: {scan_data['target']}\n\nDATA:\n{json.dumps(scan_data,indent=2)}\n\nGenerate a professional security assessment. Base analysis ONLY on the data above."
    try:
        msg=client.messages.create(model=model,max_tokens=3000,system=system,messages=[{"role":"user","content":user}])
        raw=msg.content[0].text
        console.print("[green][+] AI analysis complete[/green]")
        return _parse(raw, correlation)
    except anthropic.AuthenticationError:
        console.print("[red][-] Invalid API key[/red]"); return _fallback(correlation)
    except Exception as e:
        console.print(f"[red][-] AI error: {e}[/red]"); return _fallback(correlation)

def _parse(raw, correlation):
    cleaned=raw.strip()
    if cleaned.startswith("```"):
        lines=cleaned.split("\n")
        cleaned="\n".join(lines[1:-1] if lines[-1]=="```" else lines[1:])
    try:
        analysis=json.loads(cleaned)
        analysis["ai_powered"]=True
        return analysis
    except:
        console.print("[yellow][!] AI response not valid JSON — using fallback[/yellow]")
        fb=_fallback(correlation); fb["risk_narrative"]=raw; return fb

def _fallback(correlation):
    risk=correlation.get("risk_level","UNKNOWN")
    ports=len(correlation.get("open_ports",[]))
    cves=len(correlation.get("cve_summary",[]))
    return {
        "ai_powered":False,
        "executive_summary":f"Target presents {risk} risk with {ports} open services and {cves} CVEs identified.",
        "risk_narrative":f"APTA identified {ports} open port(s). {len(correlation.get('triggered_rules',[]))} security rules triggered. {cves} CVEs found. AI analysis unavailable — add API key to .env.",
        "key_findings":[{"title":r["risk"],"severity":r["severity"],"explanation":r["description"],"evidence":"APTA correlation engine"} for r in correlation.get("triggered_rules",[])],
        "attack_paths":correlation.get("recommended_next_steps",[]),
        "remediation_priorities":[{"priority":i+1,"action":s,"rationale":"APTA correlation engine"} for i,s in enumerate(correlation.get("recommended_next_steps",[])[:5])],
        "analyst_notes":"Add ANTHROPIC_API_KEY to .env for full AI analysis."
    }
