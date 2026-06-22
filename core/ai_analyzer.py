"""
APTA — AI Analysis Layer v2
Supports multiple AI providers:
- Google Gemini  (GEMINI_API_KEY)  -- FREE at aistudio.google.com
- Groq           (GROQ_API_KEY)    -- FREE at console.groq.com
- Anthropic Claude (ANTHROPIC_API_KEY) -- paid
Auto-detects which key is available and uses it.
"""

import json, os
from rich.console import Console
console = Console()

SYSTEM_PROMPT = """You are APTA's AI security analyst. You receive pre-processed structured scan data.

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


def analyze_with_ai(correlation, nmap, nikto, whatweb):
    """
    Auto-detects available AI provider and uses it.
    Priority: Gemini -> Groq -> Claude -> Fallback
    """
    scan_data   = _build_scan_data(correlation, nmap, nikto, whatweb)
    user_prompt = (
        f"Analyze this penetration testing data for target: {scan_data['target']}\n\n"
        f"DATA:\n{json.dumps(scan_data, indent=2)}\n\n"
        f"Generate a professional security assessment based ONLY on the data above."
    )

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    groq_key   = os.getenv("GROQ_API_KEY",   "").strip()
    claude_key = os.getenv("ANTHROPIC_API_KEY", "").strip()

    if gemini_key:
        console.print("[cyan][*] Using Google Gemini for AI analysis...[/cyan]")
        result = _use_gemini(gemini_key, user_prompt)
        if result: return result

    if groq_key:
        console.print("[cyan][*] Using Groq (Llama3) for AI analysis...[/cyan]")
        result = _use_groq(groq_key, user_prompt)
        if result: return result

    if claude_key:
        console.print("[cyan][*] Using Anthropic Claude for AI analysis...[/cyan]")
        result = _use_claude(claude_key, user_prompt)
        if result: return result

    console.print("[yellow][!] No AI provider available — using fallback analysis[/yellow]")
    console.print("[dim]    Add GEMINI_API_KEY, GROQ_API_KEY or ANTHROPIC_API_KEY to .env[/dim]")
    return _fallback(correlation)


# ─── GEMINI ──────────────────────────────────────────────────────────────────
def _use_gemini(api_key, prompt):
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=SYSTEM_PROMPT + "\n\n" + prompt
        )
        console.print("[green][+] Gemini analysis complete[/green]")
        return _parse(response.text)
    except Exception as e:
        console.print(f"[red][-] Gemini error: {e}[/red]")
        return None


# ─── GROQ ─────────────────────────────────────────────────────────────────────
def _use_groq(api_key, prompt):
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt}
            ],
            max_tokens=3000,
            temperature=0.3
        )
        console.print("[green][+] Groq analysis complete[/green]")
        return _parse(response.choices[0].message.content)
    except Exception as e:
        console.print(f"[red][-] Groq error: {e}[/red]")
        return None


# ─── CLAUDE ───────────────────────────────────────────────────────────────────
def _use_claude(api_key, prompt):
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        model  = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        msg = client.messages.create(
            model=model,
            max_tokens=3000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}]
        )
        console.print("[green][+] Claude analysis complete[/green]")
        return _parse(msg.content[0].text)
    except Exception as e:
        console.print(f"[red][-] Claude error: {e}[/red]")
        return None


# ─── HELPERS ──────────────────────────────────────────────────────────────────
def _build_scan_data(correlation, nmap, nikto, whatweb):
    return {
        "target":       correlation.get("target"),
        "overall_risk": correlation.get("risk_level"),
        "score":        correlation.get("attack_surface_score"),
        "open_ports": [
            {
                "port":    p["port"],
                "service": p["service"],
                "product": p.get("product", ""),
                "version": p.get("version", ""),
                "top_cves": [
                    {
                        "id":       c["cve_id"],
                        "severity": c["severity"],
                        "score":    c.get("cvss_score"),
                        "summary":  c["description"][:150]
                    }
                    for c in p.get("cves", [])[:3]
                ]
            }
            for p in correlation.get("open_ports", [])
        ],
        "technologies": [
            {"name": t["name"], "version": t.get("version")}
            for t in correlation.get("detected_technologies", [])
        ],
        "rules_triggered": correlation.get("triggered_rules", []),
        "compound_risks":  correlation.get("compound_risks",  []),
        "web_findings": [
            {"severity": v["severity"], "msg": v["msg"][:200]}
            for v in (nikto.get("vulnerabilities", []) if nikto else [])
        ][:15],
        "total_cves":    len(correlation.get("cve_summary", [])),
        "critical_cves": [
            c for c in correlation.get("cve_summary", [])
            if c.get("severity") in ["CRITICAL", "HIGH"]
        ][:5]
    }


def _parse(raw):
    if not raw:
        return None
    cleaned = raw.strip()
    # Strip markdown code fences if present
    if cleaned.startswith("```"):
        lines   = cleaned.split("\n")
        cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        analysis = json.loads(cleaned)
        analysis["ai_powered"] = True
        return analysis
    except json.JSONDecodeError:
        console.print("[yellow][!] Could not parse AI response as JSON — using fallback[/yellow]")
        return None


def _fallback(correlation):
    risk  = correlation.get("risk_level", "UNKNOWN")
    ports = len(correlation.get("open_ports", []))
    cves  = len(correlation.get("cve_summary", []))
    return {
        "ai_powered": False,
        "executive_summary": (
            f"Target presents {risk} risk with {ports} open services "
            f"and {cves} CVEs identified. Manual review recommended."
        ),
        "risk_narrative": (
            f"APTA identified {ports} open port(s). "
            f"{len(correlation.get('triggered_rules', []))} security rules triggered. "
            f"{len(correlation.get('compound_risks',  []))} compound risks detected. "
            f"{cves} CVEs found. "
            f"Add GEMINI_API_KEY, GROQ_API_KEY or ANTHROPIC_API_KEY to .env for full AI analysis."
        ),
        "key_findings": [
            {
                "title":       r["risk"],
                "severity":    r["severity"],
                "explanation": r["description"],
                "evidence":    "APTA correlation engine"
            }
            for r in correlation.get("triggered_rules", [])
        ],
        "attack_paths": correlation.get("recommended_next_steps", []),
        "remediation_priorities": [
            {"priority": i + 1, "action": s, "rationale": "APTA correlation engine"}
            for i, s in enumerate(correlation.get("recommended_next_steps", [])[:5])
        ],
        "analyst_notes": (
            "AI analysis unavailable. "
            "Add GEMINI_API_KEY (free at aistudio.google.com) or "
            "GROQ_API_KEY (free at console.groq.com) to .env."
        )
    }