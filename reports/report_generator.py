import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from rich.console import Console
console = Console()

C_DARK=colors.HexColor("#1a1a2e"); C_ACCENT=colors.HexColor("#0f3460")
C_RED=colors.HexColor("#dc3545"); C_ORANGE=colors.HexColor("#fd7e14")
C_YELLOW=colors.HexColor("#ffc107"); C_GREEN=colors.HexColor("#28a745")
C_LIGHT=colors.HexColor("#f8f9fa"); C_BORDER=colors.HexColor("#dee2e6")
SEV_COLORS={"CRITICAL":C_RED,"HIGH":C_ORANGE,"MEDIUM":C_YELLOW,"LOW":C_GREEN}
TB={"style":"SINGLE","size":4,"color":"AAAAAA"}
def bdr(): return {"top":TB,"bottom":TB,"left":TB,"right":TB}

def hcell(t,w):
    from reportlab.platypus import TableCell
    return Table([[Paragraph(t,ParagraphStyle("hc",fontSize=9,fontName="Helvetica-Bold",textColor=colors.white,alignment=1))]],
                 colWidths=[w])

def generate_report(target,correlation,nmap_findings,nikto_findings,whatweb_findings,ai_analysis,output_path):
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".",exist_ok=True)
    console.print("[cyan][*] Generating PDF report...[/cyan]")
    doc=SimpleDocTemplate(output_path,pagesize=A4,rightMargin=2*cm,leftMargin=2*cm,topMargin=2.5*cm,bottomMargin=2*cm)
    styles=getSampleStyleSheet()
    ST={"title":ParagraphStyle("t",fontSize=20,fontName="Helvetica-Bold",alignment=1,spaceAfter=8),
        "section":ParagraphStyle("s",fontSize=13,fontName="Helvetica-Bold",spaceBefore=14,spaceAfter=6),
        "sub":ParagraphStyle("sb",fontSize=10,fontName="Helvetica-Bold",spaceBefore=8,spaceAfter=4,textColor=C_ACCENT),
        "body":ParagraphStyle("b",fontSize=9,fontName="Helvetica",spaceAfter=5,leading=13,alignment=TA_JUSTIFY,textColor=colors.HexColor("#343a40")),
        "small":ParagraphStyle("sm",fontSize=8,fontName="Helvetica",spaceAfter=3,leading=11,textColor=colors.HexColor("#545454")),
        "code":ParagraphStyle("cd",fontSize=8,fontName="Courier",spaceAfter=3,leading=11,backColor=C_LIGHT,leftIndent=8),
        "bullet":ParagraphStyle("bl",fontSize=9,fontName="Helvetica",spaceAfter=3,leading=13,leftIndent=14)}
    story=[]
    risk=correlation.get("risk_level","UNKNOWN")
    rc=SEV_COLORS.get(risk,colors.grey)
    now=datetime.now().strftime("%B %d, %Y at %H:%M")

    # Cover
    story.append(Spacer(1,1*cm))
    cover=Table([[Paragraph("APTA SECURITY REPORT",ParagraphStyle("cv",fontSize=20,fontName="Helvetica-Bold",textColor=colors.white,alignment=1))],
                 [Paragraph(f"Target: {target}",ParagraphStyle("ct",fontSize=13,fontName="Helvetica",textColor=colors.HexColor("#adb5bd"),alignment=1))]],colWidths=[17*cm])
    cover.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_DARK),("BACKGROUND",(0,1),(-1,1),C_ACCENT),
                                ("TOPPADDING",(0,0),(-1,-1),14),("BOTTOMPADDING",(0,0),(-1,-1),14)]))
    story.append(cover); story.append(Spacer(1,0.6*cm))
    meta=[["Target",target],["Date",now],["Risk Level",risk],["Open Ports",str(len(correlation.get("open_ports",[])))],
          ["CVEs Found",str(len(correlation.get("cve_summary",[])))],["AI Powered","Yes" if ai_analysis.get("ai_powered") else "No"],["Tools","Nmap + Nikto + WhatWeb"]]
    mt=Table([[Paragraph(f"<b>{r[0]}</b>",ST["small"]),Paragraph(str(r[1]),ST["small"])] for r in meta],colWidths=[5*cm,12*cm])
    mt.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),C_LIGHT),("GRID",(0,0),(-1,-1),0.5,C_BORDER),
                             ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),8)]))
    story.append(mt); story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%",thickness=3,color=C_RED))
    story.append(Paragraph("AUTHORIZED USE ONLY — Only scan systems you own or have explicit written permission to test.",
                            ParagraphStyle("disc",fontSize=8,fontName="Helvetica",textColor=C_RED,alignment=1,spaceBefore=8)))
    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("1. Executive Summary",ST["section"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
    story.append(Paragraph(ai_analysis.get("executive_summary",f"Target presents {risk} risk."),ST["body"]))
    rt=Table([[Paragraph(f"<b>Overall Risk: {risk}</b>",ParagraphStyle("rb",fontSize=13,fontName="Helvetica-Bold",textColor=colors.white,alignment=1))]],colWidths=[17*cm])
    rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),rc),("TOPPADDING",(0,0),(-1,-1),10),("BOTTOMPADDING",(0,0),(-1,-1),10)]))
    story.append(Spacer(1,0.2*cm)); story.append(rt); story.append(Spacer(1,0.3*cm))
    if ai_analysis.get("risk_narrative"):
        story.append(Paragraph("Risk Narrative",ST["sub"]))
        story.append(Paragraph(ai_analysis["risk_narrative"],ST["body"]))

    # Risk Overview
    story.append(Paragraph("2. Risk Overview",ST["section"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
    if correlation.get("triggered_rules"):
        story.append(Paragraph("Triggered Security Rules",ST["sub"]))
        rd=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["Risk","Severity","Description"]]]
        for r in correlation["triggered_rules"]:
            sc=SEV_COLORS.get(r["severity"],colors.grey)
            rd.append([Paragraph(r["risk"],ST["small"]),
                       Paragraph(f'<font color="{sc.hexval()}">{r["severity"]}</font>',ST["small"]),
                       Paragraph(r["description"][:180],ST["small"])])
        tbl=Table(rd,colWidths=[4.5*cm,2*cm,10.5*cm])
        tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                  ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                  ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                                  ("LEFTPADDING",(0,0),(-1,-1),5),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(tbl); story.append(Spacer(1,0.3*cm))
    if correlation.get("compound_risks"):
        story.append(Paragraph("Compound Risks",ST["sub"]))
        for r in correlation["compound_risks"]:
            sc=SEV_COLORS.get(r.get("severity","MEDIUM"),colors.grey)
            t=Table([[Paragraph(f'<b><font color="{sc.hexval()}">[{r.get("severity","?")}]</font> {r["risk"]}</b>',ST["small"])],
                     [Paragraph(r["description"],ST["small"])]],colWidths=[17*cm])
            t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.3,C_BORDER),("BACKGROUND",(0,0),(-1,-1),C_LIGHT),
                                    ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("LEFTPADDING",(0,0),(-1,-1),8)]))
            story.append(t); story.append(Spacer(1,0.15*cm))

    # Nmap
    story.append(Paragraph("3. Network Scan (Nmap)",ST["section"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
    if nmap_findings and nmap_findings.get("ports"):
        if nmap_findings.get("os_detection"):
            story.append(Paragraph(f"<b>OS:</b> {nmap_findings['os_detection'][0]['name']} ({nmap_findings['os_detection'][0]['accuracy']})",ST["body"]))
        pd=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["Port","Service","Product/Version","CVEs"]]]
        for p in nmap_findings["ports"]:
            vs=p.get("product",""); vs+=(f" {p['version']}" if p.get("version") else "")
            cc=len(p.get("cves",[])); cs=f"⚠ {cc}" if cc else "0"
            pd.append([Paragraph(f"{p['port']}/{p['protocol']}",ST["small"]),Paragraph(p["service"],ST["small"]),
                       Paragraph(vs or "—",ST["small"]),Paragraph(cs,ST["small"])])
        pt=Table(pd,colWidths=[3*cm,3.5*cm,7.5*cm,3*cm])
        pt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                 ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                 ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),5)]))
        story.append(pt)
    else:
        story.append(Paragraph("No results.",ST["body"]))

    # Nikto
    if nikto_findings:
        story.append(Spacer(1,0.4*cm)); story.append(Paragraph("4. Web Scan (Nikto)",ST["section"]))
        story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
        vulns=nikto_findings.get("vulnerabilities",[])
        if vulns:
            vd=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["Severity","Finding"]]]
            for v in vulns[:25]:
                sc=SEV_COLORS.get(v.get("severity","LOW"),colors.grey)
                vd.append([Paragraph(f'<font color="{sc.hexval()}"><b>{v.get("severity","LOW")}</b></font>',ST["small"]),
                           Paragraph(v.get("msg","")[:250],ST["small"])])
            vt=Table(vd,colWidths=[2.5*cm,14.5*cm])
            vt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                     ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                     ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                                     ("LEFTPADDING",(0,0),(-1,-1),5),("VALIGN",(0,0),(-1,-1),"TOP")]))
            story.append(vt)
        else:
            story.append(Paragraph("No significant vulnerabilities found.",ST["body"]))

    # WhatWeb
    if whatweb_findings and whatweb_findings.get("technologies"):
        story.append(Spacer(1,0.4*cm)); story.append(Paragraph("5. Technology Fingerprint (WhatWeb)",ST["section"]))
        story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
        td=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["Technology","Version","CVEs"]]]
        for t in whatweb_findings["technologies"]:
            cc=len(t.get("cves",[])); cs=f"⚠ {cc}" if cc else "0"
            td.append([Paragraph(t["name"],ST["small"]),Paragraph(t.get("version") or "—",ST["small"]),Paragraph(cs,ST["small"])])
        tt=Table(td,colWidths=[7*cm,6*cm,4*cm])
        tt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                 ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                 ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),5)]))
        story.append(tt)

    # CVEs
    if correlation.get("cve_summary"):
        story.append(PageBreak()); story.append(Paragraph("6. CVE Intelligence",ST["section"]))
        story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
        cd=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["CVE ID","Severity","Score","Context","Description"]]]
        for c in correlation["cve_summary"][:20]:
            sc=SEV_COLORS.get(c.get("severity","UNKNOWN"),colors.grey)
            cd.append([Paragraph(c.get("cve_id",""),ST["small"]),
                       Paragraph(f'<font color="{sc.hexval()}"><b>{c.get("severity","?")}</b></font>',ST["small"]),
                       Paragraph(str(c.get("cvss_score") or "—"),ST["small"]),
                       Paragraph(c.get("context",""),ST["small"]),
                       Paragraph(c.get("description","")[:150],ST["small"])])
        ct=Table(cd,colWidths=[3*cm,2*cm,1.5*cm,3*cm,7.5*cm])
        ct.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                 ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                 ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                                 ("LEFTPADDING",(0,0),(-1,-1),4),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),7.5)]))
        story.append(ct)

    # AI Analysis
    story.append(PageBreak()); story.append(Paragraph("7. AI-Powered Analysis",ST["section"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
    if not ai_analysis.get("ai_powered"):
        story.append(Paragraph("AI analysis not performed — add ANTHROPIC_API_KEY to .env for full analysis.",ST["body"]))
    else:
        if ai_analysis.get("key_findings"):
            story.append(Paragraph("Key Findings",ST["sub"]))
            for f in ai_analysis["key_findings"]:
                sc=SEV_COLORS.get(f.get("severity","INFO"),colors.grey)
                t=Table([[Paragraph(f'<b><font color="{sc.hexval()}">[{f.get("severity","?")}]</font> {f.get("title","")}</b>',ST["small"])],
                          [Paragraph(f.get("explanation",""),ST["small"])],
                          [Paragraph(f'<i>Evidence: {f.get("evidence","")}</i>',ST["small"])]],colWidths=[17*cm])
                t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),C_LIGHT),("GRID",(0,0),(-1,-1),0.3,C_BORDER),
                                        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),("LEFTPADDING",(0,0),(-1,-1),8)]))
                story.append(t); story.append(Spacer(1,0.15*cm))
        if ai_analysis.get("attack_paths"):
            story.append(Spacer(1,0.2*cm)); story.append(Paragraph("Theoretical Attack Paths",ST["sub"]))
            for i,p in enumerate(ai_analysis["attack_paths"],1):
                story.append(Paragraph(f"{i}. {p}",ST["bullet"]))

    # Recommendations
    story.append(Spacer(1,0.4*cm)); story.append(Paragraph("8. Recommendations",ST["section"]))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER)); story.append(Spacer(1,0.2*cm))
    prios=ai_analysis.get("remediation_priorities",[])
    if prios:
        rd=[[Paragraph(f"<b>{h}</b>",ST["small"]) for h in ["#","Action","Rationale"]]]
        for r in prios:
            rd.append([Paragraph(f"#{r.get('priority','?')}",ST["small"]),
                       Paragraph(r.get("action",""),ST["small"]),Paragraph(r.get("rationale",""),ST["small"])])
        rt=Table(rd,colWidths=[1.5*cm,8.5*cm,7*cm])
        rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),C_ACCENT),("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                 ("GRID",(0,0),(-1,-1),0.5,C_BORDER),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LIGHT]),
                                 ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                                 ("LEFTPADDING",(0,0),(-1,-1),5),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(rt)
    else:
        for i,s in enumerate(correlation.get("recommended_next_steps",[]),1):
            story.append(Paragraph(f"{i}. {s}",ST["bullet"]))

    # Footer
    story.append(Spacer(1,0.8*cm)); story.append(HRFlowable(width="100%",thickness=1,color=C_BORDER))
    story.append(Paragraph("Legal: This report is for authorized penetration testing only. All findings require manual verification. APTA does not confirm exploitability.",
                            ParagraphStyle("ft",fontSize=7,fontName="Helvetica",textColor=colors.HexColor("#adb5bd"))))
    story.append(Paragraph(f"Generated by APTA v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M')} | EMSI Cybersecurity PFA",
                            ParagraphStyle("ft2",fontSize=7,fontName="Helvetica",textColor=colors.HexColor("#adb5bd"),alignment=1)))
    doc.build(story)
    console.print(f"[green][+] Report saved: {output_path}[/green]")
    return output_path
