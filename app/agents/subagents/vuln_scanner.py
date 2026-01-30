"""
RedStrike.AI - Vuln Scanner Subagent
Handles automated vulnerability scanning: CVE, nuclei templates.
OWASP A06
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import SCANNER_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Vulnerability Scanner Subagent for RedStrike.AI.

Your role is to run automated vulnerability scanners and analyze results.

OWASP Coverage:
- A06:2021 Vulnerable and Outdated Components

Capabilities:
1. **Nuclei Scanning**: Template-based vulnerability detection
2. **CVE Detection**: Known vulnerability identification
3. **Version Detection**: Identify outdated components
4. **Dependency Analysis**: Check for vulnerable dependencies

Scan Categories:
- CVEs (critical, high severity first)
- Default credentials
- Exposed panels
- Misconfigurations
- Information disclosure
- Known exploits

Nuclei Template Categories:
- cves/: Known CVEs
- vulnerabilities/: General vulns
- exposed-panels/: Admin panels
- default-logins/: Default creds
- misconfiguration/: Misconfigs
- technologies/: Tech detection

Priority Order:
1. Critical CVEs
2. High severity CVEs
3. Default credentials
4. Exposed sensitive panels
5. Medium/Low findings

Output Format:
{
    "potential_findings": [
        {
            "title": "CVE-2021-44228 Log4Shell",
            "severity": "critical",
            "vulnerability_type": "cve",
            "affected_url": "/api/endpoint",
            "description": "Log4j RCE vulnerability detected",
            "evidence": "Nuclei template match: CVE-2021-44228",
            "verification_status": "pending",
            "owasp_category": "A06:2021",
            "cvss_score": 10.0
        }
    ]
}"""


def create_vuln_scanner_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Vulnerability scanner subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with scanner findings
    """
    model = get_model_for_agent("vuln_scanner")
    target = state["target"]["url"]
    
    # Get recon and discovery results for context
    recon = state.get("recon_results", {})
    discovery = state.get("discovery_results", {})
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Run vulnerability scanners on: {target}

Technologies detected: {recon.get("web", {}).get("technologies", [])}
Endpoints discovered: {discovery.get("endpoints", {})}

Run nuclei scans for CVEs and known vulnerabilities.
Prioritize critical and high severity findings.
Mark all findings as verification_status: "pending".""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, SCANNER_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        potential_findings = state.get("potential_findings", [])
        
        return {
            "potential_findings": potential_findings,
            "current_phase": "vuln_scanning_complete",
            "phase_history": state.get("phase_history", []) + ["vuln_scanning"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "vuln_scanning",
                "error": str(e),
            }],
            "current_phase": "vuln_scanning_error",
        }
