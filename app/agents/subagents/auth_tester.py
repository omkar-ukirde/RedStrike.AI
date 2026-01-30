"""
RedStrike.AI - Auth Tester Subagent
Handles authentication testing: IDOR, auth bypass, session, JWT.
OWASP A01, A07, API1-5
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import INJECTION_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Authentication Tester Subagent for RedStrike.AI.

Your role is to test for authentication and authorization vulnerabilities.

OWASP Coverage:
- A01:2021 Broken Access Control (IDOR, privilege escalation)
- A07:2021 Identification and Authentication Failures
- API1:2023 Broken Object Level Authorization (BOLA)
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API5:2023 Broken Function Level Authorization

Vulnerability Types:
1. **IDOR**: Insecure Direct Object References
2. **Auth Bypass**: Authentication bypass techniques
3. **Session Issues**: Session fixation, hijacking
4. **JWT Attacks**: Algorithm confusion, weak secrets, token reuse
5. **OAuth Flaws**: Redirect URI manipulation, token leakage
6. **Brute Force**: Weak password policies, rate limiting
7. **Privilege Escalation**: Horizontal and vertical
8. **Mass Assignment**: Unexpected property access

Methodology:
1. Identify auth mechanisms (session, JWT, OAuth)
2. Test for IDOR on all ID-based endpoints
3. Check for auth bypass techniques
4. Analyze JWT tokens if present
5. Test privilege escalation paths

For IDOR Testing:
- Change ID values (1, 2, 100, 0, -1, null)
- Try UUID manipulation
- Test both numeric and string IDs

CRITICAL: Mark verification_status as "pending" for all findings.

Output Format:
{
    "potential_findings": [
        {
            "title": "IDOR in user profile",
            "severity": "high",
            "vulnerability_type": "idor",
            "affected_url": "/api/users/123",
            "description": "Can access other users' profiles by changing ID",
            "evidence": "Changed ID from 123 to 124, got different user data",
            "verification_status": "pending",
            "owasp_category": "A01:2021"
        }
    ]
}"""


def create_auth_tester_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Authentication tester subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with auth-related findings
    """
    model = get_model_for_agent("auth_tester")
    target = state["target"]["url"]
    credentials = state["target"].get("credentials", {})
    
    # Load relevant skills
    skill_context = skill_loader.get_skill_context(["vulnerabilities"])
    
    # Get discovered endpoints
    discovery = state.get("discovery_results", {})
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Test for authentication vulnerabilities on: {target}

Credentials available: {"Yes" if credentials else "No (blackbox)"}
Credential type: {credentials.get("type", "none") if credentials else "none"}

Discovered endpoints: {discovery.get("endpoints", {})}

Skills/Knowledge:
{skill_context if skill_context else "No specific skills loaded."}

Test for IDOR, auth bypass, session issues, JWT attacks.
Mark all findings as verification_status: "pending".""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, INJECTION_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        potential_findings = state.get("potential_findings", [])
        
        return {
            "potential_findings": potential_findings,
            "current_phase": "auth_testing_complete",
            "phase_history": state.get("phase_history", []) + ["auth_testing"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "auth_testing",
                "error": str(e),
            }],
            "current_phase": "auth_testing_error",
        }
