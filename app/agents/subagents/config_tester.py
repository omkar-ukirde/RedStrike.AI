"""
RedStrike.AI - Config Tester Subagent
Handles configuration testing: headers, SSL, misconfigs, secrets.
OWASP A02, A05, A08, A09, API8
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import SCANNER_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Configuration Tester Subagent for RedStrike.AI.

Your role is to test for security misconfigurations.

OWASP Coverage:
- A02:2021 Cryptographic Failures
- A05:2021 Security Misconfiguration
- A08:2021 Software and Data Integrity Failures
- A09:2021 Security Logging and Monitoring Failures
- API8:2023 Security Misconfiguration

Vulnerability Types:
1. **Security Headers**: Missing/misconfigured headers
2. **CORS**: Overly permissive CORS
3. **SSL/TLS**: Weak ciphers, expired certs, protocol issues
4. **Error Disclosure**: Verbose errors exposing info
5. **Default Credentials**: Default admin passwords
6. **Exposed Services**: Debug endpoints, admin panels
7. **Hardcoded Secrets**: API keys, tokens in responses
8. **Insecure Deserialization**: Unsafe object handling
9. **Logging Issues**: Sensitive data in logs

Security Headers to Check:
- X-Frame-Options (Clickjacking)
- X-Content-Type-Options (MIME sniffing)
- X-XSS-Protection (XSS filter)
- Content-Security-Policy (XSS, injection)
- Strict-Transport-Security (HTTPS enforcement)
- Referrer-Policy (Info leakage)
- Permissions-Policy (Feature restrictions)
- Cache-Control (Sensitive data caching)

CORS Checks:
- Access-Control-Allow-Origin: * (overly permissive)
- Reflected origin without validation
- Null origin allowed
- Credentials with wildcard

Output Format:
{
    "potential_findings": [
        {
            "title": "Missing Content-Security-Policy",
            "severity": "medium",
            "vulnerability_type": "security_header",
            "affected_url": "/",
            "description": "CSP header not set, XSS protection reduced",
            "evidence": "Response headers lack CSP",
            "verification_status": "pending",
            "owasp_category": "A05:2021"
        }
    ]
}"""


def create_config_tester_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Configuration tester subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with config-related findings
    """
    model = get_model_for_agent("config_tester")
    target = state["target"]["url"]
    
    # Load relevant skills
    skill_context = skill_loader.get_skill_context(["vulnerabilities"])
    
    # Get recon results (headers, SSL info)
    recon = state.get("recon_results", {})
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Test for security misconfigurations on: {target}

Previous recon results: {recon}

Skills/Knowledge:
{skill_context if skill_context else "No specific skills loaded."}

Check security headers, CORS, SSL/TLS, error disclosure, secrets.
Mark all findings as verification_status: "pending".""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, SCANNER_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        potential_findings = state.get("potential_findings", [])
        
        return {
            "potential_findings": potential_findings,
            "current_phase": "config_testing_complete",
            "phase_history": state.get("phase_history", []) + ["config_testing"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "config_testing",
                "error": str(e),
            }],
            "current_phase": "config_testing_error",
        }
