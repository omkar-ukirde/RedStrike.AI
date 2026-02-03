"""
RedStrike.AI - Injection Tester Subagent
Handles injection testing: XSS, SQLi, SSRF, XXE, RCE, SSTI.
OWASP A03, A10, API7, API10
"""
from typing import Dict, Any, List
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState, Finding
from app.models.llm_router import get_model_for_agent
from app.tools import INJECTION_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.agents.skill_subagent import (
    create_skill_aware_subagent,
    get_skill_categories_for_agent,
)

SYSTEM_PROMPT = """You are the Injection Tester Subagent for RedStrike.AI.

Your role is to test for all types of injection vulnerabilities.

OWASP Coverage:
- A03:2021 Injection (SQLi, OS Command, LDAP)
- A10:2021 SSRF
- API7:2023 SSRF
- API10:2023 Unsafe API Consumption

Vulnerability Types:
1. **SQL Injection**: Union, Blind (boolean/time), Error-based, Stacked
2. **XSS**: Reflected, Stored, DOM-based
3. **SSRF**: Internal services, Cloud metadata, Port scanning
4. **XXE**: XML External Entity
5. **RCE**: Remote Code Execution, OS Command Injection
6. **SSTI**: Server-Side Template Injection
7. **LFI/RFI**: Local/Remote File Inclusion
8. **LDAP Injection**: LDAP query manipulation

Methodology:
1. Review loaded skills for payloads and techniques
2. Identify injection points from discovery results
3. Test each injection type systematically using skill knowledge
4. Verify potential findings before reporting
5. Document working payloads with evidence

CRITICAL: For each potential finding, mark verification_status as "pending".
The Verifier subagent will confirm before final report.

Output Format:
{
    "potential_findings": [
        {
            "title": "SQL Injection in login",
            "severity": "critical",
            "vulnerability_type": "sqli",
            "affected_url": "/api/login",
            "affected_parameter": "username",
            "description": "Boolean-based blind SQLi",
            "evidence": "Response difference with ' OR '1'='1",
            "verification_status": "pending",
            "owasp_category": "A03:2021"
        }
    ]
}"""


def create_injection_tester_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Injection tester subagent node with skill-aware implementation.
    
    Uses progressive skill disclosure and context management
    per LangGraph deep agents specification.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with potential injection findings
    """
    model = get_model_for_agent("injection_tester")
    target = state["target"]["url"]
    
    # Get skill categories for this agent type
    skill_categories = get_skill_categories_for_agent("injection_tester")
    
    # Create skill-aware agent with context management
    agent = create_skill_aware_subagent(
        model=model,
        tools=INJECTION_LANGCHAIN_TOOLS,
        skill_categories=skill_categories,
        base_prompt=SYSTEM_PROMPT,
        max_context_messages=25,
        include_skill_references=True,  # Include detailed payloads
    )
    
    # Get discovered endpoints and parameters
    discovery = state.get("discovery_results", {})
    
    # Build task message with context
    task_message = f"""Test for injection vulnerabilities on: {target}

Discovered endpoints: {discovery.get("endpoints", {})}
Discovered parameters: {discovery.get("parameters", {})}

Use the payloads and techniques from your skill knowledge base.
Test for SQL Injection, XSS, SSRF, XXE, RCE, SSTI, LFI.
Mark all findings as verification_status: "pending"."""
    
    messages = [HumanMessage(content=task_message)]
    
    try:
        result = agent.invoke({"messages": messages})
        
        # Parse potential findings from result
        # In real implementation, parse structured output
        potential_findings = state.get("potential_findings", [])
        
        return {
            "potential_findings": potential_findings,
            "current_phase": "injection_testing_complete",
            "phase_history": state.get("phase_history", []) + ["injection_testing"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "injection_testing",
                "error": str(e),
            }],
            "current_phase": "injection_testing_error",
        }
