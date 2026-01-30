"""
RedStrike.AI - Logic Tester Subagent
Handles business logic testing: race conditions, workflow bypass.
OWASP A04, API4, API6
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import INJECTION_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Business Logic Tester Subagent for RedStrike.AI.

Your role is to test for business logic vulnerabilities.

OWASP Coverage:
- A04:2021 Insecure Design
- API4:2023 Unrestricted Resource Consumption
- API6:2023 Unrestricted Access to Sensitive Business Flows

Vulnerability Types:
1. **Race Conditions**: TOCTOU, double-spend, concurrent requests
2. **Workflow Bypass**: Skipping steps in multi-step processes
3. **Price Manipulation**: Changing prices, quantities, discounts
4. **Feature Abuse**: Using features in unintended ways
5. **Rate Limiting Bypass**: Evading rate limits
6. **Transaction Manipulation**: Altering transaction flow
7. **Inventory Manipulation**: Negative quantities, overflow

Common Business Logic Issues:
- E-commerce: Negative prices, excessive discounts, free items
- Banking: Double withdrawals, race condition transfers
- Authentication: Skip verification steps
- Subscriptions: Free premium features, trial extension
- Voting/Ratings: Multiple votes, rating manipulation

Race Condition Testing:
1. Identify state-changing operations
2. Send concurrent requests (10-100)
3. Check for inconsistent states
4. Document timing windows

Output Format:
{
    "potential_findings": [
        {
            "title": "Race condition in funds transfer",
            "severity": "critical",
            "vulnerability_type": "race_condition",
            "affected_url": "/api/transfer",
            "description": "Double-spend possible with concurrent requests",
            "evidence": "Sent 10 concurrent requests, balance went negative",
            "verification_status": "pending",
            "owasp_category": "A04:2021"
        }
    ]
}"""


def create_logic_tester_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Business logic tester subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with logic-related findings
    """
    model = get_model_for_agent("logic_tester")
    target = state["target"]["url"]
    
    # Load relevant skills
    skill_context = skill_loader.get_skill_context(["vulnerabilities"])
    
    discovery = state.get("discovery_results", {})
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Test for business logic vulnerabilities on: {target}

Discovered endpoints: {discovery.get("endpoints", {})}
Discovered parameters: {discovery.get("parameters", {})}

Skills/Knowledge:
{skill_context if skill_context else "No specific skills loaded."}

Test for race conditions, workflow bypass, and price manipulation.
Mark all findings as verification_status: "pending".""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, INJECTION_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        potential_findings = state.get("potential_findings", [])
        
        return {
            "potential_findings": potential_findings,
            "current_phase": "logic_testing_complete",
            "phase_history": state.get("phase_history", []) + ["logic_testing"],
            "messages": state.get("messages", []) + result.get("messages", []),
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "logic_testing",
                "error": str(e),
            }],
            "current_phase": "logic_testing_error",
        }
