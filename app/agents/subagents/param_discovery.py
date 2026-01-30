"""
RedStrike.AI - Parameter Discovery Subagent
Handles parameter discovery: hidden params, API endpoints.
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import DISCOVERY_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Parameter Discovery Subagent for RedStrike.AI.

Your role is to discover hidden parameters and inputs.

Capabilities:
1. **Parameter Mining**: Find hidden GET/POST parameters
2. **API Endpoint Analysis**: Discover API parameters
3. **Header Parameters**: Find custom header parameters
4. **Form Analysis**: Analyze form inputs

Why This Matters:
Hidden parameters are often:
- Debug parameters (debug=true, test=1)
- Admin parameters (admin=true, role=admin)
- Bypass parameters (token=, auth=)
- Legacy parameters (old_api=true)

Methodology:
1. Analyze known endpoints for parameters
2. Use parameter wordlists
3. Check for common hidden params
4. Test both GET and POST methods

Output Format:
{
    "parameters": [
        {
            "endpoint": "/api/users",
            "param": "debug",
            "method": "GET",
            "type": "hidden",
            "note": "Enables debug output"
        }
    ],
    "interesting": [
        {"endpoint": "/api/admin", "params": ["token", "bypass"]}
    ]
}"""


def create_param_discovery_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Parameter discovery subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with discovered parameters
    """
    model = get_model_for_agent("param_discovery")
    target = state["target"]["url"]
    
    # Get discovered endpoints
    endpoints = state.get("discovery_results", {}).get("endpoints", {})
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Discover hidden parameters on: {target}

Discovered endpoints: {endpoints}

Find hidden parameters on these endpoints.""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, DISCOVERY_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        # Update discovery results
        discovery_results = state.get("discovery_results") or {}
        discovery_results["parameters"] = {
            "raw_output": result.get("messages", [])[-1].content if result.get("messages") else "",
            "status": "completed",
        }
        
        return {
            "discovery_results": discovery_results,
            "current_phase": "param_discovery_complete",
            "phase_history": state.get("phase_history", []) + ["param_discovery"],
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "param_discovery",
                "error": str(e),
            }],
            "current_phase": "param_discovery_error",
        }
