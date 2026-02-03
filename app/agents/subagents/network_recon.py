"""
RedStrike.AI - Network Recon Subagent
Handles network reconnaissance: port scanning, service detection.
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import RECON_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.agents.skill_subagent import (
    create_skill_aware_subagent,
    get_skill_categories_for_agent,
)

SYSTEM_PROMPT = """You are the Network Reconnaissance Subagent for RedStrike.AI.

Your role is to gather network-level information about targets.

Capabilities:
1. **Port Scanning**: Use nmap to identify open ports and services
2. **Service Detection**: Identify running services and versions
3. **Network Mapping**: Map the network topology

Methodology:
1. Perform a quick top-ports scan first
2. Follow up with detailed scans on discovered ports
3. Identify service versions for vulnerability correlation

Output Format:
Return structured JSON with:
{
    "ports": [{"port": 80, "service": "http", "version": "nginx 1.21"}],
    "services": ["http", "ssh", "mysql"],
    "os_detection": "Linux",
    "notes": ["..."]
}

Always respect scope and rate limits. Only scan authorized targets."""


def create_network_recon_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Network reconnaissance subagent node with skill-aware implementation.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with recon results
    """
    model = get_model_for_agent("network_recon")
    target = state["target"]["url"]
    
    # Get skill categories for this agent type
    skill_categories = get_skill_categories_for_agent("network_recon")
    
    # Create skill-aware agent with context management
    agent = create_skill_aware_subagent(
        model=model,
        tools=RECON_LANGCHAIN_TOOLS,
        skill_categories=skill_categories,
        base_prompt=SYSTEM_PROMPT,
        max_context_messages=20,
        include_skill_references=False,  # Network recon is quick
    )
    
    task_message = f"""Perform network reconnaissance on: {target}

Scope: {state["target"].get("scope", {})}
Rate Limit: {state["target"].get("rate_limit", {})}

Execute the reconnaissance and return structured results."""

    messages = [HumanMessage(content=task_message)]
    
    try:
        result = agent.invoke({"messages": messages})
        
        # Update recon results
        recon_results = state.get("recon_results") or {}
        recon_results["network"] = {
            "raw_output": result.get("messages", [])[-1].content if result.get("messages") else "",
            "status": "completed",
        }
        
        return {
            "recon_results": recon_results,
            "current_phase": "network_recon_complete",
            "phase_history": state.get("phase_history", []) + ["network_recon"],
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "network_recon",
                "error": str(e),
            }],
            "current_phase": "network_recon_error",
        }
