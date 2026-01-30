"""
RedStrike.AI - Web Recon Subagent
Handles web reconnaissance: technology detection, WAF, headers.
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import RECON_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Web Reconnaissance Subagent for RedStrike.AI.

Your role is to gather web-specific information about targets.

Capabilities:
1. **Technology Detection**: Identify web frameworks, CMS, languages
2. **WAF Detection**: Detect Web Application Firewalls
3. **Header Analysis**: Analyze HTTP security headers
4. **SSL/TLS Analysis**: Check certificate and cipher configuration
5. **Fingerprinting**: Identify server software and versions

Methodology:
1. Check HTTP headers for technology hints
2. Detect WAF presence (important for later testing)
3. Identify technologies and frameworks
4. Note any security headers present/missing

Output Format:
Return structured JSON with:
{
    "technologies": ["nginx", "PHP 8.1", "WordPress 6.0"],
    "waf": {"detected": true, "type": "Cloudflare"},
    "headers": {"X-Frame-Options": "present", "CSP": "missing"},
    "ssl": {"grade": "A", "issues": []},
    "cms": "WordPress",
    "framework": "PHP"
}

Focus on information useful for vulnerability discovery."""


def create_web_recon_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Web reconnaissance subagent node.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with web recon results
    """
    model = get_model_for_agent("web_recon")
    target = state["target"]["url"]
    
    # Load relevant skills
    skill_context = skill_loader.get_skill_context(["reconnaissance"])
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Perform web reconnaissance on: {target}

Previous network recon results: {state.get("recon_results", {}).get("network", "None")}

Skills/Knowledge:
{skill_context if skill_context else "No specific skills loaded."}

Execute web reconnaissance and return structured results.""")
    ]
    
    try:
        from langgraph.prebuilt import create_react_agent
        agent = create_react_agent(model, RECON_LANGCHAIN_TOOLS)  # Docker execution
        result = agent.invoke({"messages": messages})
        
        # Update recon results
        recon_results = state.get("recon_results") or {}
        recon_results["web"] = {
            "raw_output": result.get("messages", [])[-1].content if result.get("messages") else "",
            "status": "completed",
        }
        
        return {
            "recon_results": recon_results,
            "current_phase": "web_recon_complete",
            "phase_history": state.get("phase_history", []) + ["web_recon"],
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "web_recon",
                "error": str(e),
            }],
            "current_phase": "web_recon_error",
        }
