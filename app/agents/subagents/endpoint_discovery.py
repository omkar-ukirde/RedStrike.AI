"""
RedStrike.AI - Endpoint Discovery Subagent
Handles endpoint discovery: crawling, directory bruteforce.
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.tools import DISCOVERY_LANGCHAIN_TOOLS  # Docker-enabled tools
from app.agents.skill_subagent import (
    create_skill_aware_subagent,
    get_skill_categories_for_agent,
)

SYSTEM_PROMPT = """You are the Endpoint Discovery Subagent for RedStrike.AI.

Your role is to discover all endpoints and attack surface.

Capabilities:
1. **Web Crawling**: Crawl the application to find all links
2. **Directory Bruteforce**: Find hidden directories and files
3. **Wayback URLs**: Fetch historical URLs
4. **JavaScript Analysis**: Extract endpoints from JS files

Priority Targets:
- Admin panels (/admin, /administrator, /manage)
- API endpoints (/api, /v1, /graphql)
- Login pages (/login, /signin, /auth)
- File upload (/upload, /import)
- Backup files (.bak, .old, .zip, .sql)
- Configuration files (config.php, .env, web.config)
- Debug endpoints (/debug, /test, /phpinfo)

Methodology:
1. Crawl visible pages first
2. Run directory bruteforce with targeted wordlist
3. Check wayback machine for historical endpoints
4. Analyze JS files for hidden API endpoints

Output Format:
{
    "endpoints": [
        {"url": "/api/users", "method": "GET", "type": "api"},
        {"url": "/admin", "method": "GET", "type": "admin_panel"}
    ],
    "interesting_files": [".git/config", "backup.sql"],
    "js_endpoints": ["/api/internal/debug"],
    "total_discovered": 150
}"""


def create_endpoint_discovery_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Endpoint discovery subagent node with skill-aware implementation.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with discovered endpoints
    """
    model = get_model_for_agent("endpoint_discovery")
    target = state["target"]["url"]
    
    # Get skill categories for this agent type
    skill_categories = get_skill_categories_for_agent("endpoint_discovery")
    
    # Create skill-aware agent with context management
    agent = create_skill_aware_subagent(
        model=model,
        tools=DISCOVERY_LANGCHAIN_TOOLS,
        skill_categories=skill_categories,
        base_prompt=SYSTEM_PROMPT,
        max_context_messages=20,
        include_skill_references=False,
    )
    
    task_message = f"""Discover endpoints on: {target}

Previous recon results: {state.get("recon_results", {})}

Find all endpoints and attack surface."""

    messages = [HumanMessage(content=task_message)]
    
    try:
        result = agent.invoke({"messages": messages})
        
        # Update discovery results
        discovery_results = state.get("discovery_results") or {}
        discovery_results["endpoints"] = {
            "raw_output": result.get("messages", [])[-1].content if result.get("messages") else "",
            "status": "completed",
        }
        
        return {
            "discovery_results": discovery_results,
            "current_phase": "endpoint_discovery_complete",
            "phase_history": state.get("phase_history", []) + ["endpoint_discovery"],
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "endpoint_discovery",
                "error": str(e),
            }],
            "current_phase": "endpoint_discovery_error",
        }
