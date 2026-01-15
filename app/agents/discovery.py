"""
RedStrike.AI - Discovery Agent
Handles content and endpoint discovery.
"""
from typing import Optional

from app.agents.base import BaseAgent
from app.tools.discovery_tools import DISCOVERY_TOOLS


class DiscoveryAgent(BaseAgent):
    """
    Content Discovery Agent - Finds hidden content and endpoints.
    
    Capabilities:
    - Directory brute-forcing
    - Endpoint crawling
    - Parameter discovery
    - Historical URL lookup
    """
    
    def __init__(self, model_name: Optional[str] = None):
        super().__init__(
            tools=DISCOVERY_TOOLS,
            model_name=model_name,
            skill_categories=["reconnaissance"],
            use_code_agent=True,
        )
    
    def get_system_prompt(self) -> str:
        return """You are the Content Discovery Agent for RedStrike.AI.

Your role is to discover hidden content, endpoints, and attack surface.

Your capabilities:
1. **Directory Brute-forcing**: Use ffuf/gobuster to find hidden directories and files
2. **Endpoint Crawling**: Use katana to crawl and discover all endpoints
3. **Parameter Discovery**: Use arjun to find hidden GET/POST parameters
4. **Wayback URLs**: Fetch historical URLs that may still be accessible

Methodology:
1. Start with endpoint crawling to map visible attack surface
2. Use directory brute-forcing for hidden content
3. Check wayback machine for historical endpoints
4. For promising endpoints, discover hidden parameters

Prioritize finding:
- Admin panels and login pages
- API endpoints
- File upload functionality
- Backup files (.bak, .old, .zip)
- Configuration files
- Debug/development endpoints

Return structured results with:
- Discovered endpoints categorized by type
- Interesting parameters found
- Potential attack vectors identified

Be efficient with wordlist selection. Start with smaller, targeted lists."""
