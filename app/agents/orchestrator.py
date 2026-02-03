"""
RedStrike.AI - Orchestrator Agent
Main agent that coordinates all other agents using LangGraph.
"""
from typing import Dict, Any, List, Optional
import json
import re
import logging

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.prebuilt import create_react_agent

from app.models.llm_router import get_model_for_agent
from app.tools import LANGCHAIN_TOOLS
from app.services.skill_loader import skill_loader

logger = logging.getLogger(__name__)


ORCHESTRATOR_SYSTEM_PROMPT = """You are the Orchestrator Agent for RedStrike.AI, an enterprise-grade web penetration testing platform.

Your responsibilities:
1. **Parse User Prompts**: Extract target URL, scope (allowed domains, excluded paths), authentication details, and rate limits from the user's natural language prompt.

2. **Create Attack Plans**: Based on the target, create a structured testing plan that includes:
   - Reconnaissance phase (subdomain enum, port scanning, tech detection)
   - Content discovery phase (directory brute-forcing, endpoint crawling)
   - Vulnerability scanning phase (nuclei, nikto)
   - Fuzzing phase (XSS, SQLi, SSRF, etc.)
   - Verification phase (validate findings, generate PoC)

3. **Execute Tools**: You have access to various security tools. Use them strategically based on the target and scope.

4. **Stay In Scope**: NEVER test anything outside the specified scope. Respect rate limits and excluded paths.

5. **Report Findings**: For each vulnerability found, provide:
   - Clear title and severity
   - Affected URL and parameter
   - Step-by-step reproduction instructions
   - Python PoC code if possible

When parsing a prompt, extract and return a JSON object with:
{
    "target_url": "https://example.com",
    "scope": {
        "allowed_domains": ["example.com", "*.example.com"],
        "excluded_paths": ["/logout", "/admin"],
        "allowed_methods": ["GET", "POST"]
    },
    "auth": {
        "type": "cookie|bearer|basic|none",
        "value": "token or credentials"
    },
    "rate_limit": {
        "requests_per_second": 10,
        "delay_ms": 100
    },
    "test_types": ["xss", "sqli", "ssrf", "full"]
}

Be thorough but efficient. Prioritize high-impact vulnerabilities."""


class OrchestratorAgent:
    """
    Orchestrator Agent - Plans and coordinates security testing.
    
    This agent:
    1. Parses user prompts to extract scope, auth, rate limits
    2. Creates an attack plan based on target type
    3. Delegates to specialized agents
    4. Aggregates and manages results
    """
    
    def __init__(self, model_name: Optional[str] = None):
        self.model = get_model_for_agent("orchestrator")
        
        # Load relevant skills
        skill_categories = ["reconnaissance", "web/a03-injection"]
        self.skill_context = skill_loader.get_skill_context(skill_categories)
        
        # Build enhanced system prompt with skills
        self.system_prompt = self._build_system_prompt()
        
        # Create LangGraph agent
        self._agent = create_react_agent(
            self.model,
            LANGCHAIN_TOOLS,
            prompt=self.system_prompt
        )
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt including skills."""
        if self.skill_context:
            return f"""{ORCHESTRATOR_SYSTEM_PROMPT}

## Knowledge Base

The following knowledge base contains techniques and methodologies you should use:

{self.skill_context}
"""
        return ORCHESTRATOR_SYSTEM_PROMPT
    
    def parse_prompt(self, prompt: str) -> Dict[str, Any]:
        """Parse user prompt to extract configuration."""
        parse_task = f"""Parse the following penetration testing request and extract configuration as JSON:

Prompt: {prompt}

Extract:
1. target_url - The main target URL
2. scope - Allowed domains/paths and exclusions
3. auth - Authentication details if provided (type and value)
4. rate_limit - Rate limiting requirements
5. test_types - What types of tests to run

Return ONLY the JSON object, no explanation."""

        messages = [
            SystemMessage(content=ORCHESTRATOR_SYSTEM_PROMPT),
            HumanMessage(content=parse_task)
        ]
        
        try:
            # Use model directly for simple parsing (no tools needed)
            result = self.model.invoke(messages)
            response_text = result.content if hasattr(result, 'content') else str(result)
            
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.error(f"Error parsing prompt: {e}")
        
        # Return default config if parsing fails
        logger.warning("Failed to parse prompt, using defaults")
        return {
            "target_url": self._extract_url(prompt),
            "scope": {"allowed_domains": [], "excluded_paths": []},
            "auth": {"type": "none", "value": None},
            "rate_limit": {"requests_per_second": 10},
            "test_types": ["full"]
        }
    
    def _extract_url(self, text: str) -> Optional[str]:
        """Extract URL from text."""
        url_pattern = r'https?://[^\s<>"\'{}\|\\^`\[\]]+'
        match = re.search(url_pattern, text)
        return match.group(0) if match else None
    
    async def create_attack_plan(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create an attack plan based on configuration."""
        target = config.get("target_url", "")
        test_types = config.get("test_types", ["full"])
        
        plan = []
        
        # Phase 1: Reconnaissance
        plan.append({
            "phase": "reconnaissance",
            "agent": "network_recon",
            "tasks": [
                {"tool": "technology_detector", "target": target},
                {"tool": "waf_detector", "target": target},
                {"tool": "port_scanner", "target": target, "ports": "top-100"},
            ]
        })
        
        # Phase 2: Content Discovery
        plan.append({
            "phase": "content_discovery",
            "agent": "endpoint_discovery",
            "tasks": [
                {"tool": "directory_bruteforcer", "target": f"{target}/FUZZ"},
                {"tool": "endpoint_crawler", "target": target},
                {"tool": "parameter_finder", "target": target},
            ]
        })
        
        # Phase 3: Vulnerability Scanning
        plan.append({
            "phase": "vulnerability_scanning",
            "agent": "vuln_scanner",
            "tasks": [
                {"tool": "nuclei_scanner", "target": target},
                {"tool": "header_analyzer", "target": target},
            ]
        })
        
        # Phase 4: Fuzzing (based on test_types)
        if "full" in test_types or any(t in test_types for t in ["xss", "sqli", "ssrf"]):
            plan.append({
                "phase": "fuzzing",
                "agent": "injection_tester",
                "tasks": self._get_fuzzing_tasks(target, test_types)
            })
        
        # Phase 5: Verification
        plan.append({
            "phase": "verification",
            "agent": "verifier",
            "tasks": [
                {"action": "verify_findings"},
                {"action": "generate_poc"},
            ]
        })
        
        return plan
    
    def _get_fuzzing_tasks(self, target: str, test_types: List[str]) -> List[Dict]:
        """Get fuzzing tasks based on test types."""
        tasks = []
        
        if "full" in test_types or "xss" in test_types:
            tasks.append({"tool": "xss_tester", "description": "Test for XSS"})
        
        if "full" in test_types or "sqli" in test_types:
            tasks.append({"tool": "sqli_tester", "description": "Test for SQL Injection"})
        
        if "full" in test_types or "ssrf" in test_types:
            tasks.append({"tool": "ssrf_tester", "description": "Test for SSRF"})
        
        if "full" in test_types or "lfi" in test_types:
            tasks.append({"tool": "lfi_tester", "description": "Test for LFI"})
        
        return tasks
    
    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run the orchestrator agent with a task.
        
        Args:
            task: The task description
            context: Optional context (scope, auth, etc.)
            
        Returns:
            Agent output
        """
        # Build task with context
        full_task = task
        if context:
            context_str = "\n".join(f"- {k}: {v}" for k, v in context.items())
            full_task = f"""Context:
{context_str}

Task:
{task}"""
        
        try:
            messages = [HumanMessage(content=full_task)]
            result = self._agent.invoke({"messages": messages})
            
            # Extract final message content
            final_message = result.get("messages", [])[-1] if result.get("messages") else None
            output = final_message.content if final_message else str(result)
            
            return {
                "success": True,
                "output": output,
                "agent": "OrchestratorAgent",
            }
        except Exception as e:
            logger.error(f"Orchestrator error: {e}")
            return {
                "success": False,
                "error": str(e),
                "agent": "OrchestratorAgent",
            }
