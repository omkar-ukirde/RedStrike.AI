"""
RedStrike.AI - Base Agent Class
"""
from typing import List, Optional, Dict, Any
from smolagents import CodeAgent, ToolCallingAgent, LiteLLMModel
import logging
import os

from app.core.config import settings
from app.services.skill_loader import skill_loader

logger = logging.getLogger(__name__)


def get_litellm_model(model_name: Optional[str] = None) -> LiteLLMModel:
    """Create a LiteLLM model instance for smolagents."""
    model = model_name or settings.litellm_model
    
    # Set up Ollama API base for Docker
    if model.startswith("ollama/"):
        ollama_base = settings.ollama_api_base
        if "localhost" in ollama_base:
            ollama_base = ollama_base.replace("localhost", "host.docker.internal")
        os.environ["OLLAMA_API_BASE"] = ollama_base
    
    return LiteLLMModel(model_id=model)


class BaseAgent:
    """Base class for all RedStrike agents."""
    
    def __init__(
        self,
        tools: List = None,
        model_name: Optional[str] = None,
        skill_categories: Optional[List[str]] = None,
        use_code_agent: bool = True,
    ):
        self.tools = tools or []
        self.model = get_litellm_model(model_name)
        self.skill_categories = skill_categories
        self.use_code_agent = use_code_agent
        
        # Load skill context
        self.skill_context = ""
        if skill_categories:
            self.skill_context = skill_loader.get_skill_context(skill_categories)
        
        # Create smolagents agent
        self._agent = self._create_agent()
    
    def _create_agent(self):
        """Create the smolagents agent instance."""
        instructions = self._build_system_prompt()
        
        if self.use_code_agent:
            return CodeAgent(
                tools=self.tools,
                model=self.model,
                instructions=instructions,
                max_steps=20,
            )
        else:
            return ToolCallingAgent(
                tools=self.tools,
                model=self.model,
                instructions=instructions,
                max_steps=20,
            )
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt including skills."""
        base_prompt = self.get_system_prompt()
        
        if self.skill_context:
            return f"""{base_prompt}

## Knowledge Base

The following knowledge base contains techniques and methodologies you should use:

{self.skill_context}
"""
        return base_prompt
    
    def get_system_prompt(self) -> str:
        """Override in subclasses to provide agent-specific system prompt."""
        return "You are a security testing agent. Follow the user's instructions carefully."
    
    async def run(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run the agent with a task.
        
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
            result = self._agent.run(full_task)
            return {
                "success": True,
                "output": result,
                "agent": self.__class__.__name__,
            }
        except Exception as e:
            logger.error(f"Agent error: {e}")
            return {
                "success": False,
                "error": str(e),
                "agent": self.__class__.__name__,
            }
