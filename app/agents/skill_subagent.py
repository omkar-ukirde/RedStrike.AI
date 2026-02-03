"""
RedStrike.AI - Skill-Aware Subagent Factory
Creates LangGraph ReAct agents with proper skill integration.
Follows LangGraph deep agents specification with context management.
"""
import logging
from typing import List, Optional, Dict, Any, Callable
from langchain_core.tools import BaseTool
from langchain_core.messages import SystemMessage, HumanMessage, BaseMessage
from langgraph.prebuilt import create_react_agent
from langgraph.graph import StateGraph

from app.services.skill_loader import skill_loader

logger = logging.getLogger(__name__)


def create_context_manager(max_messages: int = 20) -> Callable:
    """
    Create a pre_model_hook for context window management.
    
    This prevents context overflow by keeping only the most recent messages
    while preserving system messages. Per LangGraph specification, this
    modifies llm_input_messages without affecting the stored state.
    
    Args:
        max_messages: Maximum number of messages to keep in context
        
    Returns:
        A callable pre_model_hook function
    """
    def manage_context(state: Dict[str, Any]) -> Dict[str, Any]:
        messages = state.get("messages", [])
        
        if len(messages) <= max_messages:
            return {"llm_input_messages": messages}
        
        # Separate system messages from others
        system_msgs = [m for m in messages if isinstance(m, SystemMessage)]
        other_msgs = [m for m in messages if not isinstance(m, SystemMessage)]
        
        # Keep system messages + most recent other messages
        remaining_slots = max_messages - len(system_msgs)
        trimmed_messages = system_msgs + other_msgs[-remaining_slots:] if remaining_slots > 0 else system_msgs
        
        logger.debug(f"Context trimmed: {len(messages)} -> {len(trimmed_messages)} messages")
        
        return {"llm_input_messages": trimmed_messages}
    
    return manage_context


def get_skill_system_prompt(
    base_prompt: str,
    skill_categories: List[str],
    include_references: bool = False,
) -> str:
    """
    Build system prompt with skill context using progressive disclosure.
    
    Args:
        base_prompt: Base system prompt for the agent
        skill_categories: List of skill category paths
        include_references: Whether to include detailed references
        
    Returns:
        Enhanced system prompt with skill knowledge
    """
    # Get skill summaries for quick reference
    summaries = skill_loader.get_skill_summaries(skill_categories)
    
    if not summaries:
        return base_prompt
    
    # Get skill content with progressive disclosure
    skill_context = skill_loader.get_progressive_context(
        skill_categories,
        include_references=include_references,
        max_references_per_skill=2
    )
    
    # Build enhanced prompt
    enhanced_prompt = f"""{base_prompt}

## Available Skills

You have access to the following security testing skills:

{chr(10).join(f"- **{s['name']}**: {s['description'][:100]}..." for s in summaries)}

## Skill Knowledge Base

The following knowledge contains techniques, payloads, and methodologies you should use:

{skill_context}

## Important

- Use the payloads and techniques from your skill knowledge
- Reference specific methodologies when testing
- If you need more detailed information on a specific technique, it may be available in reference files
"""
    
    return enhanced_prompt


def create_skill_aware_subagent(
    model,
    tools: List[BaseTool],
    skill_categories: List[str],
    base_prompt: str,
    max_context_messages: int = 20,
    include_skill_references: bool = False,
):
    """
    Create a LangGraph ReAct agent with skill integration and context management.
    
    This follows the LangGraph deep agents specification:
    - Uses create_react_agent for tool-calling agents
    - Applies pre_model_hook for context window management
    - Integrates skills using progressive disclosure
    
    Args:
        model: LangChain chat model
        tools: List of LangChain tools
        skill_categories: List of skill category paths (e.g., ["web/a03-injection"])
        base_prompt: Base system prompt for the agent
        max_context_messages: Maximum messages to keep in context
        include_skill_references: Whether to include detailed reference files
        
    Returns:
        Compiled LangGraph agent
    """
    # Build enhanced system prompt with skills
    system_prompt = get_skill_system_prompt(
        base_prompt,
        skill_categories,
        include_references=include_skill_references
    )
    
    # Create context manager hook
    context_hook = create_context_manager(max_context_messages)
    
    # Log skill loading
    logger.info(f"Creating skill-aware subagent with categories: {skill_categories}")
    for cat in skill_categories:
        refs = skill_loader.list_references(cat)
        if refs:
            logger.debug(f"  {cat}: {len(refs)} reference files available")
    
    # Create ReAct agent with context management
    # Note: pre_model_hook was added in newer LangGraph versions
    try:
        agent = create_react_agent(
            model,
            tools,
            prompt=system_prompt,
            pre_model_hook=context_hook,
        )
    except TypeError:
        # Fallback for older LangGraph versions without pre_model_hook
        logger.warning("pre_model_hook not supported, using basic agent")
        agent = create_react_agent(
            model,
            tools,
        )
    
    return agent


def create_hierarchical_subagent(
    model,
    tools: List[BaseTool],
    skill_categories: List[str],
    base_prompt: str,
    child_agents: Optional[Dict[str, Any]] = None,
    max_context_messages: int = 25,
):
    """
    Create a hierarchical subagent that can spawn child agents.
    
    This implements the deep agents pattern where a parent agent
    can delegate to specialized child agents for specific tasks.
    
    Args:
        model: LangChain chat model
        tools: List of LangChain tools for this agent
        skill_categories: Skill categories for this agent
        base_prompt: Base system prompt
        child_agents: Optional dict of child agent names to their configs
        max_context_messages: Maximum context size
        
    Returns:
        Compiled hierarchical agent
    """
    # Build base agent with skills
    system_prompt = get_skill_system_prompt(
        base_prompt,
        skill_categories,
        include_references=False  # Keep parent context lean
    )
    
    # Add child agent descriptions if available
    if child_agents:
        child_desc = "\n## Available Sub-Agents\n\n"
        for name, config in child_agents.items():
            child_desc += f"- **{name}**: {config.get('description', 'Specialized testing agent')}\n"
        system_prompt += child_desc
    
    context_hook = create_context_manager(max_context_messages)
    
    try:
        agent = create_react_agent(
            model,
            tools,
            prompt=system_prompt,
            pre_model_hook=context_hook,
        )
    except TypeError:
        agent = create_react_agent(model, tools)
    
    return agent


# Skill category mappings for each subagent type
SUBAGENT_SKILL_MAPPINGS = {
    "network_recon": [
        "network/reconnaissance",
        "reconnaissance",
    ],
    "web_recon": [
        "network/reconnaissance",
        "web/a05-security-misconfiguration",
        "configuration",
    ],
    "endpoint_discovery": [
        "reconnaissance",
    ],
    "param_discovery": [
        "reconnaissance",
    ],
    "injection_tester": [
        "web/a03-injection",
        "web/xss",
        "web/a10-ssrf",
        "injection",
    ],
    "auth_tester": [
        "web/a07-auth-failures",
        "web/a01-broken-access-control",
        "authentication",
    ],
    "config_tester": [
        "web/a05-security-misconfiguration",
        "configuration",
    ],
    "logic_tester": [
        "web/a04-insecure-design",
        "logic",
    ],
    "vuln_scanner": [
        "web/a06-vulnerable-components",
        "vulnerabilities",
    ],
    "verifier": [
        "exploitation",
    ],
    "code_analyzer": [
        "web/a03-injection",
        "web/a08-data-integrity-failures",
    ],
    "reporter": [],  # Reporter doesn't need skills
}


def get_skill_categories_for_agent(agent_type: str) -> List[str]:
    """
    Get the appropriate skill categories for a subagent type.
    
    Args:
        agent_type: Type of subagent (e.g., "injection_tester")
        
    Returns:
        List of skill category paths
    """
    return SUBAGENT_SKILL_MAPPINGS.get(agent_type, [])
