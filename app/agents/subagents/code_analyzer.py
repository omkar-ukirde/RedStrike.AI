"""
RedStrike.AI - Code Analyzer Subagent
Handles whitebox testing: SAST, code review.
"""
from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState
from app.models.llm_router import get_model_for_agent
from app.agents.skill_subagent import (
    get_skill_system_prompt,
    get_skill_categories_for_agent,
)
from app.services.skill_loader import skill_loader

SYSTEM_PROMPT = """You are the Code Analyzer Subagent for RedStrike.AI.

Your role is to perform static analysis and code review for whitebox testing.

Capabilities:
1. **SAST**: Static Application Security Testing
2. **Code Review**: Manual code security review
3. **Vulnerability Patterns**: Identify common vulnerability patterns
4. **Data Flow Analysis**: Track user input to dangerous sinks

What to Look For:
- SQL Injection: User input in SQL queries
- XSS: Unsanitized output
- Command Injection: User input in system commands
- Path Traversal: User input in file paths
- Insecure Deserialization: Untrusted data deserialization
- Hardcoded Secrets: API keys, passwords in code
- Authentication Issues: Weak auth implementations
- Authorization Issues: Missing access controls

Output Format:
Return structured findings with:
{
    "findings": [
        {
            "type": "SQL Injection",
            "file": "app/models/user.py",
            "line": 45,
            "code": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "severity": "critical",
            "description": "User input directly concatenated into SQL query",
            "fix": "Use parameterized queries"
        }
    ],
    "summary": "Found 3 critical, 5 high severity issues"
}

Be thorough - code analysis is the most reliable way to find vulnerabilities."""


def create_code_analyzer_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Code analyzer subagent node with skill-aware implementation (whitebox testing).
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with code analysis results
    """
    model = get_model_for_agent("code_analyzer")
    code_url = state["target"].get("code_url")
    
    if not code_url:
        return {
            "current_phase": "code_analysis_skipped",
            "phase_history": state.get("phase_history", []) + ["code_analysis_skipped"],
        }
    
    # Get skill categories for code analyzer
    skill_categories = get_skill_categories_for_agent("code_analyzer")
    
    # Build enhanced prompt with skills (code analyzer doesn't use tools)
    enhanced_prompt = get_skill_system_prompt(
        SYSTEM_PROMPT,
        skill_categories,
        include_references=True,  # Include detailed vulnerability patterns
    )
    
    messages = [
        SystemMessage(content=enhanced_prompt),
        HumanMessage(content=f"""Perform code analysis on repository: {code_url}

Target application: {state["target"]["url"]}

Analyze the code for security vulnerabilities and return structured findings.""")
    ]
    
    try:
        # Code analyzer doesn't use tools - pure LLM reasoning with skill knowledge
        result = model.invoke(messages)
        
        # Parse findings from code analysis
        return {
            "current_phase": "code_analysis_complete",
            "phase_history": state.get("phase_history", []) + ["code_analysis"],
            "messages": state.get("messages", []) + [result],
        }
        
    except Exception as e:
        return {
            "errors": state.get("errors", []) + [{
                "phase": "code_analysis",
                "error": str(e),
            }],
            "current_phase": "code_analysis_error",
        }
