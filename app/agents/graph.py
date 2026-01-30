"""
RedStrike.AI - Main LangGraph Agent
Deep Agent with subagents for security testing.
"""
import logging
from typing import Optional, Dict, Any, List
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.state import ScanState, create_initial_state
from app.models.llm_router import get_model_for_agent
from app.tools import ALL_TOOLS, RECON_TOOLS, DISCOVERY_TOOLS, SCANNER_TOOLS, FUZZER_TOOLS
from app.agents.subagents import (
    create_network_recon_subagent,
    create_web_recon_subagent,
    create_code_analyzer_subagent,
    create_endpoint_discovery_subagent,
    create_param_discovery_subagent,
    create_injection_tester_subagent,
    create_auth_tester_subagent,
    create_config_tester_subagent,
    create_logic_tester_subagent,
    create_vuln_scanner_subagent,
    create_verifier_subagent,
    create_reporter_subagent,
)

logger = logging.getLogger(__name__)


# Orchestrator system prompt
ORCHESTRATOR_PROMPT = """You are the Orchestrator Agent for RedStrike.AI, an enterprise-grade web penetration testing platform.

Your responsibilities:
1. **Coordinate Testing Phases**: Based on the scan configuration, delegate to appropriate subagents.
2. **Maintain Scope**: NEVER test anything outside the specified scope.
3. **Track Progress**: Monitor each phase and move to the next when complete.
4. **Handle Errors**: If a subagent fails, log the error and continue with other phases.

Available Subagents:
- network_recon: Port scanning, service detection
- web_recon: Technology detection, WAF, headers
- code_analyzer: SAST, code review (whitebox only)
- endpoint_discovery: Crawling, directory bruteforce
- param_discovery: Hidden parameters, API endpoints
- injection_tester: XSS, SQLi, SSRF, XXE, RCE, SSTI
- auth_tester: IDOR, auth bypass, session, JWT
- config_tester: Headers, SSL, misconfigs, secrets
- logic_tester: Business logic, race conditions
- vuln_scanner: CVE scanning, nuclei templates
- verifier: Two-step vulnerability verification
- reporter: Report generation

Testing Flow:
1. Reconnaissance (network_recon, web_recon)
2. Discovery (endpoint_discovery, param_discovery)
3. Vulnerability Testing (injection, auth, config, logic, scanner)
4. Verification (verifier - MANDATORY for all findings)
5. Reporting (reporter)

IMPORTANT: Always delegate to verifier before adding findings to verified_findings.
Only verified findings should be included in the final report."""


def create_orchestrator_node(state: ScanState) -> Dict[str, Any]:
    """Main orchestrator that coordinates all subagents."""
    model = get_model_for_agent("orchestrator")
    
    messages = state.get("messages", [])
    current_phase = state.get("current_phase", "initialization")
    scan_config = state.get("scan_config", {})
    
    # Determine next phase based on current state
    if current_phase == "initialization":
        return {
            "current_phase": "reconnaissance",
            "phase_history": state.get("phase_history", []) + ["initialization"],
            "messages": messages + [
                SystemMessage(content=ORCHESTRATOR_PROMPT),
                HumanMessage(content=f"Starting scan of {state['target']['url']} with config: {scan_config}")
            ],
        }
    
    # Continue with current phase
    return {"current_phase": current_phase}


def should_run_recon(state: ScanState) -> bool:
    """Check if reconnaissance should run."""
    config = state.get("scan_config", {})
    return config.get("network_recon", True) or config.get("web_recon", True)


def should_run_discovery(state: ScanState) -> bool:
    """Check if discovery should run."""
    config = state.get("scan_config", {})
    return config.get("endpoint_discovery", True) or config.get("param_discovery", True)


def should_run_testing(state: ScanState) -> bool:
    """Check if vulnerability testing should run."""
    config = state.get("scan_config", {})
    return any([
        config.get("injection_testing", True),
        config.get("auth_testing", True),
        config.get("config_testing", True),
        config.get("logic_testing", True),
        config.get("vuln_scanning", True),
    ])


def should_run_code_analysis(state: ScanState) -> bool:
    """Check if code analysis should run (whitebox only)."""
    config = state.get("scan_config", {})
    target = state.get("target", {})
    return config.get("code_analysis", False) and target.get("code_url") is not None


def route_from_recon(state: ScanState) -> str:
    """Route after reconnaissance phase."""
    if should_run_code_analysis(state):
        return "code_analysis"
    elif should_run_discovery(state):
        return "discovery"
    elif should_run_testing(state):
        return "testing"
    else:
        return "reporting"


def route_from_discovery(state: ScanState) -> str:
    """Route after discovery phase."""
    if should_run_testing(state):
        return "testing"
    else:
        return "reporting"


def route_from_testing(state: ScanState) -> str:
    """Route after testing phase - always go to verification."""
    potential = state.get("potential_findings", [])
    if potential:
        return "verification"
    return "reporting"


def route_from_verification(state: ScanState) -> str:
    """Route after verification - go to reporting."""
    return "reporting"


def create_redstrike_graph() -> StateGraph:
    """
    Create the main LangGraph workflow.
    
    Returns:
        Compiled StateGraph for RedStrike scanning
    """
    # Build the graph
    workflow = StateGraph(ScanState)
    
    # Add nodes
    workflow.add_node("orchestrator", create_orchestrator_node)
    workflow.add_node("network_recon", create_network_recon_subagent)
    workflow.add_node("web_recon", create_web_recon_subagent)
    workflow.add_node("code_analyzer", create_code_analyzer_subagent)
    workflow.add_node("endpoint_discovery", create_endpoint_discovery_subagent)
    workflow.add_node("param_discovery", create_param_discovery_subagent)
    workflow.add_node("injection_tester", create_injection_tester_subagent)
    workflow.add_node("auth_tester", create_auth_tester_subagent)
    workflow.add_node("config_tester", create_config_tester_subagent)
    workflow.add_node("logic_tester", create_logic_tester_subagent)
    workflow.add_node("vuln_scanner", create_vuln_scanner_subagent)
    workflow.add_node("verifier", create_verifier_subagent)
    workflow.add_node("reporter", create_reporter_subagent)
    
    # Set entry point
    workflow.set_entry_point("orchestrator")
    
    # Add edges from orchestrator
    workflow.add_conditional_edges(
        "orchestrator",
        lambda state: "recon" if should_run_recon(state) else "discovery" if should_run_discovery(state) else "testing",
        {
            "recon": "network_recon",
            "discovery": "endpoint_discovery",
            "testing": "injection_tester",
        }
    )
    
    # Reconnaissance flow
    workflow.add_edge("network_recon", "web_recon")
    workflow.add_conditional_edges(
        "web_recon",
        route_from_recon,
        {
            "code_analysis": "code_analyzer",
            "discovery": "endpoint_discovery",
            "testing": "injection_tester",
            "reporting": "reporter",
        }
    )
    
    # Code analysis (whitebox)
    workflow.add_edge("code_analyzer", "endpoint_discovery")
    
    # Discovery flow
    workflow.add_edge("endpoint_discovery", "param_discovery")
    workflow.add_conditional_edges(
        "param_discovery",
        route_from_discovery,
        {
            "testing": "injection_tester",
            "reporting": "reporter",
        }
    )
    
    # Testing flow (parallel-ish, sequential for now)
    workflow.add_edge("injection_tester", "auth_tester")
    workflow.add_edge("auth_tester", "config_tester")
    workflow.add_edge("config_tester", "logic_tester")
    workflow.add_edge("logic_tester", "vuln_scanner")
    workflow.add_conditional_edges(
        "vuln_scanner",
        route_from_testing,
        {
            "verification": "verifier",
            "reporting": "reporter",
        }
    )
    
    # Verification to reporting
    workflow.add_edge("verifier", "reporter")
    
    # End at reporter
    workflow.add_edge("reporter", END)
    
    return workflow.compile()


# Global graph instance
_graph_instance = None


def get_redstrike_graph() -> StateGraph:
    """Get the global graph instance."""
    global _graph_instance
    if _graph_instance is None:
        _graph_instance = create_redstrike_graph()
    return _graph_instance


async def run_scan(
    target_url: str,
    scan_config: Optional[Dict[str, Any]] = None,
    credentials: Optional[Dict[str, str]] = None,
    code_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run a security scan on the target.
    
    Args:
        target_url: URL to scan
        scan_config: Optional scan configuration
        credentials: Optional credentials for greybox/whitebox
        code_url: Optional code repository URL for whitebox
        
    Returns:
        Scan results including findings and report
    """
    graph = get_redstrike_graph()
    initial_state = create_initial_state(
        target_url=target_url,
        scan_config=scan_config,
        credentials=credentials,
        code_url=code_url,
    )
    
    logger.info(f"Starting scan of {target_url}")
    
    # Run the graph
    final_state = await graph.ainvoke(initial_state)
    
    return {
        "target": target_url,
        "verified_findings": final_state.get("verified_findings", []),
        "false_positives": final_state.get("false_positives", []),
        "report": final_state.get("final_report"),
        "errors": final_state.get("errors", []),
    }
