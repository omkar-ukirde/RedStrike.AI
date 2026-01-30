"""
RedStrike.AI - Subagents Package
Contains all subagent definitions for the LangGraph workflow.
"""

from app.agents.subagents.network_recon import create_network_recon_subagent
from app.agents.subagents.web_recon import create_web_recon_subagent
from app.agents.subagents.code_analyzer import create_code_analyzer_subagent
from app.agents.subagents.endpoint_discovery import create_endpoint_discovery_subagent
from app.agents.subagents.param_discovery import create_param_discovery_subagent
from app.agents.subagents.injection_tester import create_injection_tester_subagent
from app.agents.subagents.auth_tester import create_auth_tester_subagent
from app.agents.subagents.config_tester import create_config_tester_subagent
from app.agents.subagents.logic_tester import create_logic_tester_subagent
from app.agents.subagents.vuln_scanner import create_vuln_scanner_subagent
from app.agents.subagents.verifier import create_verifier_subagent
from app.agents.subagents.reporter import create_reporter_subagent

__all__ = [
    "create_network_recon_subagent",
    "create_web_recon_subagent",
    "create_code_analyzer_subagent",
    "create_endpoint_discovery_subagent",
    "create_param_discovery_subagent",
    "create_injection_tester_subagent",
    "create_auth_tester_subagent",
    "create_config_tester_subagent",
    "create_logic_tester_subagent",
    "create_vuln_scanner_subagent",
    "create_verifier_subagent",
    "create_reporter_subagent",
]
