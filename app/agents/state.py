"""
RedStrike.AI - LangGraph State Schema
Defines the state passed between agents in the graph.
"""
from typing import TypedDict, Annotated, List, Optional, Dict, Any
from langgraph.graph.message import add_messages
from enum import Enum


class ScanMode(str, Enum):
    """Testing mode selection."""
    BLACKBOX = "blackbox"
    GREYBOX = "greybox"
    WHITEBOX = "whitebox"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VerificationStatus(str, Enum):
    """Two-step verification status."""
    PENDING = "pending"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MANUAL = "needs_manual"


class Finding(TypedDict, total=False):
    """Individual vulnerability finding."""
    id: str
    title: str
    severity: str
    vulnerability_type: str
    affected_url: str
    affected_parameter: Optional[str]
    description: str
    evidence: str
    
    # Two-step verification
    verification_status: str
    verification_attempts: int
    
    # Step-by-step PoC
    poc_steps: List[str]
    poc_request: str
    poc_response: str
    poc_code: str
    
    # Metadata
    detected_by: str
    verified_by: Optional[str]
    owasp_category: Optional[str]
    cvss_score: Optional[float]


class TargetConfig(TypedDict, total=False):
    """Target configuration."""
    url: str
    scope: Dict[str, Any]
    credentials: Optional[Dict[str, str]]
    code_url: Optional[str]  # For whitebox testing
    rate_limit: Optional[Dict[str, int]]


class ScanConfig(TypedDict, total=False):
    """User scan configuration."""
    scan_mode: str
    
    # Testing mode toggles (user selects any combination)
    network_recon: bool
    web_recon: bool
    code_analysis: bool
    endpoint_discovery: bool
    param_discovery: bool
    injection_testing: bool
    auth_testing: bool
    config_testing: bool
    logic_testing: bool
    vuln_scanning: bool


class ReconResults(TypedDict, total=False):
    """Reconnaissance phase results."""
    subdomains: List[str]
    ports: List[Dict[str, Any]]
    technologies: List[str]
    waf_detected: Optional[str]
    ssl_info: Optional[Dict[str, Any]]
    headers: Dict[str, str]


class DiscoveryResults(TypedDict, total=False):
    """Discovery phase results."""
    endpoints: List[str]
    parameters: List[Dict[str, Any]]
    api_endpoints: List[str]
    forms: List[Dict[str, Any]]
    js_files: List[str]


class ScanState(TypedDict):
    """
    Main state for the LangGraph agent.
    Passed between all agents in the graph.
    """
    # Message history for agent communication
    messages: Annotated[list, add_messages]
    
    # Target configuration
    target: TargetConfig
    scan_config: ScanConfig
    
    # Current phase tracking
    current_phase: str
    phase_history: List[str]
    
    # Phase results
    recon_results: Optional[ReconResults]
    discovery_results: Optional[DiscoveryResults]
    
    # Findings (pre and post verification)
    potential_findings: List[Finding]
    verified_findings: List[Finding]
    false_positives: List[Finding]
    
    # Final output
    final_report: Optional[str]
    
    # Error tracking
    errors: List[Dict[str, Any]]


def create_initial_state(
    target_url: str,
    scan_config: Optional[ScanConfig] = None,
    credentials: Optional[Dict[str, str]] = None,
    code_url: Optional[str] = None,
) -> ScanState:
    """Create initial state for a new scan."""
    
    # Default scan config - all enabled
    default_config: ScanConfig = {
        "scan_mode": ScanMode.BLACKBOX.value,
        "network_recon": True,
        "web_recon": True,
        "code_analysis": code_url is not None,
        "endpoint_discovery": True,
        "param_discovery": True,
        "injection_testing": True,
        "auth_testing": True,
        "config_testing": True,
        "logic_testing": True,
        "vuln_scanning": True,
    }
    
    # Override with user config
    if scan_config:
        default_config.update(scan_config)
    
    # Determine scan mode
    if code_url:
        default_config["scan_mode"] = ScanMode.WHITEBOX.value
    elif credentials:
        default_config["scan_mode"] = ScanMode.GREYBOX.value
    
    return ScanState(
        messages=[],
        target={
            "url": target_url,
            "scope": {"allowed_domains": [target_url]},
            "credentials": credentials,
            "code_url": code_url,
            "rate_limit": {"requests_per_second": 10},
        },
        scan_config=default_config,
        current_phase="initialization",
        phase_history=[],
        recon_results=None,
        discovery_results=None,
        potential_findings=[],
        verified_findings=[],
        false_positives=[],
        final_report=None,
        errors=[],
    )
