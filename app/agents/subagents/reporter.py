"""
RedStrike.AI - Reporter Subagent
Generates comprehensive reports from verified findings.
Supports user-provided templates.
"""
from typing import Dict, Any, List, Optional
from langchain_core.messages import HumanMessage, SystemMessage
from datetime import datetime

from app.agents.state import ScanState, Finding
from app.models.llm_router import get_model_for_agent

SYSTEM_PROMPT = """You are the Reporter Subagent for RedStrike.AI.

Your role is to generate comprehensive, professional vulnerability reports.

## Report Structure

### 1. Executive Summary
- Total vulnerabilities by severity
- Key risks identified
- Immediate actions required

### 2. Scope & Methodology
- Target(s) tested
- Testing type (blackbox/greybox/whitebox)
- Testing methodology
- Tools used
- Testing period

### 3. Findings Summary Table
| ID | Title | Severity | OWASP | Status |
|----|-------|----------|-------|--------|

### 4. Detailed Findings
For each verified vulnerability:

#### [SEVERITY] Finding Title

**Overview**
| Field | Value |
|-------|-------|
| Severity | Critical/High/Medium/Low/Info |
| OWASP Category | A01:2021 |
| Affected URL | https://... |
| Affected Parameter | username |
| CVSS Score | 9.8 |

**Description**
Clear explanation of the vulnerability.

**Steps to Reproduce**
1. Step one
2. Step two
3. Step three

**HTTP Request**
```http
POST /api/login HTTP/1.1
...
```

**HTTP Response**
```http
HTTP/1.1 200 OK
...
```

**Proof of Concept**
```python
# Python PoC code
```

**Impact**
Business and technical impact.

**Remediation**
How to fix the vulnerability.

**References**
- OWASP link
- CWE link
- Related CVEs

### 5. Remediation Summary
Prioritized list of fixes.

## Format Options
User can request: Markdown, HTML, PDF, CSV, JSON

If user provided a template, follow that format exactly."""


def create_reporter_subagent(state: ScanState) -> Dict[str, Any]:
    """
    Reporter subagent node - generates final report.
    
    Args:
        state: Current scan state
        
    Returns:
        Updated state with final report
    """
    model = get_model_for_agent("reporter")
    target = state["target"]["url"]
    
    # Get verified findings
    verified_findings = state.get("verified_findings", [])
    false_positives = state.get("false_positives", [])
    
    # Get scan metadata
    scan_config = state.get("scan_config", {})
    phase_history = state.get("phase_history", [])
    errors = state.get("errors", [])
    
    # Build report context
    report_context = _build_report_context(
        target=target,
        scan_config=scan_config,
        verified_findings=verified_findings,
        false_positives=false_positives,
        phase_history=phase_history,
        errors=errors,
    )
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"""Generate a comprehensive security report.

{report_context}

Generate a complete Markdown report following the standard structure.
Include all findings with their step-by-step PoC details.""")
    ]
    
    try:
        result = model.invoke(messages)
        
        final_report = result.content if hasattr(result, 'content') else str(result)
        
        return {
            "final_report": final_report,
            "current_phase": "reporting_complete",
            "phase_history": state.get("phase_history", []) + ["reporting"],
        }
        
    except Exception as e:
        # Generate minimal report on error
        return {
            "final_report": _generate_fallback_report(target, verified_findings),
            "errors": state.get("errors", []) + [{
                "phase": "reporting",
                "error": str(e),
            }],
            "current_phase": "reporting_error",
        }


def _build_report_context(
    target: str,
    scan_config: dict,
    verified_findings: List[Finding],
    false_positives: List[Finding],
    phase_history: List[str],
    errors: List[dict],
) -> str:
    """Build context string for report generation."""
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in verified_findings:
        sev = f.get("severity", "informational").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    context = f"""
## Report Information
- Target: {target}
- Date: {datetime.now().strftime("%Y-%m-%d %H:%M")}
- Scan Mode: {scan_config.get("scan_mode", "blackbox")}

## Testing Phases Completed
{", ".join(phase_history)}

## Findings Summary
- Critical: {severity_counts["critical"]}
- High: {severity_counts["high"]}
- Medium: {severity_counts["medium"]}
- Low: {severity_counts["low"]}
- Informational: {severity_counts["informational"]}
- False Positives: {len(false_positives)}

## Verified Findings
{_format_findings_for_report(verified_findings)}

## Errors During Scan
{_format_errors(errors) if errors else "No errors occurred."}
"""
    return context


def _format_findings_for_report(findings: List[Finding]) -> str:
    """Format verified findings for report."""
    if not findings:
        return "No vulnerabilities found."
    
    formatted = []
    for f in findings:
        formatted.append(f"""
### [{f.get('severity', 'Unknown').upper()}] {f.get('title', 'Unknown')}

| Field | Value |
|-------|-------|
| ID | {f.get('id', 'N/A')} |
| Type | {f.get('vulnerability_type', 'Unknown')} |
| URL | {f.get('affected_url', 'Unknown')} |
| Parameter | {f.get('affected_parameter', 'N/A')} |
| OWASP | {f.get('owasp_category', 'N/A')} |
| CVSS | {f.get('cvss_score', 'N/A')} |

**Description**: {f.get('description', 'No description')}

**Evidence**: {f.get('evidence', 'No evidence')}

**Steps to Reproduce**:
{chr(10).join(f.get('poc_steps', ['No steps provided']))}

**Request**:
```http
{f.get('poc_request', 'No request available')}
```

**Response**:
```http
{f.get('poc_response', 'No response available')}
```

**PoC Code**:
```python
{f.get('poc_code', '# No PoC code available')}
```
""")
    return "\n".join(formatted)


def _format_errors(errors: List[dict]) -> str:
    """Format errors for report."""
    return "\n".join([f"- {e.get('phase', 'Unknown')}: {e.get('error', 'Unknown error')}" for e in errors])


def _generate_fallback_report(target: str, findings: List[Finding]) -> str:
    """Generate minimal report if LLM fails."""
    return f"""# Security Scan Report

**Target**: {target}
**Date**: {datetime.now().strftime("%Y-%m-%d %H:%M")}

## Summary
Total findings: {len(findings)}

## Findings
{_format_findings_for_report(findings)}

---
*Report generated by RedStrike.AI*
"""
