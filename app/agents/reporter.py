"""
RedStrike.AI - Reporter Agent
Generates comprehensive reports.
"""
from typing import Optional, List, Dict, Any

from app.agents.base import BaseAgent


class ReporterAgent(BaseAgent):
    """
    Reporter Agent - Generates and formats vulnerability reports.
    
    Capabilities:
    - Consolidate findings from all agents
    - Generate formatted reports
    - Create executive summaries
    - Export to various formats
    """
    
    def __init__(self, model_name: Optional[str] = None):
        super().__init__(
            tools=[],  # No tools needed, uses code generation
            model_name=model_name,
            skill_categories=["reporting"],
            use_code_agent=True,
        )
    
    def get_system_prompt(self) -> str:
        return """You are the Reporter Agent for RedStrike.AI.

Your role is to generate comprehensive, professional vulnerability reports.

Report Structure:

1. **Executive Summary**
   - Total vulnerabilities by severity
   - Key risks identified
   - Recommended priority actions

2. **Scope & Methodology**
   - Targets tested
   - Testing methodology
   - Tools used
   - Limitations

3. **Findings** (for each vulnerability)
   - Title and Severity (Critical/High/Medium/Low/Info)
   - Affected URL/Component
   - Description
   - Impact
   - Reproduction Steps (numbered, clear)
   - PoC Code (if available)
   - Remediation Recommendations
   - References (CVE, OWASP, etc.)

4. **Remediation Summary**
   - Prioritized list of fixes
   - Quick wins vs long-term improvements

Formatting:
- Use Markdown for rich formatting
- Include severity badges
- Code blocks for payloads and PoC
- Tables for summary data

Be professional and clear. Reports should be suitable for both technical teams and management."""
    
    def generate_report(self, findings: List[Dict[str, Any]], project_info: Dict[str, Any]) -> str:
        """Generate a markdown report from findings."""
        report_task = f"""Generate a comprehensive vulnerability report for:

Project: {project_info.get('name', 'Unknown')}
Target: {project_info.get('target_url', 'Unknown')}
Date: {project_info.get('date', 'Unknown')}

Findings:
{self._format_findings(findings)}

Generate a complete Markdown report following the standard structure."""

        result = self._agent.run(report_task)
        return result
    
    def _format_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for the prompt."""
        if not findings:
            return "No vulnerabilities found."
        
        formatted = []
        for i, f in enumerate(findings, 1):
            formatted.append(f"""
Finding #{i}:
- Title: {f.get('title', 'Unknown')}
- Severity: {f.get('severity', 'Unknown')}
- URL: {f.get('affected_url', 'Unknown')}
- Type: {f.get('vulnerability_type', 'Unknown')}
- Description: {f.get('description', 'No description')}
- PoC: {f.get('poc_code', 'None')}
""")
        return "\n".join(formatted)
    
    def generate_csv_export(self, findings: List[Dict[str, Any]]) -> str:
        """Generate CSV export of findings."""
        headers = [
            "ID", "Title", "Severity", "Type", "URL", "Parameter",
            "Description", "PoC Code", "Reproduction Steps", "Verified"
        ]
        
        rows = [",".join(headers)]
        
        for f in findings:
            row = [
                str(f.get('id', '')),
                f'"{f.get("title", "")}"',
                f.get('severity', ''),
                f.get('vulnerability_type', ''),
                f'"{f.get("affected_url", "")}"',
                f.get('affected_parameter', ''),
                f'"{f.get("description", "").replace(chr(34), chr(39))}"',
                f'"{f.get("poc_code", "").replace(chr(34), chr(39)).replace(chr(10), " ")}"',
                f'"{f.get("reproduction_steps", "").replace(chr(34), chr(39)).replace(chr(10), " ")}"',
                str(f.get('verified', False)),
            ]
            rows.append(",".join(row))
        
        return "\n".join(rows)
