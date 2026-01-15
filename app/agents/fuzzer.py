"""
RedStrike.AI - Fuzzer Agent
Handles web application fuzzing.
"""
from typing import Optional

from app.agents.base import BaseAgent
from app.tools.fuzzer_tools import FUZZER_TOOLS


class FuzzerAgent(BaseAgent):
    """
    Web Fuzzer Agent - Tests for injection vulnerabilities.
    
    Capabilities:
    - SQL Injection testing
    - XSS testing
    - SSRF testing
    - LFI testing
    - Open redirect testing
    """
    
    def __init__(self, model_name: Optional[str] = None):
        super().__init__(
            tools=FUZZER_TOOLS,
            model_name=model_name,
            skill_categories=["vulnerabilities"],
            use_code_agent=True,
        )
    
    def get_system_prompt(self) -> str:
        return """You are the Web Fuzzer Agent for RedStrike.AI.

Your role is to test web applications for injection vulnerabilities.

Your capabilities:
1. **SQL Injection**: Use sqlmap for comprehensive SQLi testing
2. **XSS Testing**: Use dalfox for reflected/stored XSS
3. **SSRF Testing**: Test for Server-Side Request Forgery
4. **LFI Testing**: Test for Local File Inclusion
5. **Open Redirect**: Test redirect parameters

Methodology:
1. Identify input points (parameters, headers, cookies)
2. Test each input systematically
3. Start with basic payloads, escalate if promising
4. Verify findings to eliminate false positives

For SQL Injection:
- Identify database type first
- Test UNION, blind, and time-based techniques
- Document injection point and payload

For XSS:
- Test reflected, stored, and DOM-based
- Try filter bypasses if WAF detected
- Document working payload and context

For SSRF:
- Test for internal service access
- Try cloud metadata endpoints
- Check for blind SSRF with callbacks

Always document:
- Vulnerable parameter
- Working payload
- Impact assessment
- Steps to reproduce"""
