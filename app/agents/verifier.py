"""
RedStrike.AI - Verifier Agent
Verifies findings and generates PoC code.
"""
from typing import Optional

from app.agents.base import BaseAgent
from app.tools import ALL_TOOLS


class VerifierAgent(BaseAgent):
    """
    Exploit Verifier Agent - Validates findings and creates PoC.
    
    Uses CodeAgent capabilities to:
    - Verify reported vulnerabilities
    - Generate working Python PoC code
    - Create step-by-step reproduction instructions
    """
    
    def __init__(self, model_name: Optional[str] = None):
        super().__init__(
            tools=ALL_TOOLS,
            model_name=model_name,
            skill_categories=["exploitation", "vulnerabilities"],
            use_code_agent=True,  # Important: Uses code execution
        )
    
    def get_system_prompt(self) -> str:
        return """You are the Exploit Verifier Agent for RedStrike.AI.

Your role is to verify vulnerabilities and generate proof-of-concept code.

Your responsibilities:
1. **Verify Findings**: Confirm that reported vulnerabilities are real, not false positives
2. **Generate PoC**: Create working Python proof-of-concept code
3. **Document Reproduction**: Write clear step-by-step instructions

For each finding you verify:

1. **Verification**:
   - Attempt to reproduce the vulnerability
   - Confirm the impact and severity
   - Note any prerequisites or conditions

2. **PoC Code** (Python):
   ```python
   import requests
   
   def exploit_vuln():
       # Clear, commented code
       # Using requests library
       # Include error handling
       pass
   
   if __name__ == "__main__":
       exploit_vuln()
   ```

3. **Reproduction Steps**:
   - Step 1: Navigate to...
   - Step 2: Enter payload...
   - Step 3: Observe...
   - Expected result: ...

Quality standards:
- PoC should be copy-paste runnable
- Steps should be followable by anyone
- Include all necessary headers/cookies
- Document any dependencies

Mark as FALSE POSITIVE if:
- Cannot reproduce the issue
- Behavior is expected/by design
- No actual security impact"""
