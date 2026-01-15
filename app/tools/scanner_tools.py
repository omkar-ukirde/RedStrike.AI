"""
RedStrike.AI - Vulnerability Scanner Tools for Smolagents
"""
from smolagents import Tool
from typing import Optional
import json

from app.tools.docker_executor import get_docker_executor


class NucleiScanner(Tool):
    """Scan for vulnerabilities using Nuclei templates."""
    
    name = "nuclei_scanner"
    description = """
    Scan a target for known vulnerabilities using Nuclei templates.
    This is the primary vulnerability scanner that uses community-maintained templates.
    Use for CVE detection, misconfigurations, and known vulnerabilities.
    """
    inputs = {
        "target": {
            "type": "string",
            "description": "Target URL or file with list of URLs"
        },
        "templates": {
            "type": "string",
            "description": "Template categories: 'cves', 'vulnerabilities', 'misconfigurations', 'exposures', 'all'",
            "nullable": True
        },
        "severity": {
            "type": "string",
            "description": "Minimum severity: 'info', 'low', 'medium', 'high', 'critical'",
            "nullable": True
        },
        "tags": {
            "type": "string",
            "description": "Comma-separated tags to filter templates (e.g., 'xss,sqli,rce')",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(
        self,
        target: str,
        templates: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[str] = None
    ) -> str:
        import asyncio
        
        args = f"-u {target} -jsonl -silent"
        
        if templates and templates != "all":
            args += f" -t {templates}/"
        
        if severity:
            args += f" -s {severity}"
        
        if tags:
            args += f" -tags {tags}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("nuclei", args)
        )
        
        if result["success"]:
            findings = []
            for line in result["stdout"].strip().split("\n"):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except:
                        continue
            
            return json.dumps({
                "target": target,
                "findings": findings,
                "count": len(findings),
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class NiktoScanner(Tool):
    """Web server scanner using Nikto."""
    
    name = "nikto_scanner"
    description = """
    Scan a web server for dangerous files, outdated software, and misconfigurations using Nikto.
    Good for identifying server-level issues and missing security headers.
    """
    inputs = {
        "target": {
            "type": "string",
            "description": "Target URL to scan"
        },
        "tuning": {
            "type": "string",
            "description": "Scan tuning: '1' file upload, '2' misc, '3' info disclosure, '4' injection, 'x' all",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, target: str, tuning: Optional[str] = None) -> str:
        import asyncio
        
        args = f"-h {target} -Format json"
        
        if tuning:
            args += f" -Tuning {tuning}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("nikto", args)
        )
        
        return json.dumps({
            "target": target,
            "output": result["stdout"],
            "success": result["success"]
        })


class HeaderAnalyzer(Tool):
    """Analyze HTTP security headers."""
    
    name = "header_analyzer"
    description = """
    Analyze HTTP response headers for security issues.
    Checks for missing security headers like CSP, HSTS, X-Frame-Options, etc.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL to analyze"
        }
    }
    output_type = "string"
    
    def forward(self, url: str) -> str:
        import asyncio
        
        # Use curl to get headers
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute(f"curl -sI {url}")
        )
        
        if result["success"]:
            headers = {}
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            
            for line in result["stdout"].split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            missing_headers = []
            present_headers = []
            for h in security_headers:
                if h in headers or h.lower() in [k.lower() for k in headers]:
                    present_headers.append(h)
                else:
                    missing_headers.append(h)
            
            return json.dumps({
                "url": url,
                "all_headers": headers,
                "security_headers_present": present_headers,
                "security_headers_missing": missing_headers,
                "issues": len(missing_headers),
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class SSLAnalyzer(Tool):
    """Analyze SSL/TLS configuration."""
    
    name = "ssl_analyzer"
    description = """
    Check SSL/TLS configuration for security issues.
    Identifies weak ciphers, expired certificates, and protocol issues.
    """
    inputs = {
        "host": {
            "type": "string",
            "description": "Target hostname to analyze"
        },
        "port": {
            "type": "integer",
            "description": "Port number (default: 443)",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, host: str, port: Optional[int] = None) -> str:
        import asyncio
        
        target_port = port or 443
        
        # Use openssl to check certificate and nmap for SSL analysis
        cert_result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute(
                f"echo | openssl s_client -connect {host}:{target_port} -servername {host} 2>/dev/null | openssl x509 -noout -dates -subject -issuer"
            )
        )
        
        nmap_result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute(f"nmap --script ssl-enum-ciphers -p {target_port} {host}")
        )
        
        return json.dumps({
            "host": host,
            "port": target_port,
            "certificate_info": cert_result["stdout"],
            "cipher_analysis": nmap_result["stdout"],
            "success": True
        })


# Export all tools
SCANNER_TOOLS = [
    NucleiScanner(),
    NiktoScanner(),
    HeaderAnalyzer(),
    SSLAnalyzer(),
]
