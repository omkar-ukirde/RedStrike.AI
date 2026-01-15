"""
RedStrike.AI - Reconnaissance Tools for Smolagents
"""
from smolagents import Tool
from typing import Optional
import json

from app.tools.docker_executor import get_docker_executor


class SubdomainEnumerator(Tool):
    """Enumerate subdomains using subfinder."""
    
    name = "subdomain_enumerator"
    description = """
    Enumerate subdomains for a given domain using subfinder.
    Use this tool when you need to discover subdomains of a target domain.
    Returns a list of discovered subdomains.
    """
    inputs = {
        "domain": {
            "type": "string",
            "description": "The target domain to enumerate subdomains for (e.g., example.com)"
        },
        "sources": {
            "type": "string",
            "description": "Comma-separated list of sources to use (optional)",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, domain: str, sources: Optional[str] = None) -> str:
        import asyncio
        
        args = f"-d {domain} -silent"
        if sources:
            args += f" -sources {sources}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("subfinder", args)
        )
        
        if result["success"]:
            subdomains = result["stdout"].strip().split("\n")
            return json.dumps({
                "domain": domain,
                "subdomains": [s for s in subdomains if s],
                "count": len([s for s in subdomains if s])
            })
        else:
            return json.dumps({"error": result["stderr"]})


class PortScanner(Tool):
    """Scan ports using nmap."""
    
    name = "port_scanner"
    description = """
    Scan ports on a target using nmap.
    Use this tool to discover open ports and services on a target.
    Returns a list of open ports with service information.
    """
    inputs = {
        "target": {
            "type": "string",
            "description": "The target IP or hostname to scan"
        },
        "ports": {
            "type": "string",
            "description": "Port specification (e.g., '80,443', '1-1000', 'top-100')",
            "nullable": True
        },
        "scan_type": {
            "type": "string",
            "description": "Scan type: 'quick', 'full', 'stealth'",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, target: str, ports: Optional[str] = None, scan_type: Optional[str] = None) -> str:
        import asyncio
        
        args = f"{target} -oX -"
        
        if ports:
            if ports == "top-100":
                args += " --top-ports 100"
            else:
                args += f" -p {ports}"
        
        if scan_type == "stealth":
            args = f"-sS {args}"
        elif scan_type == "full":
            args = f"-sV -sC {args}"
        else:  # quick
            args = f"-T4 {args}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("nmap", args)
        )
        
        if result["success"]:
            # Parse XML output
            return json.dumps({
                "target": target,
                "raw_output": result["stdout"],
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class TechnologyDetector(Tool):
    """Detect technologies using httpx and whatweb."""
    
    name = "technology_detector"
    description = """
    Detect technologies and frameworks used by a web application.
    Use this tool to fingerprint web technologies, frameworks, CMS, and server software.
    Returns detected technologies and their versions.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "The target URL to analyze"
        }
    }
    output_type = "string"
    
    def forward(self, url: str) -> str:
        import asyncio
        
        results = {}
        
        # Use httpx for headers and tech detection
        httpx_args = f"-u {url} -tech-detect -status-code -title -server -json"
        httpx_result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("httpx", httpx_args)
        )
        
        if httpx_result["success"]:
            try:
                results["httpx"] = json.loads(httpx_result["stdout"])
            except:
                results["httpx"] = httpx_result["stdout"]
        
        # Use whatweb for detailed fingerprinting
        whatweb_args = f"{url} --log-json=-"
        whatweb_result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("whatweb", whatweb_args)
        )
        
        if whatweb_result["success"]:
            try:
                results["whatweb"] = json.loads(whatweb_result["stdout"])
            except:
                results["whatweb"] = whatweb_result["stdout"]
        
        return json.dumps({
            "url": url,
            "technologies": results,
            "success": True
        })


class WAFDetector(Tool):
    """Detect Web Application Firewalls using wafw00f."""
    
    name = "waf_detector"
    description = """
    Detect if a Web Application Firewall (WAF) is protecting the target.
    Use this tool before running aggressive scans to understand protection.
    Returns detected WAF type if any.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "The target URL to check for WAF"
        }
    }
    output_type = "string"
    
    def forward(self, url: str) -> str:
        import asyncio
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("wafw00f", f"{url} -o -")
        )
        
        if result["success"]:
            return json.dumps({
                "url": url,
                "waf_detected": "No WAF" not in result["stdout"],
                "details": result["stdout"],
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class LiveHostChecker(Tool):
    """Check if hosts are live using httpx."""
    
    name = "live_host_checker"
    description = """
    Check which hosts from a list are live and responding.
    Use this to filter a list of subdomains/hosts to only active ones.
    """
    inputs = {
        "hosts": {
            "type": "string",
            "description": "Comma-separated list of hosts to check"
        }
    }
    output_type = "string"
    
    def forward(self, hosts: str) -> str:
        import asyncio
        
        # Create input file
        host_list = hosts.split(",")
        input_content = "\n".join(h.strip() for h in host_list)
        
        # Write to temp file and run httpx
        asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute(f"echo '{input_content}' > /tmp/hosts.txt")
        )
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute("cat /tmp/hosts.txt | httpx -silent")
        )
        
        if result["success"]:
            live_hosts = [h for h in result["stdout"].strip().split("\n") if h]
            return json.dumps({
                "total_checked": len(host_list),
                "live_hosts": live_hosts,
                "live_count": len(live_hosts)
            })
        else:
            return json.dumps({"error": result["stderr"]})


# Export all tools
RECON_TOOLS = [
    SubdomainEnumerator(),
    PortScanner(),
    TechnologyDetector(),
    WAFDetector(),
    LiveHostChecker(),
]
