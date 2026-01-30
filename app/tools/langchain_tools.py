"""
RedStrike.AI - LangChain Tool Wrappers
Wraps Docker-executed security tools for use with LangGraph.
All tools execute in the Kali Docker container.
"""
from typing import Optional, List, Type
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field
import asyncio
import json

from app.tools.docker_executor import get_docker_executor


# ============================================================
# RECONNAISSANCE TOOLS
# ============================================================

class SubfinderInput(BaseModel):
    domain: str = Field(description="Target domain for subdomain enumeration")
    recursive: bool = Field(default=False, description="Enable recursive subdomain discovery")


def subfinder(domain: str, recursive: bool = False) -> str:
    """Discover subdomains using Subfinder. Executes in Kali Docker container."""
    args = f"-d {domain} -silent"
    if recursive:
        args += " -recursive"
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("subfinder", args)
    )
    return json.dumps({
        "domain": domain,
        "subdomains": result["stdout"].strip().split("\n") if result["stdout"] else [],
        "success": result["success"]
    })


class NmapInput(BaseModel):
    target: str = Field(description="Target IP or hostname")
    ports: str = Field(default="--top-ports 1000", description="Ports to scan (e.g., '22,80,443' or '-p-' for all)")
    scan_type: str = Field(default="default", description="Scan type: 'quick', 'full', 'version', 'vuln'")


def nmap_scan(target: str, ports: str = "--top-ports 1000", scan_type: str = "default") -> str:
    """Run nmap port scan. Executes in Kali Docker container."""
    scan_flags = {
        "quick": "-sT -T4",
        "full": "-sS -sV -sC -O",
        "version": "-sV",
        "vuln": "--script vuln",
        "default": "-sT -sV"
    }
    
    flags = scan_flags.get(scan_type, scan_flags["default"])
    args = f"{flags} {ports} {target}"
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("nmap", args)
    )
    return json.dumps({
        "target": target,
        "output": result["stdout"],
        "success": result["success"]
    })


class TechDetectInput(BaseModel):
    url: str = Field(description="Target URL for technology detection")


def detect_technologies(url: str) -> str:
    """Detect web technologies using whatweb. Executes in Kali Docker container."""
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("whatweb", f"-a 3 {url}")
    )
    return json.dumps({
        "url": url,
        "technologies": result["stdout"],
        "success": result["success"]
    })


def detect_waf(url: str) -> str:
    """Detect Web Application Firewall using wafw00f. Executes in Kali Docker container."""
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("wafw00f", f"{url} -o -")
    )
    return json.dumps({
        "url": url,
        "waf_info": result["stdout"],
        "success": result["success"]
    })


# ============================================================
# DISCOVERY TOOLS
# ============================================================

class DirectoryBruteInput(BaseModel):
    url: str = Field(description="Target URL for directory bruteforce")
    wordlist: str = Field(default="common", description="Wordlist: 'common', 'directories', 'directories-small'")
    extensions: str = Field(default="", description="File extensions to check (comma-separated)")


def directory_bruteforce(url: str, wordlist: str = "common", extensions: str = "") -> str:
    """Bruteforce directories using ffuf. Executes in Kali Docker container."""
    wordlist_path = get_docker_executor().get_wordlist_path(wordlist)
    
    args = f'-u "{url}/FUZZ" -w {wordlist_path} -mc 200,301,302,403 -o /tmp/ffuf_output.json -of json'
    if extensions:
        args += f" -e {extensions}"
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("ffuf", args)
    )
    
    # Read output file
    cat_result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute("cat /tmp/ffuf_output.json 2>/dev/null || echo '{}'")
    )
    
    return json.dumps({
        "url": url,
        "results": cat_result["stdout"],
        "success": result["success"]
    })


class CrawlerInput(BaseModel):
    url: str = Field(description="Target URL to crawl")
    depth: int = Field(default=3, description="Crawl depth")


def crawl_website(url: str, depth: int = 3) -> str:
    """Crawl website for endpoints using katana. Executes in Kali Docker container."""
    args = f'-u "{url}" -d {depth} -silent -o /tmp/katana_output.txt'
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("katana", args)
    )
    
    cat_result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute("cat /tmp/katana_output.txt 2>/dev/null")
    )
    
    return json.dumps({
        "url": url,
        "endpoints": cat_result["stdout"].strip().split("\n") if cat_result["stdout"] else [],
        "success": result["success"]
    })


# ============================================================
# INJECTION TESTING TOOLS
# ============================================================

class SQLiInput(BaseModel):
    url: str = Field(description="Target URL with parameters")
    data: str = Field(default="", description="POST data (optional)")
    level: int = Field(default=1, description="Test level 1-5")
    risk: int = Field(default=1, description="Risk level 1-3")


def test_sqli(url: str, data: str = "", level: int = 1, risk: int = 1) -> str:
    """Test for SQL injection using sqlmap. Executes in Kali Docker container."""
    args = f'-u "{url}" --batch --level={level} --risk={risk}'
    if data:
        args += f' --data="{data}"'
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("sqlmap", args)
    )
    
    vulnerable = "is vulnerable" in result["stdout"].lower() or "injectable" in result["stdout"].lower()
    
    return json.dumps({
        "url": url,
        "vulnerable": vulnerable,
        "output": result["stdout"],
        "success": result["success"]
    })


class XSSInput(BaseModel):
    url: str = Field(description="Target URL with parameters")
    param: str = Field(default="", description="Specific parameter to test")


def test_xss(url: str, param: str = "") -> str:
    """Test for XSS using dalfox. Executes in Kali Docker container."""
    args = f'url "{url}" --silence'
    if param:
        args += f" -p {param}"
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("dalfox", args)
    )
    
    findings = []
    for line in result["stdout"].split("\n"):
        if "[POC]" in line or "[V]" in line:
            findings.append(line.strip())
    
    return json.dumps({
        "url": url,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "success": result["success"]
    })


# ============================================================
# VULNERABILITY SCANNING TOOLS
# ============================================================

class NucleiInput(BaseModel):
    target: str = Field(description="Target URL")
    severity: str = Field(default="critical,high", description="Severity filter: critical,high,medium,low")
    tags: str = Field(default="", description="Template tags (e.g., cve,rce)")


def nuclei_scan(target: str, severity: str = "critical,high", tags: str = "") -> str:
    """Run nuclei vulnerability scan. Executes in Kali Docker container."""
    args = f'-u "{target}" -s {severity} -silent -o /tmp/nuclei_output.txt'
    if tags:
        args += f" -tags {tags}"
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("nuclei", args)
    )
    
    cat_result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute("cat /tmp/nuclei_output.txt 2>/dev/null")
    )
    
    return json.dumps({
        "target": target,
        "findings": cat_result["stdout"].strip().split("\n") if cat_result["stdout"] else [],
        "success": result["success"]
    })


class NiktoInput(BaseModel):
    target: str = Field(description="Target URL for web server scanning")


def nikto_scan(target: str) -> str:
    """Run nikto web server scan. Executes in Kali Docker container."""
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute_tool("nikto", f"-h {target} -Format txt")
    )
    return json.dumps({
        "target": target,
        "output": result["stdout"],
        "success": result["success"]
    })


# ============================================================
# HTTP/CURL TOOLS
# ============================================================

class CurlInput(BaseModel):
    url: str = Field(description="Target URL")
    method: str = Field(default="GET", description="HTTP method")
    data: str = Field(default="", description="Request body")
    headers: str = Field(default="", description="Custom headers (JSON format)")


def http_request(url: str, method: str = "GET", data: str = "", headers: str = "") -> str:
    """Make HTTP request using curl. Executes in Kali Docker container."""
    cmd = f'curl -s -X {method} "{url}" -w "\\n%{{http_code}}"'
    
    if data:
        cmd += f" -d '{data}'"
    
    if headers:
        try:
            header_dict = json.loads(headers)
            for key, value in header_dict.items():
                cmd += f' -H "{key}: {value}"'
        except json.JSONDecodeError:
            pass
    
    result = asyncio.get_event_loop().run_until_complete(
        get_docker_executor().execute(cmd)
    )
    
    lines = result["stdout"].strip().split("\n")
    status_code = lines[-1] if lines else "0"
    body = "\n".join(lines[:-1]) if len(lines) > 1 else ""
    
    return json.dumps({
        "url": url,
        "status_code": status_code,
        "body": body,
        "success": result["success"]
    })


# ============================================================
# CREATE LANGCHAIN TOOLS
# ============================================================

def create_langchain_tools() -> List[BaseTool]:
    """Create list of LangChain tools for LangGraph agents."""
    return [
        # Reconnaissance
        StructuredTool.from_function(
            func=subfinder,
            name="subfinder",
            description="Discover subdomains for a domain. Executes in Kali Docker.",
            args_schema=SubfinderInput,
        ),
        StructuredTool.from_function(
            func=nmap_scan,
            name="nmap_scan",
            description="Scan ports and services. Executes in Kali Docker.",
            args_schema=NmapInput,
        ),
        StructuredTool.from_function(
            func=detect_technologies,
            name="detect_technologies",
            description="Detect web technologies. Executes in Kali Docker.",
            args_schema=TechDetectInput,
        ),
        StructuredTool.from_function(
            func=detect_waf,
            name="detect_waf",
            description="Detect Web Application Firewall. Executes in Kali Docker.",
            args_schema=TechDetectInput,
        ),
        
        # Discovery
        StructuredTool.from_function(
            func=directory_bruteforce,
            name="directory_bruteforce",
            description="Bruteforce directories and files. Executes in Kali Docker.",
            args_schema=DirectoryBruteInput,
        ),
        StructuredTool.from_function(
            func=crawl_website,
            name="crawl_website",
            description="Crawl website for endpoints. Executes in Kali Docker.",
            args_schema=CrawlerInput,
        ),
        
        # Injection Testing
        StructuredTool.from_function(
            func=test_sqli,
            name="test_sqli",
            description="Test for SQL injection with sqlmap. Executes in Kali Docker.",
            args_schema=SQLiInput,
        ),
        StructuredTool.from_function(
            func=test_xss,
            name="test_xss",
            description="Test for XSS with dalfox. Executes in Kali Docker.",
            args_schema=XSSInput,
        ),
        
        # Vulnerability Scanning
        StructuredTool.from_function(
            func=nuclei_scan,
            name="nuclei_scan",
            description="Run nuclei vulnerability scan. Executes in Kali Docker.",
            args_schema=NucleiInput,
        ),
        StructuredTool.from_function(
            func=nikto_scan,
            name="nikto_scan",
            description="Run nikto web server scan. Executes in Kali Docker.",
            args_schema=NiktoInput,
        ),
        
        # HTTP
        StructuredTool.from_function(
            func=http_request,
            name="http_request",
            description="Make HTTP request with curl. Executes in Kali Docker.",
            args_schema=CurlInput,
        ),
    ]


# Pre-built tool list for import
LANGCHAIN_TOOLS = create_langchain_tools()


# Tool groups for subagents
RECON_LANGCHAIN_TOOLS = [t for t in LANGCHAIN_TOOLS if t.name in [
    "subfinder", "nmap_scan", "detect_technologies", "detect_waf"
]]

DISCOVERY_LANGCHAIN_TOOLS = [t for t in LANGCHAIN_TOOLS if t.name in [
    "directory_bruteforce", "crawl_website"
]]

INJECTION_LANGCHAIN_TOOLS = [t for t in LANGCHAIN_TOOLS if t.name in [
    "test_sqli", "test_xss", "http_request"
]]

SCANNER_LANGCHAIN_TOOLS = [t for t in LANGCHAIN_TOOLS if t.name in [
    "nuclei_scan", "nikto_scan"
]]
