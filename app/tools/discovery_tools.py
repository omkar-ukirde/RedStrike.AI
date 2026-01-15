"""
RedStrike.AI - Content Discovery Tools for Smolagents
"""
from smolagents import Tool
from typing import Optional
import json

from app.tools.docker_executor import get_docker_executor


class DirectoryBruteforcer(Tool):
    """Brute-force directories and files using ffuf."""
    
    name = "directory_bruteforcer"
    description = """
    Discover hidden directories and files on a web server using ffuf.
    Use this tool to find admin panels, backup files, and hidden endpoints.
    Returns a list of discovered paths with status codes.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL with FUZZ keyword for injection point (e.g., http://example.com/FUZZ)"
        },
        "wordlist": {
            "type": "string",
            "description": "Wordlist to use: 'common', 'directories', 'directories-small'",
            "nullable": True
        },
        "extensions": {
            "type": "string",
            "description": "File extensions to check (comma-separated, e.g., 'php,html,txt')",
            "nullable": True
        },
        "filter_codes": {
            "type": "string",
            "description": "Status codes to filter out (e.g., '404,403')",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(
        self,
        url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[str] = None,
        filter_codes: Optional[str] = None
    ) -> str:
        import asyncio
        
        wordlist_path = get_docker_executor().get_wordlist_path(wordlist or "common")
        
        args = f"-u {url} -w {wordlist_path} -o /tmp/ffuf_output.json -of json"
        
        if extensions:
            args += f" -e {extensions}"
        
        if filter_codes:
            args += f" -fc {filter_codes}"
        else:
            args += " -fc 404"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("ffuf", args)
        )
        
        # Read output file
        output = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute("cat /tmp/ffuf_output.json 2>/dev/null || echo '{}'")
        )
        
        try:
            ffuf_results = json.loads(output["stdout"])
            discovered = []
            if "results" in ffuf_results:
                for r in ffuf_results["results"]:
                    discovered.append({
                        "url": r.get("url"),
                        "status": r.get("status"),
                        "length": r.get("length"),
                        "words": r.get("words"),
                    })
            return json.dumps({
                "target": url,
                "discovered": discovered,
                "count": len(discovered),
                "success": True
            })
        except:
            return json.dumps({
                "target": url,
                "raw_output": result["stdout"],
                "success": result["success"]
            })


class GobusterScanner(Tool):
    """Directory discovery using gobuster."""
    
    name = "gobuster_scanner"
    description = """
    Alternative directory brute-forcing using gobuster.
    Use for DNS subdomain enumeration or directory discovery.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL to scan"
        },
        "mode": {
            "type": "string",
            "description": "Mode: 'dir' for directories, 'dns' for subdomains, 'vhost' for virtual hosts",
            "nullable": True
        },
        "wordlist": {
            "type": "string",
            "description": "Wordlist name: 'common', 'directories', 'subdomains'",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, url: str, mode: str = "dir", wordlist: Optional[str] = None) -> str:
        import asyncio
        
        if mode == "dns":
            wordlist_path = get_docker_executor().get_wordlist_path(wordlist or "subdomains")
        else:
            wordlist_path = get_docker_executor().get_wordlist_path(wordlist or "common")
        
        args = f"{mode} -u {url} -w {wordlist_path} -q"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("gobuster", args)
        )
        
        if result["success"]:
            lines = result["stdout"].strip().split("\n")
            discovered = [line for line in lines if line.strip()]
            return json.dumps({
                "target": url,
                "mode": mode,
                "discovered": discovered,
                "count": len(discovered),
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class EndpointCrawler(Tool):
    """Crawl and discover endpoints using katana."""
    
    name = "endpoint_crawler"
    description = """
    Crawl a website to discover all endpoints, forms, and links using katana.
    Use this for comprehensive endpoint discovery before testing.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL to crawl"
        },
        "depth": {
            "type": "integer",
            "description": "Crawl depth (default: 3)",
            "nullable": True
        },
        "js_crawl": {
            "type": "boolean",
            "description": "Enable JavaScript crawling for SPAs",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, url: str, depth: Optional[int] = None, js_crawl: Optional[bool] = None) -> str:
        import asyncio
        
        args = f"-u {url} -silent"
        
        if depth:
            args += f" -d {depth}"
        else:
            args += " -d 3"
        
        if js_crawl:
            args += " -js-crawl"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("katana", args)
        )
        
        if result["success"]:
            endpoints = [e for e in result["stdout"].strip().split("\n") if e]
            return json.dumps({
                "target": url,
                "endpoints": endpoints,
                "count": len(endpoints),
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


class ParameterFinder(Tool):
    """Find hidden parameters using arjun."""
    
    name = "parameter_finder"
    description = """
    Discover hidden GET and POST parameters on web endpoints using arjun.
    Use this to find undocumented API parameters for testing.
    """
    inputs = {
        "url": {
            "type": "string",
            "description": "Target URL to test for hidden parameters"
        },
        "method": {
            "type": "string",
            "description": "HTTP method: GET or POST",
            "nullable": True
        }
    }
    output_type = "string"
    
    def forward(self, url: str, method: Optional[str] = None) -> str:
        import asyncio
        
        args = f"-u {url} --stable"
        
        if method:
            args += f" -m {method.upper()}"
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute_tool("arjun", args)
        )
        
        return json.dumps({
            "url": url,
            "output": result["stdout"],
            "success": result["success"]
        })


class WaybackFetcher(Tool):
    """Fetch historical URLs from Wayback Machine."""
    
    name = "wayback_fetcher"
    description = """
    Retrieve historical URLs from the Wayback Machine for a domain.
    Useful for finding old endpoints, removed pages, and exposed files.
    """
    inputs = {
        "domain": {
            "type": "string",
            "description": "Target domain to look up"
        }
    }
    output_type = "string"
    
    def forward(self, domain: str) -> str:
        import asyncio
        
        result = asyncio.get_event_loop().run_until_complete(
            get_docker_executor().execute(f"echo {domain} | waybackurls")
        )
        
        if result["success"]:
            urls = [u for u in result["stdout"].strip().split("\n") if u]
            return json.dumps({
                "domain": domain,
                "urls": urls[:500],  # Limit to 500
                "total_count": len(urls),
                "success": True
            })
        else:
            return json.dumps({"error": result["stderr"]})


# Export all tools
DISCOVERY_TOOLS = [
    DirectoryBruteforcer(),
    GobusterScanner(),
    EndpointCrawler(),
    ParameterFinder(),
    WaybackFetcher(),
]
