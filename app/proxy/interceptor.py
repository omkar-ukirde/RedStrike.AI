"""
RedStrike.AI - HTTP Proxy Interceptor
Captures HTTP/HTTPS traffic like Burp Suite.
"""
import asyncio
import logging
from typing import Optional, Callable
from datetime import datetime

from mitmproxy import ctx, http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

logger = logging.getLogger(__name__)


class RedStrikeAddon:
    """Mitmproxy addon for intercepting HTTP traffic."""
    
    def __init__(
        self,
        project_id: int,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None,
        scope_domains: Optional[list] = None,
    ):
        self.project_id = project_id
        self.on_request = on_request
        self.on_response = on_response
        self.scope_domains = scope_domains or []
    
    def _in_scope(self, host: str) -> bool:
        """Check if host is in scope."""
        if not self.scope_domains:
            return True
        
        for domain in self.scope_domains:
            if domain.startswith("*."):
                if host.endswith(domain[1:]):
                    return True
            elif host == domain or host.endswith("." + domain):
                return True
        
        return False
    
    def request(self, flow: http.HTTPFlow):
        """Handle intercepted request."""
        if not self._in_scope(flow.request.host):
            return
        
        # Build raw request
        raw_request = self._build_raw_request(flow.request)
        
        if self.on_request:
            asyncio.create_task(self.on_request(
                project_id=self.project_id,
                url=flow.request.pretty_url,
                method=flow.request.method,
                path=flow.request.path,
                headers=dict(flow.request.headers),
                raw_request=raw_request,
            ))
    
    def response(self, flow: http.HTTPFlow):
        """Handle intercepted response."""
        if not self._in_scope(flow.request.host):
            return
        
        raw_request = self._build_raw_request(flow.request)
        raw_response = self._build_raw_response(flow.response)
        
        if self.on_response:
            asyncio.create_task(self.on_response(
                project_id=self.project_id,
                url=flow.request.pretty_url,
                method=flow.request.method,
                path=flow.request.path,
                status_code=flow.response.status_code,
                headers=dict(flow.response.headers),
                raw_request=raw_request,
                raw_response=raw_response,
                response_time_ms=int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000),
            ))
    
    def _build_raw_request(self, request: http.Request) -> str:
        """Build raw HTTP request string."""
        lines = [f"{request.method} {request.path} {request.http_version}"]
        lines.append(f"Host: {request.host}")
        
        for name, value in request.headers.items():
            if name.lower() != "host":
                lines.append(f"{name}: {value}")
        
        lines.append("")
        
        if request.content:
            lines.append(request.content.decode("utf-8", errors="replace"))
        
        return "\r\n".join(lines)
    
    def _build_raw_response(self, response: http.Response) -> str:
        """Build raw HTTP response string."""
        lines = [f"{response.http_version} {response.status_code} {response.reason}"]
        
        for name, value in response.headers.items():
            lines.append(f"{name}: {value}")
        
        lines.append("")
        
        # Limit response body size
        if response.content:
            body = response.content[:50000].decode("utf-8", errors="replace")
            lines.append(body)
        
        return "\r\n".join(lines)


class ProxyInterceptor:
    """Manages the HTTP proxy for a project."""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.master: Optional[DumpMaster] = None
        self._running = False
    
    async def start(
        self,
        project_id: int,
        on_request: Optional[Callable] = None,
        on_response: Optional[Callable] = None,
        scope_domains: Optional[list] = None,
    ):
        """Start the proxy server."""
        if self._running:
            logger.warning("Proxy already running")
            return
        
        options = Options(
            listen_host="0.0.0.0",
            listen_port=self.port,
            ssl_insecure=True,
        )
        
        self.master = DumpMaster(options)
        
        addon = RedStrikeAddon(
            project_id=project_id,
            on_request=on_request,
            on_response=on_response,
            scope_domains=scope_domains,
        )
        
        self.master.addons.add(addon)
        
        self._running = True
        logger.info(f"Proxy started on port {self.port}")
        
        await self.master.run()
    
    def stop(self):
        """Stop the proxy server."""
        if self.master:
            self.master.shutdown()
            self._running = False
            logger.info("Proxy stopped")
    
    @property
    def is_running(self) -> bool:
        return self._running
