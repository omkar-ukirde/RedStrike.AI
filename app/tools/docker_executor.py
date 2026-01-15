"""
RedStrike.AI - Docker Executor
Executes commands in the Kali Linux container.
"""
import asyncio
import docker
from docker.errors import NotFound, APIError
from typing import Optional, Dict, Any
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class DockerExecutor:
    """Execute commands in the Kali Docker container."""
    
    def __init__(self):
        self.client = docker.from_env()
        self.container_name = settings.kali_container_name
        self._container = None
    
    @property
    def container(self):
        """Get or create the Kali container."""
        if self._container is None:
            try:
                self._container = self.client.containers.get(self.container_name)
            except NotFound:
                logger.error(f"Container {self.container_name} not found. Please run docker-compose up.")
                raise RuntimeError(f"Kali container '{self.container_name}' not found")
        return self._container
    
    async def execute(
        self,
        command: str,
        timeout: int = 300,
        workdir: str = "/data",
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a command in the Kali container.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            workdir: Working directory in container
            env: Environment variables
            
        Returns:
            Dict with exit_code, stdout, stderr
        """
        try:
            # Run command in container
            exec_result = self.container.exec_run(
                cmd=f"/bin/bash -c '{command}'",
                workdir=workdir,
                environment=env or {},
                demux=True,
            )
            
            exit_code = exec_result.exit_code
            stdout = exec_result.output[0].decode() if exec_result.output[0] else ""
            stderr = exec_result.output[1].decode() if exec_result.output[1] else ""
            
            return {
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "success": exit_code == 0,
            }
            
        except APIError as e:
            logger.error(f"Docker API error: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
            }
    
    async def execute_tool(
        self,
        tool_name: str,
        args: str,
        output_file: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a security tool in the container.
        
        Args:
            tool_name: Name of the tool (e.g., nmap, nuclei, ffuf)
            args: Command line arguments
            output_file: Optional output file path
            
        Returns:
            Dict with result
        """
        command = f"{tool_name} {args}"
        if output_file:
            command += f" -o {output_file}"
        
        logger.info(f"Executing: {command}")
        result = await self.execute(command)
        
        # If output file was specified, read it
        if output_file and result["success"]:
            cat_result = await self.execute(f"cat {output_file}")
            result["output_content"] = cat_result["stdout"]
        
        return result
    
    def get_wordlist_path(self, wordlist_name: str) -> str:
        """Get the path to a SecLists wordlist."""
        wordlist_mapping = {
            "directories": "/wordlists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "directories-small": "/wordlists/Discovery/Web-Content/directory-list-2.3-small.txt",
            "common": "/wordlists/Discovery/Web-Content/common.txt",
            "subdomains": "/wordlists/Discovery/DNS/subdomains-top1million-5000.txt",
            "passwords": "/wordlists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
            "usernames": "/wordlists/Usernames/Names/names.txt",
            "sqli": "/wordlists/Fuzzing/SQLi/Generic-SQLi.txt",
            "xss": "/wordlists/Fuzzing/XSS/XSS-Jhaddix.txt",
            "lfi": "/wordlists/Fuzzing/LFI/LFI-Jhaddix.txt",
        }
        return wordlist_mapping.get(wordlist_name, wordlist_name)

# Lazy initialization to avoid import-time Docker connection failures
_docker_executor = None

def get_docker_executor() -> DockerExecutor:
    """Get or create the Docker executor instance."""
    global _docker_executor
    if _docker_executor is None:
        _docker_executor = DockerExecutor()
    return _docker_executor

# For backwards compatibility
docker_executor = None  # Will be None until first call to get_docker_executor()
