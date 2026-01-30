# Tools Package - RedStrike.AI
from app.tools.docker_executor import get_docker_executor, DockerExecutor
from app.tools.recon_tools import RECON_TOOLS
from app.tools.discovery_tools import DISCOVERY_TOOLS
from app.tools.scanner_tools import SCANNER_TOOLS
from app.tools.fuzzer_tools import FUZZER_TOOLS

# LangChain tools for LangGraph (all execute in Kali Docker)
from app.tools.langchain_tools import (
    LANGCHAIN_TOOLS,
    RECON_LANGCHAIN_TOOLS,
    DISCOVERY_LANGCHAIN_TOOLS,
    INJECTION_LANGCHAIN_TOOLS,
    SCANNER_LANGCHAIN_TOOLS,
)

# Combined smolagents tools (legacy support)
ALL_TOOLS = RECON_TOOLS + DISCOVERY_TOOLS + SCANNER_TOOLS + FUZZER_TOOLS

__all__ = [
    # Docker executor
    "get_docker_executor",
    "DockerExecutor",
    # Legacy smolagents tools
    "ALL_TOOLS",
    "RECON_TOOLS",
    "DISCOVERY_TOOLS",
    "SCANNER_TOOLS",
    "FUZZER_TOOLS",
    # LangChain tools for LangGraph (Docker execution)
    "LANGCHAIN_TOOLS",
    "RECON_LANGCHAIN_TOOLS",
    "DISCOVERY_LANGCHAIN_TOOLS",
    "INJECTION_LANGCHAIN_TOOLS",
    "SCANNER_LANGCHAIN_TOOLS",
]
