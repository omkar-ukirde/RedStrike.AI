"""
RedStrike.AI - Base Agent Utilities
LangGraph/LangChain-based agent infrastructure.
"""
from typing import Optional
import os
import logging

from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.prebuilt import create_react_agent

from app.core.config import settings
from app.models.llm_router import get_model_for_agent

logger = logging.getLogger(__name__)


def get_ollama_base_url() -> str:
    """Get Ollama API base URL, adjusted for Docker environment."""
    ollama_base = settings.ollama_api_base
    if "localhost" in ollama_base:
        # In Docker, localhost refers to the container itself
        # Use host.docker.internal to reach host machine
        ollama_base = ollama_base.replace("localhost", "host.docker.internal")
    return ollama_base


def setup_llm_environment():
    """Configure LLM environment variables for LiteLLM."""
    ollama_base = get_ollama_base_url()
    os.environ["OLLAMA_API_BASE"] = ollama_base


# Run setup on module import
setup_llm_environment()
