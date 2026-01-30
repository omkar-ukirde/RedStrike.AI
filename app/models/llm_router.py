"""
RedStrike.AI - Multi-Provider LLM Router
Handles routing to different LLM providers based on configuration.
"""
import os
import yaml
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


class LLMRouter:
    """
    Routes to appropriate LLM provider/model based on agent type.
    Supports: ollama, openai, anthropic, vllm, together, groq, azure, google
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the LLM router.
        
        Args:
            config_path: Path to llm_config.yaml. If None, uses default location.
        """
        if config_path is None:
            # Default config location
            config_path = Path(__file__).parent.parent.parent / "config" / "llm_config.yaml"
        
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._model_cache: Dict[str, BaseChatModel] = {}
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            logger.warning(f"Config not found at {self.config_path}, using defaults")
            return self._get_default_config()
        
        with open(self.config_path, "r") as f:
            config = yaml.safe_load(f)
        
        # Expand environment variables in config
        return self._expand_env_vars(config)
    
    def _expand_env_vars(self, obj: Any) -> Any:
        """Recursively expand ${VAR} patterns in config values."""
        if isinstance(obj, str):
            # Handle ${VAR} pattern
            if obj.startswith("${") and obj.endswith("}"):
                var_name = obj[2:-1]
                return os.environ.get(var_name)
            return obj
        elif isinstance(obj, dict):
            return {k: self._expand_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._expand_env_vars(item) for item in obj]
        return obj
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            "default": {
                "provider": "ollama",
                "model": "qwen2.5:7b",
                "api_base": "http://localhost:11434",
                "temperature": 0.1,
                "max_tokens": 4096,
            },
            "agents": {},
        }
    
    def _get_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Get configuration for specific agent type."""
        agents_config = self.config.get("agents", {})
        default_config = self.config.get("default", {})
        
        if agent_type in agents_config:
            # Merge with defaults
            agent_config = {**default_config, **agents_config[agent_type]}
        else:
            agent_config = default_config.copy()
        
        return agent_config
    
    def get_model(self, agent_type: str, force_reload: bool = False) -> BaseChatModel:
        """
        Get the LLM model for a specific agent type.
        
        Args:
            agent_type: Type of agent (orchestrator, recon, fuzzer, etc.)
            force_reload: Force reload the model even if cached
            
        Returns:
            BaseChatModel instance configured for the agent
        """
        cache_key = agent_type
        
        if not force_reload and cache_key in self._model_cache:
            return self._model_cache[cache_key]
        
        config = self._get_agent_config(agent_type)
        provider = config.get("provider", "ollama")
        
        try:
            model = self._create_model(provider, config)
            self._model_cache[cache_key] = model
            logger.info(f"Loaded {provider}/{config.get('model')} for {agent_type}")
            return model
        except Exception as e:
            logger.error(f"Failed to load model for {agent_type}: {e}")
            raise
    
    def _create_model(self, provider: str, config: Dict[str, Any]) -> BaseChatModel:
        """Create model instance based on provider."""
        model_name = config.get("model")
        temperature = config.get("temperature", 0.1)
        max_tokens = config.get("max_tokens", 4096)
        
        if provider == "ollama":
            from langchain_ollama import ChatOllama
            api_base = config.get("api_base", "http://localhost:11434")
            return ChatOllama(
                model=model_name,
                base_url=api_base,
                temperature=temperature,
                num_predict=max_tokens,
            )
        
        elif provider == "openai":
            from langchain_openai import ChatOpenAI
            api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
            api_base = config.get("api_base", "https://api.openai.com/v1")
            return ChatOpenAI(
                model=model_name,
                api_key=api_key,
                base_url=api_base,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            api_key = config.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
            return ChatAnthropic(
                model=model_name,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        elif provider == "vllm":
            from langchain_openai import ChatOpenAI
            api_base = config.get("api_base", "http://localhost:8000/v1")
            return ChatOpenAI(
                model=model_name,
                base_url=api_base,
                api_key="not-needed",  # vLLM doesn't require key
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        elif provider == "together":
            from langchain_openai import ChatOpenAI
            api_key = config.get("api_key") or os.environ.get("TOGETHER_API_KEY")
            return ChatOpenAI(
                model=model_name,
                base_url="https://api.together.xyz/v1",
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        elif provider == "groq":
            from langchain_groq import ChatGroq
            api_key = config.get("api_key") or os.environ.get("GROQ_API_KEY")
            return ChatGroq(
                model=model_name,
                api_key=api_key,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        elif provider == "google":
            from langchain_google_genai import ChatGoogleGenerativeAI
            api_key = config.get("api_key") or os.environ.get("GOOGLE_API_KEY")
            return ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=api_key,
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
        
        elif provider == "azure":
            from langchain_openai import AzureChatOpenAI
            api_key = config.get("api_key") or os.environ.get("AZURE_OPENAI_API_KEY")
            endpoint = config.get("api_base") or os.environ.get("AZURE_OPENAI_ENDPOINT")
            deployment = config.get("deployment_name", model_name)
            return AzureChatOpenAI(
                azure_deployment=deployment,
                azure_endpoint=endpoint,
                api_key=api_key,
                api_version=config.get("api_version", "2024-02-15-preview"),
                temperature=temperature,
                max_tokens=max_tokens,
            )
        
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    def list_configured_agents(self) -> Dict[str, str]:
        """List all configured agents and their models."""
        agents_config = self.config.get("agents", {})
        default = self.config.get("default", {})
        
        result = {}
        for agent_type in agents_config:
            config = self._get_agent_config(agent_type)
            provider = config.get("provider", "ollama")
            model = config.get("model", "unknown")
            result[agent_type] = f"{provider}/{model}"
        
        # Add default for unlisted agents
        result["_default"] = f"{default.get('provider', 'ollama')}/{default.get('model', 'unknown')}"
        
        return result
    
    def reload_config(self):
        """Reload configuration and clear cache."""
        self.config = self._load_config()
        self._model_cache.clear()
        logger.info("LLM configuration reloaded")


# Singleton instance
_router_instance: Optional[LLMRouter] = None


def get_llm_router(config_path: Optional[str] = None) -> LLMRouter:
    """Get the global LLM router instance."""
    global _router_instance
    
    if _router_instance is None:
        _router_instance = LLMRouter(config_path)
    
    return _router_instance


def get_model_for_agent(agent_type: str) -> BaseChatModel:
    """Convenience function to get model for an agent type."""
    return get_llm_router().get_model(agent_type)
