"""
RedStrike.AI - Configuration Module
"""
from pydantic_settings import BaseSettings
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # App
    app_name: str = "RedStrike.AI"
    app_version: str = "1.0.0"
    debug: bool = True
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    
    # Database
    database_url: str = "postgresql+asyncpg://redstrike:redstrike@localhost:5432/redstrike"
    
    # JWT
    jwt_secret_key: str = "your-super-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    
    # LiteLLM
    litellm_model: str = "ollama/llama3.2"
    ollama_api_base: str = "http://localhost:11434"
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    
    # Docker
    kali_container_name: str = "redstrike-kali"
    docker_network: str = "redstrike-network"
    
    # Proxy
    proxy_port: int = 8080
    proxy_enabled: bool = True
    
    # Admin (created on first run)
    admin_email: str = "admin@redstrike.ai"
    admin_password: str = "changeme123"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
