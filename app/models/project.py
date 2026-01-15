"""
RedStrike.AI - Project Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class ProjectStatus(str, enum.Enum):
    """Project status enum."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class Project(Base):
    """Project model - represents a pentesting engagement."""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    target_url = Column(String(512), nullable=False)
    
    # User prompt that initiated the project
    prompt = Column(Text, nullable=False)
    
    # Configuration extracted from prompt
    scope_config = Column(JSON, default=dict)  # allowed_domains, excluded_paths
    auth_config = Column(JSON, default=dict)   # type, credentials, headers
    rate_limit_config = Column(JSON, default=dict)  # requests_per_second, delay
    
    # Model configuration
    model_name = Column(String(255), default="ollama/llama3.2")
    
    # Status
    status = Column(Enum(ProjectStatus), default=ProjectStatus.PENDING)
    
    # State for resumability
    state_snapshot = Column(JSON, default=dict)
    
    # Owner
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    http_history = relationship("HTTPHistory", back_populates="project", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Project {self.name}: {self.target_url}>"
