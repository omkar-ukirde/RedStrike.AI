"""
RedStrike.AI - Scan Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class ScanStatus(str, enum.Enum):
    """Scan status enum."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentType(str, enum.Enum):
    """Agent type enum."""
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    DISCOVERY = "discovery"
    VULN_SCANNER = "vuln_scanner"
    FUZZER = "fuzzer"
    VERIFIER = "verifier"
    REPORTER = "reporter"


class Scan(Base):
    """Scan model - represents an individual agent's scan execution."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    
    # Agent info
    agent_type = Column(Enum(AgentType), nullable=False)
    agent_name = Column(String(255), nullable=True)
    
    # Status and state
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    state_snapshot = Column(JSON, default=dict)  # For resumability
    
    # Execution details
    command = Column(Text, nullable=True)
    output = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    
    def __repr__(self):
        return f"<Scan {self.agent_type}: {self.status}>"
