"""
RedStrike.AI - Endpoint Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class DiscoveryMethod(str, enum.Enum):
    """How the endpoint was discovered."""
    PROXY = "proxy"
    CRAWLER = "crawler"
    BRUTEFORCE = "bruteforce"
    SCAN = "scan"
    MANUAL = "manual"


class Endpoint(Base):
    """Endpoint model - represents discovered URLs/endpoints for site view."""
    __tablename__ = "endpoints"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    
    # URL info
    url = Column(String(2048), nullable=False)
    method = Column(String(10), default="GET")
    path = Column(String(1024), nullable=False)
    query_params = Column(JSON, default=dict)
    
    # Request/Response info
    request_headers = Column(JSON, default=dict)
    response_headers = Column(JSON, default=dict)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(255), nullable=True)
    response_size = Column(Integer, nullable=True)
    
    # Discovery info
    discovered_by = Column(Enum(DiscoveryMethod), default=DiscoveryMethod.SCAN)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="endpoints")
    findings = relationship("Finding", back_populates="endpoint")
    http_history = relationship("HTTPHistory", back_populates="endpoint")
    
    def __repr__(self):
        return f"<Endpoint {self.method} {self.path}>"
