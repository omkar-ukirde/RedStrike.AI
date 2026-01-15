"""
RedStrike.AI - HTTP History Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


class HTTPHistory(Base):
    """HTTP History model - stores raw requests/responses like Burp Suite."""
    __tablename__ = "http_history"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=True)
    
    # Raw request/response
    request_raw = Column(Text, nullable=False)
    response_raw = Column(Text, nullable=True)
    
    # Timing
    request_timestamp = Column(DateTime, default=datetime.utcnow)
    response_time_ms = Column(Integer, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="http_history")
    endpoint = relationship("Endpoint", back_populates="http_history")
    
    def __repr__(self):
        return f"<HTTPHistory {self.id}>"
