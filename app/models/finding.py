"""
RedStrike.AI - Finding Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class Severity(str, enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, enum.Enum):
    """Common vulnerability types."""
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    IDOR = "idor"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    INFO_DISCLOSURE = "info_disclosure"
    MISCONFIG = "misconfiguration"
    AUTH_BYPASS = "auth_bypass"
    BROKEN_AUTH = "broken_auth"
    EXPOSED_ADMIN = "exposed_admin"
    DEFAULT_CREDS = "default_credentials"
    SUBDOMAIN = "subdomain_takeover"
    OTHER = "other"


class Finding(Base):
    """Finding model - represents a discovered vulnerability."""
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=True)
    
    # Vulnerability info
    title = Column(String(512), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    vulnerability_type = Column(Enum(VulnerabilityType), default=VulnerabilityType.OTHER)
    
    # Affected target
    affected_url = Column(String(2048), nullable=False)
    affected_parameter = Column(String(255), nullable=True)
    
    # Details
    description = Column(Text, nullable=False)
    reproduction_steps = Column(Text, nullable=True)  # Markdown formatted
    poc_code = Column(Text, nullable=True)  # Python PoC code
    
    # Evidence
    request_evidence = Column(Text, nullable=True)
    response_evidence = Column(Text, nullable=True)
    raw_evidence = Column(JSON, default=dict)
    
    # Verification
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    
    # Metadata
    discovered_by = Column(String(255), nullable=True)  # Agent name
    cvss_score = Column(String(10), nullable=True)
    cve_id = Column(String(50), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")
    
    def __repr__(self):
        return f"<Finding [{self.severity.value}] {self.title}>"
