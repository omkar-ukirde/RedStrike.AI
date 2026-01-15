"""
RedStrike.AI - Findings API
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import io

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import Finding, Project, Severity, VulnerabilityType
from app.agents import ReporterAgent

router = APIRouter(prefix="/api", tags=["Findings"])


# Pydantic Schemas
class FindingResponse(BaseModel):
    id: int
    project_id: int
    title: str
    severity: Severity
    vulnerability_type: VulnerabilityType
    affected_url: str
    affected_parameter: Optional[str]
    description: str
    reproduction_steps: Optional[str]
    poc_code: Optional[str]
    verified: bool
    false_positive: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class FindingListResponse(BaseModel):
    id: int
    title: str
    severity: Severity
    vulnerability_type: VulnerabilityType
    affected_url: str
    verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    verified: Optional[bool] = None
    false_positive: Optional[bool] = None


# Endpoints
@router.get("/projects/{project_id}/findings", response_model=List[FindingListResponse])
async def list_findings(
    project_id: int,
    severity: Optional[Severity] = None,
    vuln_type: Optional[VulnerabilityType] = None,
    verified_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all findings for a project."""
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = select(Finding).where(Finding.project_id == project_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    if vuln_type:
        query = query.where(Finding.vulnerability_type == vuln_type)
    if verified_only:
        query = query.where(Finding.verified == True)
    
    query = query.order_by(Finding.severity, Finding.created_at.desc())
    
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get finding details with PoC code."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == finding.project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: int,
    update_data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update finding (mark as verified or false positive)."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == finding.project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if update_data.verified is not None:
        finding.verified = update_data.verified
        if update_data.verified:
            finding.verified_at = datetime.utcnow()
    
    if update_data.false_positive is not None:
        finding.false_positive = update_data.false_positive
    
    await db.commit()
    await db.refresh(finding)
    
    return finding


@router.get("/projects/{project_id}/export")
async def export_findings_csv(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Export findings as CSV."""
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get findings
    result = await db.execute(
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.severity)
    )
    findings = result.scalars().all()
    
    # Generate CSV
    reporter = ReporterAgent()
    findings_data = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "vulnerability_type": f.vulnerability_type.value,
            "affected_url": f.affected_url,
            "affected_parameter": f.affected_parameter,
            "description": f.description,
            "poc_code": f.poc_code,
            "reproduction_steps": f.reproduction_steps,
            "verified": f.verified,
        }
        for f in findings
    ]
    
    csv_content = reporter.generate_csv_export(findings_data)
    
    # Return as downloadable file
    return StreamingResponse(
        io.BytesIO(csv_content.encode()),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={project.name}_findings.csv"
        },
    )


@router.get("/projects/{project_id}/report")
async def generate_report(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Generate a markdown report for the project."""
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get findings
    result = await db.execute(
        select(Finding)
        .where(Finding.project_id == project_id)
        .where(Finding.false_positive == False)
        .order_by(Finding.severity)
    )
    findings = result.scalars().all()
    
    # Generate report
    reporter = ReporterAgent(model_name=project.model_name)
    findings_data = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "vulnerability_type": f.vulnerability_type.value,
            "affected_url": f.affected_url,
            "description": f.description,
            "poc_code": f.poc_code,
            "reproduction_steps": f.reproduction_steps,
        }
        for f in findings
    ]
    
    project_info = {
        "name": project.name,
        "target_url": project.target_url,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
    }
    
    report = reporter.generate_report(findings_data, project_info)
    
    return {"report": report, "format": "markdown"}
