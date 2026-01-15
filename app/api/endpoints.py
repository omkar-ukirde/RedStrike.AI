"""
RedStrike.AI - Endpoints API (Site View)
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
from collections import defaultdict

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import Endpoint, HTTPHistory, Finding, Project, DiscoveryMethod

router = APIRouter(prefix="/api", tags=["Endpoints"])


# Pydantic Schemas
class EndpointResponse(BaseModel):
    id: int
    project_id: int
    url: str
    method: str
    path: str
    status_code: Optional[int]
    content_type: Optional[str]
    discovered_by: DiscoveryMethod
    findings_count: int = 0
    created_at: datetime
    
    class Config:
        from_attributes = True


class HTTPHistoryResponse(BaseModel):
    id: int
    request_raw: str
    response_raw: Optional[str]
    request_timestamp: datetime
    response_time_ms: Optional[int]
    
    class Config:
        from_attributes = True


class SitemapNode(BaseModel):
    path: str
    method: Optional[str] = None
    endpoint_id: Optional[int] = None
    findings: List[Dict[str, Any]] = []
    children: Dict[str, "SitemapNode"] = {}
    
    class Config:
        from_attributes = True


# Endpoints
@router.get("/projects/{project_id}/endpoints", response_model=List[EndpointResponse])
async def list_endpoints(
    project_id: int,
    method: Optional[str] = None,
    has_findings: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all discovered endpoints for a project."""
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = select(Endpoint).where(Endpoint.project_id == project_id)
    
    if method:
        query = query.where(Endpoint.method == method.upper())
    
    result = await db.execute(query)
    endpoints = result.scalars().all()
    
    # Add findings count
    response = []
    for e in endpoints:
        findings_count = len(e.findings) if e.findings else 0
        if has_findings and findings_count == 0:
            continue
        response.append(EndpointResponse(
            id=e.id,
            project_id=e.project_id,
            url=e.url,
            method=e.method,
            path=e.path,
            status_code=e.status_code,
            content_type=e.content_type,
            discovered_by=e.discovered_by,
            findings_count=findings_count,
            created_at=e.created_at,
        ))
    
    return response


@router.get("/projects/{project_id}/sitemap")
async def get_sitemap(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get sitemap tree structure for site view."""
    # Verify project ownership
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get all endpoints
    result = await db.execute(
        select(Endpoint).where(Endpoint.project_id == project_id)
    )
    endpoints = result.scalars().all()
    
    # Get all findings
    result = await db.execute(
        select(Finding).where(Finding.project_id == project_id)
    )
    findings = result.scalars().all()
    
    # Build findings map by endpoint
    endpoint_findings = defaultdict(list)
    for f in findings:
        if f.endpoint_id:
            endpoint_findings[f.endpoint_id].append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "type": f.vulnerability_type.value,
            })
    
    # Build tree structure
    def build_tree(endpoints_list):
        tree = {"path": "/", "children": {}, "findings": [], "endpoints": []}
        
        for endpoint in endpoints_list:
            parts = endpoint.path.strip("/").split("/") if endpoint.path else []
            current = tree
            
            for part in parts:
                if part not in current["children"]:
                    current["children"][part] = {
                        "path": part,
                        "children": {},
                        "findings": [],
                        "endpoints": [],
                    }
                current = current["children"][part]
            
            # Add endpoint info
            current["endpoints"].append({
                "id": endpoint.id,
                "method": endpoint.method,
                "url": endpoint.url,
                "status_code": endpoint.status_code,
            })
            
            # Add findings
            if endpoint.id in endpoint_findings:
                current["findings"].extend(endpoint_findings[endpoint.id])
        
        return tree
    
    sitemap = build_tree(endpoints)
    
    return {
        "project_id": project_id,
        "target_url": project.target_url,
        "sitemap": sitemap,
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
    }


@router.get("/endpoints/{endpoint_id}/history", response_model=List[HTTPHistoryResponse])
async def get_endpoint_history(
    endpoint_id: int,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get HTTP history for a specific endpoint."""
    # Get endpoint and verify project ownership
    result = await db.execute(
        select(Endpoint).where(Endpoint.id == endpoint_id)
    )
    endpoint = result.scalar_one_or_none()
    
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    result = await db.execute(
        select(Project)
        .where(Project.id == endpoint.project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    # Get history
    result = await db.execute(
        select(HTTPHistory)
        .where(HTTPHistory.endpoint_id == endpoint_id)
        .order_by(HTTPHistory.request_timestamp.desc())
        .limit(limit)
    )
    
    return result.scalars().all()


@router.get("/endpoints/{endpoint_id}/findings")
async def get_endpoint_findings(
    endpoint_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get findings for a specific endpoint."""
    # Get endpoint and verify project ownership
    result = await db.execute(
        select(Endpoint).where(Endpoint.id == endpoint_id)
    )
    endpoint = result.scalar_one_or_none()
    
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    result = await db.execute(
        select(Project)
        .where(Project.id == endpoint.project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.endpoint_id == endpoint_id)
    )
    findings = result.scalars().all()
    
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "vulnerability_type": f.vulnerability_type.value,
            "verified": f.verified,
        }
        for f in findings
    ]
