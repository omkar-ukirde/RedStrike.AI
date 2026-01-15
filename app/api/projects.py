"""
RedStrike.AI - Projects API
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.core.database import get_db
from app.core.security import get_current_user
from app.models import Project, ProjectStatus, Scan, ScanStatus
from app.agents import OrchestratorAgent
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/projects", tags=["Projects"])


# Pydantic Schemas
class ProjectCreate(BaseModel):
    name: str
    prompt: str
    model_name: Optional[str] = None


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    model_name: Optional[str] = None


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    target_url: Optional[str]
    prompt: str
    status: ProjectStatus
    model_name: str
    scope_config: Dict[str, Any]
    auth_config: Dict[str, Any]
    rate_limit_config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class ProjectListResponse(BaseModel):
    id: int
    name: str
    target_url: Optional[str]
    status: ProjectStatus
    created_at: datetime
    findings_count: Optional[int] = 0
    
    class Config:
        from_attributes = True


# Endpoints
@router.post("/", response_model=ProjectResponse)
async def create_project(
    project_data: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new pentesting project from a natural language prompt."""
    # Parse the prompt using orchestrator
    orchestrator = OrchestratorAgent(model_name=project_data.model_name)
    config = orchestrator.parse_prompt(project_data.prompt)
    
    # Create project
    project = Project(
        name=project_data.name,
        prompt=project_data.prompt,
        target_url=config.get("target_url", ""),
        scope_config=config.get("scope", {}),
        auth_config=config.get("auth", {}),
        rate_limit_config=config.get("rate_limit", {}),
        model_name=project_data.model_name or "ollama/llama3.2",
        owner_id=current_user["user_id"],
        status=ProjectStatus.PENDING,
    )
    
    db.add(project)
    await db.commit()
    await db.refresh(project)
    
    return project


@router.get("/", response_model=List[ProjectListResponse])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """List all projects for the current user."""
    result = await db.execute(
        select(Project)
        .where(Project.owner_id == current_user["user_id"])
        .order_by(Project.created_at.desc())
    )
    projects = result.scalars().all()
    
    # Add findings count
    response = []
    for p in projects:
        response.append(ProjectListResponse(
            id=p.id,
            name=p.name,
            target_url=p.target_url,
            status=p.status,
            created_at=p.created_at,
            findings_count=len(p.findings) if p.findings else 0,
        ))
    
    return response


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get project details."""
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    update_data: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update project details."""
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if update_data.name:
        project.name = update_data.name
    if update_data.description:
        project.description = update_data.description
    if update_data.model_name:
        project.model_name = update_data.model_name
    
    await db.commit()
    await db.refresh(project)
    
    return project


@router.post("/{project_id}/start")
async def start_project(
    project_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Start or resume a project scan."""
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if project.status == ProjectStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project is already running",
        )
    
    # Update status
    project.status = ProjectStatus.RUNNING
    project.started_at = datetime.utcnow()
    await db.commit()
    
    # Start scan in background
    scan_service = ScanService(db)
    background_tasks.add_task(scan_service.run_scan, project_id)
    
    return {"message": "Scan started", "project_id": project_id}


@router.post("/{project_id}/pause")
async def pause_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Pause a running project scan."""
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if project.status != ProjectStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project is not running",
        )
    
    project.status = ProjectStatus.PAUSED
    await db.commit()
    
    return {"message": "Scan paused", "project_id": project_id}


@router.delete("/{project_id}")
async def delete_project(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete a project."""
    result = await db.execute(
        select(Project)
        .where(Project.id == project_id)
        .where(Project.owner_id == current_user["user_id"])
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if project.status == ProjectStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running project. Pause it first.",
        )
    
    await db.delete(project)
    await db.commit()
    
    return {"message": "Project deleted successfully"}
