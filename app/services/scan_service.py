"""
RedStrike.AI - Scan Service
Manages scan execution and agent orchestration.
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional, TYPE_CHECKING
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Project, Scan, Finding, Endpoint, ProjectStatus, ScanStatus, AgentType, Severity, VulnerabilityType, DiscoveryMethod
from app.api.websocket import get_connection_manager

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing scan execution."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.ws_manager = get_connection_manager()
    
    async def run_scan(self, project_id: int):
        """Run a complete scan for a project."""
        try:
            # Get project
            result = await self.db.execute(
                select(Project).where(Project.id == project_id)
            )
            project = result.scalar_one_or_none()
            
            if not project:
                logger.error(f"Project {project_id} not found")
                return
            
            # Initialize orchestrator (lazy import to avoid circular import)
            from app.agents.orchestrator import OrchestratorAgent
            orchestrator = OrchestratorAgent(model_name=project.model_name)
            
            # Create attack plan
            await self.ws_manager.broadcast_scan_update(
                project_id, "planning", "running", "Creating attack plan..."
            )
            
            config = {
                "target_url": project.target_url,
                "scope": project.scope_config,
                "auth": project.auth_config,
                "rate_limit": project.rate_limit_config,
            }
            
            plan = await orchestrator.create_attack_plan(config)
            
            # Save plan to state
            project.state_snapshot = {"plan": plan, "current_phase": 0}
            await self.db.commit()
            
            # Execute phases
            for i, phase in enumerate(plan):
                # Check if paused
                await self.db.refresh(project)
                if project.status == ProjectStatus.PAUSED:
                    project.state_snapshot["current_phase"] = i
                    await self.db.commit()
                    await self.ws_manager.broadcast_scan_update(
                        project_id, phase["phase"], "paused", "Scan paused by user"
                    )
                    return
                
                await self.run_phase(project, phase, config)
            
            # Complete
            project.status = ProjectStatus.COMPLETED
            project.completed_at = datetime.utcnow()
            await self.db.commit()
            
            # Get summary
            findings_count = len(project.findings) if project.findings else 0
            endpoints_count = len(project.endpoints) if project.endpoints else 0
            
            await self.ws_manager.broadcast_scan_complete(project_id, {
                "findings": findings_count,
                "endpoints": endpoints_count,
                "duration": str(project.completed_at - project.started_at),
            })
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            project.status = ProjectStatus.FAILED
            await self.db.commit()
            await self.ws_manager.broadcast_scan_update(
                project_id, "error", "failed", str(e)
            )
    
    async def run_phase(self, project: Project, phase: dict, config: dict):
        """Run a single scan phase."""
        phase_name = phase["phase"]
        agent_type = phase.get("agent", "unknown")
        
        await self.ws_manager.broadcast_scan_update(
            project.id, phase_name, "running", f"Starting {phase_name}..."
        )
        
        # Create scan record
        scan = Scan(
            project_id=project.id,
            agent_type=AgentType(agent_type.lower().replace("agent", "").strip() or "orchestrator"),
            agent_name=agent_type,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        await self.db.commit()
        
        try:
            # Get appropriate agent
            agent = self.get_agent(agent_type, project.model_name)
            
            if agent:
                for task in phase.get("tasks", []):
                    await self.ws_manager.broadcast_scan_update(
                        project.id, phase_name, "running",
                        f"Executing: {task.get('tool', task.get('action', 'unknown'))}"
                    )
                    
                    result = await agent.run(str(task), context=config)
                    
                    # Process results
                    await self.process_agent_result(project, scan, result)
            
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Phase error: {e}")
            scan.status = ScanStatus.FAILED
            scan.error = str(e)
        
        await self.db.commit()
        
        await self.ws_manager.broadcast_scan_update(
            project.id, phase_name, scan.status.value, f"{phase_name} completed"
        )
    
    def get_agent(self, agent_type: str, model_name: str):
        """Get agent instance by type."""
        # Lazy imports to avoid circular import
        from app.agents.recon import ReconAgent
        from app.agents.discovery import DiscoveryAgent
        from app.agents.vuln_scanner import VulnScannerAgent
        from app.agents.fuzzer import FuzzerAgent
        from app.agents.verifier import VerifierAgent
        
        agents = {
            "ReconAgent": ReconAgent,
            "DiscoveryAgent": DiscoveryAgent,
            "VulnScannerAgent": VulnScannerAgent,
            "FuzzerAgent": FuzzerAgent,
            "VerifierAgent": VerifierAgent,
        }
        
        agent_class = agents.get(agent_type)
        if agent_class:
            return agent_class(model_name=model_name)
        return None
    
    async def process_agent_result(self, project: Project, scan: Scan, result: dict):
        """Process agent result and save findings/endpoints."""
        if not result.get("success"):
            return
        
        output = result.get("output", "")
        
        # Try to extract findings from output
        # This is a simplified version - in production, agents would return structured data
        if "vulnerable" in str(output).lower() or "finding" in str(output).lower():
            # Create a finding placeholder (agents should return structured data)
            finding = Finding(
                project_id=project.id,
                scan_id=scan.id,
                title=f"Potential vulnerability found",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.OTHER,
                affected_url=project.target_url,
                description=str(output)[:2000],
                discovered_by=scan.agent_name,
            )
            self.db.add(finding)
            await self.db.commit()
            await self.db.refresh(finding)
            
            await self.ws_manager.broadcast_finding(project.id, {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
            })
