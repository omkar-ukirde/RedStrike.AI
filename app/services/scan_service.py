"""
RedStrike.AI - Scan Service
Manages scan execution and agent orchestration using LangGraph.
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any, TYPE_CHECKING
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Project, Scan, Finding, Endpoint, ProjectStatus, ScanStatus, AgentType, Severity, VulnerabilityType, DiscoveryMethod
from app.api.websocket import get_connection_manager

logger = logging.getLogger(__name__)

# Progress tracking for scans
_scan_progress: Dict[int, Dict[str, Any]] = {}


def get_scan_progress(project_id: int) -> Dict[str, Any]:
    """Get current scan progress for a project."""
    return _scan_progress.get(project_id, {
        "phase": "pending",
        "phase_index": 0,
        "total_phases": 0,
        "status": "pending",
        "message": "Scan not started",
        "started_at": None,
        "progress_percent": 0,
    })


def update_scan_progress(project_id: int, phase: str, phase_index: int, 
                         total_phases: int, status: str, message: str):
    """Update scan progress for real-time tracking."""
    progress_percent = int((phase_index / total_phases) * 100) if total_phases > 0 else 0
    _scan_progress[project_id] = {
        "phase": phase,
        "phase_index": phase_index,
        "total_phases": total_phases,
        "status": status,
        "message": message,
        "started_at": _scan_progress.get(project_id, {}).get("started_at", datetime.utcnow().isoformat()),
        "progress_percent": progress_percent,
        "updated_at": datetime.utcnow().isoformat(),
    }


def clear_scan_progress(project_id: int):
    """Clear scan progress after completion."""
    if project_id in _scan_progress:
        del _scan_progress[project_id]


class ScanService:
    """Service for managing scan execution with LangGraph agents."""
    
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
            
            # Initialize progress
            update_scan_progress(project_id, "initializing", 0, 5, "running", "Initializing scan...")
            
            # Initialize orchestrator (lazy import to avoid circular import)
            from app.agents.orchestrator import OrchestratorAgent
            orchestrator = OrchestratorAgent(model_name=project.model_name)
            
            # Create attack plan
            update_scan_progress(project_id, "planning", 0, 5, "running", "Creating attack plan...")
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
            total_phases = len(plan)
            
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
                    update_scan_progress(project_id, phase["phase"], i, total_phases, "paused", "Scan paused by user")
                    await self.ws_manager.broadcast_scan_update(
                        project_id, phase["phase"], "paused", "Scan paused by user"
                    )
                    return
                
                update_scan_progress(project_id, phase["phase"], i + 1, total_phases, "running", f"Running {phase['phase']}...")
                await self.run_phase(project, phase, config)
            
            # Complete
            project.status = ProjectStatus.COMPLETED
            project.completed_at = datetime.utcnow()
            await self.db.commit()
            
            # Get summary
            findings_count = len(project.findings) if project.findings else 0
            endpoints_count = len(project.endpoints) if project.endpoints else 0
            
            update_scan_progress(project_id, "completed", total_phases, total_phases, "completed", "Scan completed successfully")
            
            await self.ws_manager.broadcast_scan_complete(project_id, {
                "findings": findings_count,
                "endpoints": endpoints_count,
                "duration": str(project.completed_at - project.started_at),
            })
            
            # Clear progress after a delay
            await asyncio.sleep(60)
            clear_scan_progress(project_id)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            project.status = ProjectStatus.FAILED
            await self.db.commit()
            update_scan_progress(project_id, "error", 0, 0, "failed", str(e))
            await self.ws_manager.broadcast_scan_update(
                project_id, "error", "failed", str(e)
            )
    
    async def run_phase(self, project: Project, phase: dict, config: dict):
        """Run a single scan phase using LangGraph subagents."""
        phase_name = phase["phase"]
        agent_type = phase.get("agent", "unknown")
        
        await self.ws_manager.broadcast_scan_update(
            project.id, phase_name, "running", f"Starting {phase_name}..."
        )
        
        # Create scan record
        scan = Scan(
            project_id=project.id,
            agent_type=self._get_agent_type(agent_type),
            agent_name=agent_type,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        self.db.add(scan)
        await self.db.commit()
        
        try:
            # Run LangGraph subagent
            result = await self.run_subagent(agent_type, project, config)
            
            if result:
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
    
    def _get_agent_type(self, agent_name: str) -> AgentType:
        """Map agent name to AgentType enum."""
        mapping = {
            "network_recon": AgentType.RECON,
            "web_recon": AgentType.RECON,
            "endpoint_discovery": AgentType.DISCOVERY,
            "param_discovery": AgentType.DISCOVERY,
            "vuln_scanner": AgentType.SCANNER,
            "injection_tester": AgentType.FUZZER,
            "auth_tester": AgentType.FUZZER,
            "config_tester": AgentType.FUZZER,
            "logic_tester": AgentType.FUZZER,
            "verifier": AgentType.VERIFIER,
        }
        return mapping.get(agent_name, AgentType.ORCHESTRATOR)
    
    async def run_subagent(self, agent_type: str, project: Project, config: dict) -> Optional[Dict[str, Any]]:
        """Run appropriate LangGraph subagent based on type."""
        from app.agents.state import ScanState
        
        # Build initial state
        state = ScanState(
            target={
                "url": project.target_url,
                "scope": config.get("scope", {}),
                "rate_limit": config.get("rate_limit", {}),
            },
            messages=[],
            current_phase=agent_type,
            phase_history=[],
            recon_results={},
            discovery_results={},
            potential_findings=[],
            verified_findings=[],
            false_positives=[],
            errors=[],
        )
        
        # Import and run appropriate subagent
        try:
            if agent_type == "network_recon":
                from app.agents.subagents.network_recon import create_network_recon_subagent
                return create_network_recon_subagent(state)
            elif agent_type == "web_recon":
                from app.agents.subagents.web_recon import create_web_recon_subagent
                return create_web_recon_subagent(state)
            elif agent_type == "endpoint_discovery":
                from app.agents.subagents.endpoint_discovery import create_endpoint_discovery_subagent
                return create_endpoint_discovery_subagent(state)
            elif agent_type == "param_discovery":
                from app.agents.subagents.param_discovery import create_param_discovery_subagent
                return create_param_discovery_subagent(state)
            elif agent_type == "vuln_scanner":
                from app.agents.subagents.vuln_scanner import create_vuln_scanner_subagent
                return create_vuln_scanner_subagent(state)
            elif agent_type == "injection_tester":
                from app.agents.subagents.injection_tester import create_injection_tester_subagent
                return create_injection_tester_subagent(state)
            elif agent_type == "auth_tester":
                from app.agents.subagents.auth_tester import create_auth_tester_subagent
                return create_auth_tester_subagent(state)
            elif agent_type == "config_tester":
                from app.agents.subagents.config_tester import create_config_tester_subagent
                return create_config_tester_subagent(state)
            elif agent_type == "logic_tester":
                from app.agents.subagents.logic_tester import create_logic_tester_subagent
                return create_logic_tester_subagent(state)
            elif agent_type == "verifier":
                from app.agents.subagents.verifier import create_verifier_subagent
                return create_verifier_subagent(state)
            else:
                logger.warning(f"Unknown agent type: {agent_type}")
                return None
        except Exception as e:
            logger.error(f"Error running subagent {agent_type}: {e}")
            return None
    
    async def process_agent_result(self, project: Project, scan: Scan, result: dict):
        """Process agent result and save findings/endpoints."""
        # Handle findings from verifier
        verified_findings = result.get("verified_findings", [])
        for finding_data in verified_findings:
            finding = Finding(
                project_id=project.id,
                scan_id=scan.id,
                title=finding_data.get("title", "Vulnerability found"),
                severity=Severity(finding_data.get("severity", "medium")),
                vulnerability_type=VulnerabilityType(finding_data.get("vulnerability_type", "other")),
                affected_url=finding_data.get("affected_url", project.target_url),
                affected_parameter=finding_data.get("affected_parameter"),
                description=finding_data.get("description", ""),
                evidence=finding_data.get("evidence", ""),
                reproduction_steps=finding_data.get("reproduction_steps", ""),
                poc_code=finding_data.get("poc_code", ""),
                owasp_category=finding_data.get("owasp_category"),
                discovered_by=scan.agent_name,
                verified=finding_data.get("verification_status") == "verified",
            )
            self.db.add(finding)
            await self.db.commit()
            await self.db.refresh(finding)
            
            await self.ws_manager.broadcast_finding(project.id, {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
            })
        
        # Handle potential findings (unverified)
        potential = result.get("potential_findings", [])
        for finding_data in potential:
            if not any(f.get("title") == finding_data.get("title") for f in verified_findings):
                finding = Finding(
                    project_id=project.id,
                    scan_id=scan.id,
                    title=finding_data.get("title", "Potential vulnerability"),
                    severity=Severity(finding_data.get("severity", "medium")),
                    vulnerability_type=VulnerabilityType(finding_data.get("vulnerability_type", "other")),
                    affected_url=finding_data.get("affected_url", project.target_url),
                    description=finding_data.get("description", ""),
                    evidence=finding_data.get("evidence", ""),
                    discovered_by=scan.agent_name,
                    verified=False,
                )
                self.db.add(finding)
        
        await self.db.commit()
