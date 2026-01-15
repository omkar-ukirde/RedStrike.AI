"""
RedStrike.AI - WebSocket API for Real-time Updates
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Set
import json
import logging

from app.core.database import get_db
from app.core.security import decode_token
from app.models import Project

router = APIRouter(tags=["WebSocket"])
logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections per project."""
    
    def __init__(self):
        # project_id -> set of websockets
        self.active_connections: Dict[int, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, project_id: int):
        """Accept and register a new connection."""
        await websocket.accept()
        
        if project_id not in self.active_connections:
            self.active_connections[project_id] = set()
        
        self.active_connections[project_id].add(websocket)
        logger.info(f"Client connected to project {project_id}")
    
    def disconnect(self, websocket: WebSocket, project_id: int):
        """Remove a connection."""
        if project_id in self.active_connections:
            self.active_connections[project_id].discard(websocket)
            if not self.active_connections[project_id]:
                del self.active_connections[project_id]
        logger.info(f"Client disconnected from project {project_id}")
    
    async def send_to_project(self, project_id: int, message: dict):
        """Send message to all clients watching a project."""
        if project_id in self.active_connections:
            dead_connections = set()
            
            for websocket in self.active_connections[project_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send message: {e}")
                    dead_connections.add(websocket)
            
            # Clean up dead connections
            for ws in dead_connections:
                self.active_connections[project_id].discard(ws)
    
    async def broadcast_scan_update(
        self,
        project_id: int,
        phase: str,
        status: str,
        message: str,
        data: dict = None,
    ):
        """Broadcast scan progress update."""
        await self.send_to_project(project_id, {
            "type": "scan_update",
            "phase": phase,
            "status": status,
            "message": message,
            "data": data or {},
        })
    
    async def broadcast_finding(self, project_id: int, finding: dict):
        """Broadcast new finding."""
        await self.send_to_project(project_id, {
            "type": "new_finding",
            "finding": finding,
        })
    
    async def broadcast_endpoint(self, project_id: int, endpoint: dict):
        """Broadcast new endpoint discovered."""
        await self.send_to_project(project_id, {
            "type": "new_endpoint",
            "endpoint": endpoint,
        })
    
    async def broadcast_scan_complete(self, project_id: int, summary: dict):
        """Broadcast scan completion."""
        await self.send_to_project(project_id, {
            "type": "scan_complete",
            "summary": summary,
        })


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws/projects/{project_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    project_id: int,
):
    """WebSocket endpoint for real-time project updates."""
    
    # Authenticate via query param token
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Authentication required")
        return
    
    try:
        payload = decode_token(token)
        user_id = int(payload.get("sub"))
    except Exception as e:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    # Connect
    await manager.connect(websocket, project_id)
    
    try:
        while True:
            # Keep connection alive, handle any client messages
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle client commands
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                
            except json.JSONDecodeError:
                pass
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, project_id)


# Export manager for use in other modules
def get_connection_manager() -> ConnectionManager:
    return manager
