# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - WebSocket Handler
# Real-time updates for mission events
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
from typing import Any, Dict, List, Set
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState


websocket_router = APIRouter()


class ConnectionManager:
    """
    WebSocket connection manager.
    
    Manages active WebSocket connections and broadcasts events.
    """
    
    def __init__(self):
        # Map: mission_id -> set of websockets
        self._active_connections: Dict[str, Set[WebSocket]] = {}
        # All global connections
        self._global_connections: Set[WebSocket] = set()
    
    async def connect(
        self,
        websocket: WebSocket,
        mission_id: str = None
    ) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        
        if mission_id:
            if mission_id not in self._active_connections:
                self._active_connections[mission_id] = set()
            self._active_connections[mission_id].add(websocket)
        else:
            self._global_connections.add(websocket)
    
    def disconnect(
        self,
        websocket: WebSocket,
        mission_id: str = None
    ) -> None:
        """Remove a WebSocket connection."""
        if mission_id and mission_id in self._active_connections:
            self._active_connections[mission_id].discard(websocket)
            if not self._active_connections[mission_id]:
                del self._active_connections[mission_id]
        else:
            self._global_connections.discard(websocket)
    
    async def broadcast_to_mission(
        self,
        mission_id: str,
        message: Dict[str, Any]
    ) -> None:
        """Broadcast a message to all connections for a mission."""
        if mission_id not in self._active_connections:
            return
        
        disconnected = set()
        
        for websocket in self._active_connections[mission_id]:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected
        for ws in disconnected:
            self._active_connections[mission_id].discard(ws)
    
    async def broadcast_global(self, message: Dict[str, Any]) -> None:
        """Broadcast a message to all global connections."""
        disconnected = set()
        
        for websocket in self._global_connections:
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json(message)
            except Exception:
                disconnected.add(websocket)
        
        # Clean up disconnected
        for ws in disconnected:
            self._global_connections.discard(ws)
    
    def get_connection_count(self, mission_id: str = None) -> int:
        """Get the number of active connections."""
        if mission_id:
            return len(self._active_connections.get(mission_id, set()))
        return len(self._global_connections)


# Global manager instance
manager = ConnectionManager()


@websocket_router.websocket("/ws")
async def global_websocket(websocket: WebSocket):
    """
    Global WebSocket endpoint for all events.
    
    Receives all mission events.
    """
    await manager.connect(websocket)
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to RAGLOX v3.0",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        while True:
            # Keep connection alive, wait for client messages
            data = await websocket.receive_text()
            
            # Echo back or handle commands
            try:
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@websocket_router.websocket("/ws/missions/{mission_id}")
async def mission_websocket(
    websocket: WebSocket,
    mission_id: str
):
    """
    Mission-specific WebSocket endpoint.
    
    Receives events only for the specified mission.
    
    Events:
    - new_target: New target discovered
    - new_vuln: New vulnerability found
    - new_cred: New credential harvested
    - new_session: New session established
    - goal_achieved: Mission goal achieved
    - status_change: Mission status changed
    - statistics: Stats update
    """
    await manager.connect(websocket, mission_id)
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "mission_id": mission_id,
            "message": f"Connected to mission {mission_id}",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        while True:
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "mission_id": mission_id,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
                elif message.get("type") == "subscribe":
                    # Client can subscribe to specific event types
                    event_types = message.get("events", [])
                    await websocket.send_json({
                        "type": "subscribed",
                        "events": event_types,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, mission_id)


# ═══════════════════════════════════════════════════════════════
# Event Broadcasting Functions
# ═══════════════════════════════════════════════════════════════

async def broadcast_new_target(
    mission_id: str,
    target_id: str,
    ip: str,
    hostname: str = None
) -> None:
    """Broadcast new target event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_target",
        "mission_id": mission_id,
        "data": {
            "target_id": target_id,
            "ip": ip,
            "hostname": hostname
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_vuln(
    mission_id: str,
    vuln_id: str,
    target_id: str,
    severity: str,
    vuln_type: str
) -> None:
    """Broadcast new vulnerability event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_vuln",
        "mission_id": mission_id,
        "data": {
            "vuln_id": vuln_id,
            "target_id": target_id,
            "severity": severity,
            "type": vuln_type
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_cred(
    mission_id: str,
    cred_id: str,
    target_id: str,
    username: str,
    privilege_level: str
) -> None:
    """Broadcast new credential event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_cred",
        "mission_id": mission_id,
        "data": {
            "cred_id": cred_id,
            "target_id": target_id,
            "username": username,
            "privilege_level": privilege_level
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_new_session(
    mission_id: str,
    session_id: str,
    target_id: str,
    session_type: str,
    privilege: str
) -> None:
    """Broadcast new session event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "new_session",
        "mission_id": mission_id,
        "data": {
            "session_id": session_id,
            "target_id": target_id,
            "type": session_type,
            "privilege": privilege
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_goal_achieved(
    mission_id: str,
    goal: str
) -> None:
    """Broadcast goal achieved event."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "goal_achieved",
        "mission_id": mission_id,
        "data": {
            "goal": goal
        },
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Also broadcast globally
    await manager.broadcast_global({
        "type": "goal_achieved",
        "mission_id": mission_id,
        "data": {
            "goal": goal
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_status_change(
    mission_id: str,
    old_status: str,
    new_status: str
) -> None:
    """Broadcast mission status change."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "status_change",
        "mission_id": mission_id,
        "data": {
            "old_status": old_status,
            "new_status": new_status
        },
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Also broadcast globally
    await manager.broadcast_global({
        "type": "status_change",
        "mission_id": mission_id,
        "data": {
            "old_status": old_status,
            "new_status": new_status
        },
        "timestamp": datetime.utcnow().isoformat()
    })


async def broadcast_statistics(
    mission_id: str,
    stats: Dict[str, Any]
) -> None:
    """Broadcast statistics update."""
    await manager.broadcast_to_mission(mission_id, {
        "type": "statistics",
        "mission_id": mission_id,
        "data": stats,
        "timestamp": datetime.utcnow().isoformat()
    })
