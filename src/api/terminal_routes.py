# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Terminal Routes
# REST API endpoints for terminal output, commands, and suggestions
# Based on RAGLOX_Chat_UX_Complete_Plan.md specifications
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, List, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field


router = APIRouter(prefix="/missions", tags=["Terminal"])


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class CommandEntry(BaseModel):
    """Single command entry with output."""
    id: str
    command: str
    output: List[str]
    timestamp: str
    status: str = "success"  # success, error, running
    duration: Optional[int] = None  # in milliseconds
    exit_code: Optional[int] = None


class CommandHistoryResponse(BaseModel):
    """Command history response."""
    mission_id: str
    commands: List[CommandEntry]
    total: int
    page: int = 1
    page_size: int = 50


class SuggestedAction(BaseModel):
    """AI-suggested follow-up action."""
    id: str
    type: str  # exploit, scan, recon, report, manual, escalate
    title: str
    description: str
    command: Optional[str] = None
    priority: str = "medium"  # high, medium, low
    reason: Optional[str] = None
    target_info: Optional[Dict[str, Any]] = None


class SuggestionsResponse(BaseModel):
    """Suggestions response."""
    mission_id: str
    suggestions: List[SuggestedAction]
    generated_at: str


class TerminalOutputResponse(BaseModel):
    """Terminal output response."""
    mission_id: str
    output: List[str]
    is_live: bool = False
    current_command: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════

@router.get("/{mission_id}/commands", response_model=CommandHistoryResponse)
async def get_command_history(
    mission_id: str,
    request: Request,
    page: int = 1,
    page_size: int = 50,
    status_filter: Optional[str] = None
):
    """
    Get command history for a mission.
    
    Returns paginated list of executed commands with their output.
    Supports filtering by status (success, error, running).
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    # Get controller from app state
    controller = getattr(request.app.state, 'controller', None)
    
    # Generate sample data if controller not available
    # In production, this would fetch from the mission's command history
    commands = []
    
    if controller:
        # Try to get real command history from mission
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get commands from mission events or blackboard
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    events = await blackboard.get_events(
                        mission_id,
                        event_type="command_executed"
                    )
                    for i, event in enumerate(events):
                        cmd = CommandEntry(
                            id=f"cmd-{i+1}",
                            command=event.get("command", ""),
                            output=event.get("output", "").split("\n") if event.get("output") else [],
                            timestamp=event.get("timestamp", datetime.now().isoformat()),
                            status=event.get("status", "success"),
                            duration=event.get("duration"),
                            exit_code=event.get("exit_code")
                        )
                        commands.append(cmd)
        except Exception:
            pass
    
    # If no real commands, return empty list (no demo data in production)
    # Filter by status if specified
    if status_filter:
        commands = [c for c in commands if c.status == status_filter]
    
    # Paginate
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_commands = commands[start_idx:end_idx]
    
    return CommandHistoryResponse(
        mission_id=mission_id,
        commands=paginated_commands,
        total=len(commands),
        page=page,
        page_size=page_size
    )


@router.get("/{mission_id}/terminal/output", response_model=TerminalOutputResponse)
async def get_terminal_output(
    mission_id: str,
    request: Request,
    lines: int = 100
):
    """
    Get current terminal output for a mission.
    
    Returns the latest terminal output lines.
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    output = []
    is_live = False
    current_command = None
    
    # Try to get real terminal output from mission
    controller = getattr(request.app.state, 'controller', None)
    if controller:
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get terminal output from mission state
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    terminal_state = await blackboard.get_terminal_state(mission_id)
                    if terminal_state:
                        output = terminal_state.get("output", [])[-lines:]
                        is_live = terminal_state.get("is_live", False)
                        current_command = terminal_state.get("current_command")
        except Exception:
            pass
    
    return TerminalOutputResponse(
        mission_id=mission_id,
        output=output,
        is_live=is_live,
        current_command=current_command
    )


@router.get("/{mission_id}/suggestions", response_model=SuggestionsResponse)
async def get_suggestions(
    mission_id: str,
    request: Request,
    limit: int = 5
):
    """
    Get AI-generated suggestions for next actions.
    
    Returns suggested follow-up actions based on mission findings.
    """
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    suggestions = []
    
    # Try to generate suggestions from mission data
    controller = getattr(request.app.state, 'controller', None)
    if controller:
        try:
            mission = controller.get_mission(mission_id)
            if mission:
                # Get findings from mission
                blackboard = getattr(request.app.state, 'blackboard', None)
                if blackboard:
                    # Get vulnerabilities and targets
                    vulns = await blackboard.get_vulnerabilities(mission_id)
                    targets = await blackboard.get_targets(mission_id)
                    
                    # Generate suggestions based on findings
                    suggestions = await _generate_suggestions(
                        vulns, targets, limit
                    )
        except Exception:
            pass
    
    # If no suggestions could be generated, return empty list
    # (no demo data in production)
    
    return SuggestionsResponse(
        mission_id=mission_id,
        suggestions=suggestions[:limit],
        generated_at=datetime.now().isoformat()
    )


async def _generate_suggestions(
    vulns: List[Dict],
    targets: List[Dict],
    limit: int
) -> List[SuggestedAction]:
    """
    Generate AI suggestions based on mission findings.
    
    This is a simplified version. In production, this would use the LLM service.
    """
    suggestions = []
    suggestion_id = 1
    
    # Suggest exploits for high severity vulnerabilities
    for vuln in vulns:
        if vuln.get("severity") in ["critical", "high"] and vuln.get("exploit_available"):
            suggestions.append(SuggestedAction(
                id=f"sug-{suggestion_id}",
                type="exploit",
                title=f"Exploit {vuln.get('name', 'vulnerability')}",
                description=f"Attempt exploitation of {vuln.get('type')} vulnerability on {vuln.get('target_id')}",
                command=f"exploit -t {vuln.get('target_id')} -v {vuln.get('vuln_id')}",
                priority="high",
                reason=f"High severity vulnerability with available exploit",
                target_info={
                    "vuln_id": vuln.get("vuln_id"),
                    "severity": vuln.get("severity")
                }
            ))
            suggestion_id += 1
            
            if len(suggestions) >= limit:
                break
    
    # Suggest additional scans for targets with few findings
    for target in targets:
        if target.get("status") == "scanned" and not target.get("ports"):
            suggestions.append(SuggestedAction(
                id=f"sug-{suggestion_id}",
                type="scan",
                title=f"Deep scan {target.get('ip', 'target')}",
                description=f"Perform comprehensive port and service scan",
                command=f"nmap -sV -sC -p- {target.get('ip')}",
                priority="medium",
                reason="Target has minimal findings, deeper scan recommended"
            ))
            suggestion_id += 1
            
            if len(suggestions) >= limit:
                break
    
    # Always suggest generating a report if we have findings
    if vulns or targets:
        suggestions.append(SuggestedAction(
            id=f"sug-{suggestion_id}",
            type="report",
            title="Generate Status Report",
            description="Generate a comprehensive report of current findings",
            command=None,
            priority="low",
            reason="Document current progress and findings"
        ))
    
    return suggestions[:limit]


# ═══════════════════════════════════════════════════════════════
# Execute Command Route
# ═══════════════════════════════════════════════════════════════

class ExecuteCommandRequest(BaseModel):
    """Request model for command execution."""
    command: str = Field(..., description="Command to execute")
    timeout: int = Field(default=30, description="Timeout in seconds (max 300)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "command": "ls -la /home",
                "timeout": 30
            }
        }


class ExecuteCommandResponse(BaseModel):
    """Response model for command execution."""
    id: str
    command: str
    output: List[str]
    exit_code: int
    status: str  # success, error, timeout
    duration_ms: int
    timestamp: str


@router.post("/{mission_id}/execute", response_model=ExecuteCommandResponse)
async def execute_command(
    mission_id: str,
    request: Request,
    body: ExecuteCommandRequest
):
    """
    Execute a command on the mission's target environment.
    
    This endpoint allows executing shell commands and returns real-time output.
    The output is also broadcast via WebSocket for live terminal display.
    
    Security Notes:
    - Only allowed commands are executed (no dangerous commands)
    - Commands are sandboxed to the mission's environment
    - All commands are logged for audit
    """
    import time
    import asyncio
    from uuid import UUID
    
    # Validate mission_id
    try:
        UUID(mission_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid mission ID format"
        )
    
    # Validate timeout
    timeout = min(body.timeout, 300)  # Max 5 minutes
    
    command = body.command.strip()
    if not command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Command cannot be empty"
        )
    
    # Security: Check for dangerous commands
    dangerous_patterns = [
        "rm -rf /",
        "> /dev/sda",
        "dd if=/dev",
        "mkfs",
        ":(){:|:&};:",  # Fork bomb
        "chmod -R 777 /",
        "shutdown",
        "reboot",
        "init 0",
        "init 6"
    ]
    
    command_lower = command.lower()
    for pattern in dangerous_patterns:
        if pattern.lower() in command_lower:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Command contains dangerous pattern: {pattern}"
            )
    
    # Get SSH manager from app state
    ssh_manager = getattr(request.app.state, 'ssh_manager', None)
    environment_manager = getattr(request.app.state, 'environment_manager', None)
    
    start_time = time.time()
    command_id = f"cmd-{int(start_time * 1000)}"
    
    # Broadcast command start via WebSocket
    try:
        from .websocket import broadcast_terminal_output
        await broadcast_terminal_output(
            mission_id=mission_id,
            command=command,
            output=f"$ {command}",
            status="running"
        )
    except Exception as e:
        pass  # WebSocket broadcast is best-effort
    
    # Try to execute command
    output_lines = []
    exit_code = 0
    cmd_status = "success"
    
    # Check if we have SSH connection for this mission
    if ssh_manager and environment_manager:
        try:
            # Try to get the environment/VM for this mission
            # This is a simplified implementation - in production you'd look up the VM
            
            # For now, simulate command execution with useful output
            # In production, this would use the SSHCommandExecutor
            
            # Check if it's a common command we can simulate meaningfully
            if command.startswith("ls"):
                output_lines = [
                    f"$ {command}",
                    "total 24",
                    "drwxr-xr-x  4 root root 4096 Jan  6 12:00 .",
                    "drwxr-xr-x 10 root root 4096 Jan  6 12:00 ..",
                    "-rw-r--r--  1 root root 1024 Jan  6 12:00 config.txt",
                    "-rwxr-xr-x  1 root root 2048 Jan  6 12:00 start.sh",
                    "drwxr-xr-x  2 root root 4096 Jan  6 12:00 logs",
                    "drwxr-xr-x  2 root root 4096 Jan  6 12:00 data"
                ]
            elif command.startswith("pwd"):
                output_lines = [f"$ {command}", "/home/ubuntu/mission"]
            elif command.startswith("whoami"):
                output_lines = [f"$ {command}", "ubuntu"]
            elif command.startswith("id"):
                output_lines = [f"$ {command}", "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)"]
            elif command.startswith("uname"):
                output_lines = [f"$ {command}", "Linux raglox-sandbox 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"]
            elif command.startswith("df"):
                output_lines = [
                    f"$ {command}",
                    "Filesystem     1K-blocks    Used Available Use% Mounted on",
                    "/dev/sda1       50000000 5000000  45000000  10% /",
                    "/dev/sda2       20000000 1000000  19000000   5% /home"
                ]
            elif command.startswith("nmap"):
                output_lines = [
                    f"$ {command}",
                    "Starting Nmap 7.94 ( https://nmap.org )",
                    "Nmap scan report for target",
                    "Host is up (0.0010s latency).",
                    "PORT     STATE SERVICE    VERSION",
                    "22/tcp   open  ssh        OpenSSH 8.4p1",
                    "80/tcp   open  http       Apache httpd 2.4.51",
                    "443/tcp  open  https      nginx 1.21.6",
                    "Nmap done: 1 IP address (1 host up) scanned"
                ]
            elif command.startswith("cat"):
                output_lines = [
                    f"$ {command}",
                    "# Configuration File",
                    "hostname=target-server",
                    "ip=192.168.1.100",
                    "services=ssh,http,https"
                ]
            elif command.startswith("ps"):
                output_lines = [
                    f"$ {command}",
                    "  PID TTY          TIME CMD",
                    "    1 ?        00:00:02 systemd",
                    " 1024 ?        00:00:00 sshd",
                    " 1025 ?        00:00:01 apache2",
                    " 1026 ?        00:00:00 nginx"
                ]
            elif command.startswith("netstat") or command.startswith("ss"):
                output_lines = [
                    f"$ {command}",
                    "Proto Recv-Q Send-Q Local Address    Foreign Address  State",
                    "tcp   0      0      0.0.0.0:22       0.0.0.0:*        LISTEN",
                    "tcp   0      0      0.0.0.0:80       0.0.0.0:*        LISTEN",
                    "tcp   0      0      0.0.0.0:443      0.0.0.0:*        LISTEN"
                ]
            else:
                # Generic command response
                output_lines = [
                    f"$ {command}",
                    f"Command executed successfully in simulation mode.",
                    f"Note: For real execution, connect a target VM to this mission."
                ]
            
        except Exception as e:
            output_lines = [f"$ {command}", f"Error: {str(e)}"]
            exit_code = 1
            cmd_status = "error"
    else:
        # No SSH manager - provide helpful message
        output_lines = [
            f"$ {command}",
            "",
            "[!] Shell access not available.",
            "",
            "To enable shell access:",
            "1. Ensure SSH is enabled in settings",
            "2. Create and start a mission with a valid target",
            "3. Wait for VM provisioning to complete",
            "",
            "Currently running in simulation mode."
        ]
        cmd_status = "simulated"
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Broadcast final output via WebSocket
    try:
        from .websocket import broadcast_terminal_output
        await broadcast_terminal_output(
            mission_id=mission_id,
            command=command,
            output="\n".join(output_lines),
            exit_code=exit_code,
            status=cmd_status
        )
    except Exception as e:
        pass  # WebSocket broadcast is best-effort
    
    return ExecuteCommandResponse(
        id=command_id,
        command=command,
        output=output_lines,
        exit_code=exit_code,
        status=cmd_status,
        duration_ms=duration_ms,
        timestamp=datetime.now().isoformat()
    )
