# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Tool Manager
# Automated penetration testing tool installation and management
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("raglox.infrastructure.tools")


# ═══════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════

class ToolStatus(Enum):
    """Tool installation status."""
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    FAILED = "failed"
    OUTDATED = "outdated"


class ToolCategory(Enum):
    """Tool categories for penetration testing."""
    RECON = "recon"
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CREDENTIAL = "credential"
    LATERAL = "lateral"
    PERSISTENCE = "persistence"
    UTILITY = "utility"


@dataclass
class ToolManifest:
    """Tool installation manifest."""
    name: str
    description: str
    category: ToolCategory
    platforms: List[str]  # linux, windows, macos
    
    # Installation
    install_commands: Dict[str, List[str]]  # platform -> commands
    verify_command: str
    expected_output: Optional[str] = None
    
    # Dependencies
    dependencies: List[str] = field(default_factory=list)
    
    # Metadata
    version: Optional[str] = None
    homepage: Optional[str] = None
    
    # Resources
    min_memory_mb: int = 100
    min_disk_mb: int = 50
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "platforms": self.platforms,
            "verify_command": self.verify_command,
            "dependencies": self.dependencies,
            "version": self.version
        }


@dataclass
class ToolInstallResult:
    """Result of tool installation."""
    tool_name: str
    status: ToolStatus
    
    # Timing
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Results
    install_output: str = ""
    verify_output: str = ""
    error_message: str = ""
    
    # Verification
    version_installed: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "duration_seconds": self.duration_seconds,
            "version_installed": self.version_installed,
            "error_message": self.error_message
        }


# ═══════════════════════════════════════════════════════════════
# Tool Registry
# ═══════════════════════════════════════════════════════════════

TOOL_REGISTRY: Dict[str, ToolManifest] = {
    # ═══════════════════════════════════════════════════════════
    # Reconnaissance Tools
    # ═══════════════════════════════════════════════════════════
    
    "nmap": ToolManifest(
        name="nmap",
        description="Network exploration and security auditing tool",
        category=ToolCategory.RECON,
        platforms=["linux", "macos"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq nmap"],
            "macos": ["brew install nmap"]
        },
        verify_command="nmap --version",
        expected_output="Nmap",
        homepage="https://nmap.org"
    ),
    
    "masscan": ToolManifest(
        name="masscan",
        description="High-speed port scanner",
        category=ToolCategory.RECON,
        platforms=["linux"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq git gcc make libpcap-dev",
                "git clone https://github.com/robertdavidgraham/masscan /tmp/masscan",
                "cd /tmp/masscan && make -j",
                "cp /tmp/masscan/bin/masscan /usr/local/bin/"
            ]
        },
        verify_command="masscan --version",
        expected_output="Masscan",
        dependencies=["git", "gcc", "make"],
        min_disk_mb=100
    ),
    
    "amass": ToolManifest(
        name="amass",
        description="In-depth DNS enumeration and network mapping",
        category=ToolCategory.RECON,
        platforms=["linux"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq wget",
                "wget -qO /tmp/amass.zip https://github.com/owasp-amass/amass/releases/latest/download/amass_Linux_amd64.zip",
                "unzip -o /tmp/amass.zip -d /tmp/amass",
                "mv /tmp/amass/amass_Linux_amd64/amass /usr/local/bin/",
                "chmod +x /usr/local/bin/amass"
            ]
        },
        verify_command="amass -version",
        expected_output="OWASP Amass",
        min_memory_mb=512
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Vulnerability Scanners
    # ═══════════════════════════════════════════════════════════
    
    "nuclei": ToolManifest(
        name="nuclei",
        description="Fast vulnerability scanner with templates",
        category=ToolCategory.SCANNER,
        platforms=["linux", "macos"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq wget",
                "wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_amd64.zip",
                "unzip -o /tmp/nuclei.zip -d /tmp/",
                "mv /tmp/nuclei /usr/local/bin/",
                "chmod +x /usr/local/bin/nuclei",
                "nuclei -update-templates"
            ]
        },
        verify_command="nuclei -version",
        expected_output="nuclei",
        min_disk_mb=500  # Templates can be large
    ),
    
    "nikto": ToolManifest(
        name="nikto",
        description="Web server scanner",
        category=ToolCategory.SCANNER,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq nikto"]
        },
        verify_command="nikto -Version",
        expected_output="Nikto"
    ),
    
    "wpscan": ToolManifest(
        name="wpscan",
        description="WordPress vulnerability scanner",
        category=ToolCategory.SCANNER,
        platforms=["linux"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq ruby ruby-dev libcurl4-openssl-dev make zlib1g-dev",
                "gem install wpscan"
            ]
        },
        verify_command="wpscan --version",
        expected_output="WPScan",
        dependencies=["ruby"],
        min_memory_mb=256
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Exploitation Tools
    # ═══════════════════════════════════════════════════════════
    
    "metasploit": ToolManifest(
        name="metasploit",
        description="Penetration testing framework",
        category=ToolCategory.EXPLOIT,
        platforms=["linux"],
        install_commands={
            "linux": [
                "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall",
                "chmod 755 /tmp/msfinstall",
                "/tmp/msfinstall"
            ]
        },
        verify_command="msfconsole --version",
        expected_output="Framework",
        min_memory_mb=2048,
        min_disk_mb=2000
    ),
    
    "searchsploit": ToolManifest(
        name="searchsploit",
        description="Exploit database search tool",
        category=ToolCategory.EXPLOIT,
        platforms=["linux"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq exploitdb"
            ]
        },
        verify_command="searchsploit --version",
        expected_output="ExploitDB"
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Post-Exploitation Tools
    # ═══════════════════════════════════════════════════════════
    
    "linpeas": ToolManifest(
        name="linpeas",
        description="Linux privilege escalation scanner",
        category=ToolCategory.POST_EXPLOIT,
        platforms=["linux"],
        install_commands={
            "linux": [
                "mkdir -p /opt/privesc",
                "wget -qO /opt/privesc/linpeas.sh https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
                "chmod +x /opt/privesc/linpeas.sh"
            ]
        },
        verify_command="test -f /opt/privesc/linpeas.sh && echo 'linpeas installed'",
        expected_output="linpeas installed"
    ),
    
    "pspy": ToolManifest(
        name="pspy",
        description="Process spy without root permissions",
        category=ToolCategory.POST_EXPLOIT,
        platforms=["linux"],
        install_commands={
            "linux": [
                "mkdir -p /opt/privesc",
                "wget -qO /opt/privesc/pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
                "chmod +x /opt/privesc/pspy64"
            ]
        },
        verify_command="test -f /opt/privesc/pspy64 && echo 'pspy installed'",
        expected_output="pspy installed"
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Credential Tools
    # ═══════════════════════════════════════════════════════════
    
    "hashcat": ToolManifest(
        name="hashcat",
        description="Advanced password recovery",
        category=ToolCategory.CREDENTIAL,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq hashcat"]
        },
        verify_command="hashcat --version",
        expected_output="hashcat",
        min_memory_mb=512
    ),
    
    "john": ToolManifest(
        name="john",
        description="John the Ripper password cracker",
        category=ToolCategory.CREDENTIAL,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq john"]
        },
        verify_command="john --help | head -1",
        expected_output="John"
    ),
    
    "hydra": ToolManifest(
        name="hydra",
        description="Network login cracker",
        category=ToolCategory.CREDENTIAL,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq hydra"]
        },
        verify_command="hydra -V",
        expected_output="Hydra"
    ),
    
    "lazagne": ToolManifest(
        name="lazagne",
        description="Credentials recovery tool",
        category=ToolCategory.CREDENTIAL,
        platforms=["linux", "windows"],
        install_commands={
            "linux": [
                "pip3 install lazagne"
            ],
            "windows": [
                "pip install lazagne"
            ]
        },
        verify_command="lazagne --version || python3 -m lazagne --help",
        expected_output="LaZagne"
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Lateral Movement Tools
    # ═══════════════════════════════════════════════════════════
    
    "impacket": ToolManifest(
        name="impacket",
        description="Network protocol toolkit",
        category=ToolCategory.LATERAL,
        platforms=["linux"],
        install_commands={
            "linux": [
                "pip3 install impacket"
            ]
        },
        verify_command="python3 -c 'import impacket; print(impacket.__version__)'",
        expected_output="0."
    ),
    
    "crackmapexec": ToolManifest(
        name="crackmapexec",
        description="Swiss army knife for pentesting networks",
        category=ToolCategory.LATERAL,
        platforms=["linux"],
        install_commands={
            "linux": [
                "pip3 install crackmapexec"
            ]
        },
        verify_command="crackmapexec --version || cme --version",
        expected_output="CME"
    ),
    
    "evil-winrm": ToolManifest(
        name="evil-winrm",
        description="Windows Remote Management shell",
        category=ToolCategory.LATERAL,
        platforms=["linux"],
        install_commands={
            "linux": [
                "apt-get update -qq",
                "apt-get install -y -qq ruby ruby-dev",
                "gem install evil-winrm"
            ]
        },
        verify_command="evil-winrm --version || ruby -e 'require \"evil-winrm\"'",
        expected_output="Evil-WinRM"
    ),
    
    # ═══════════════════════════════════════════════════════════
    # Utility Tools
    # ═══════════════════════════════════════════════════════════
    
    "curl": ToolManifest(
        name="curl",
        description="Command line HTTP client",
        category=ToolCategory.UTILITY,
        platforms=["linux", "macos"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq curl"]
        },
        verify_command="curl --version",
        expected_output="curl"
    ),
    
    "jq": ToolManifest(
        name="jq",
        description="JSON processor",
        category=ToolCategory.UTILITY,
        platforms=["linux", "macos"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq jq"]
        },
        verify_command="jq --version",
        expected_output="jq"
    ),
    
    "netcat": ToolManifest(
        name="netcat",
        description="TCP/UDP networking utility",
        category=ToolCategory.UTILITY,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq netcat-openbsd"]
        },
        verify_command="nc -h 2>&1 | head -1",
        expected_output="nc"
    ),
    
    "socat": ToolManifest(
        name="socat",
        description="Multipurpose relay tool",
        category=ToolCategory.UTILITY,
        platforms=["linux"],
        install_commands={
            "linux": ["apt-get update -qq", "apt-get install -y -qq socat"]
        },
        verify_command="socat -V | head -1",
        expected_output="socat"
    ),
}


# ═══════════════════════════════════════════════════════════════
# Tool Manager
# ═══════════════════════════════════════════════════════════════

class ToolManager:
    """
    Manages penetration testing tool installation on execution environments.
    
    Features:
    - Automatic tool installation
    - Dependency resolution
    - Version verification
    - Platform-aware installation
    - Installation caching
    
    Usage:
        manager = ToolManager()
        
        # Check if tool is installed
        is_installed = await manager.is_tool_installed(env, "nmap")
        
        # Install a tool
        result = await manager.install_tool(env, "nmap")
        
        # Install multiple tools
        results = await manager.ensure_tools_installed(env, ["nmap", "nuclei", "hydra"])
    """
    
    def __init__(
        self,
        registry: Optional[Dict[str, ToolManifest]] = None,
        install_timeout: int = 300
    ):
        self.registry = registry or TOOL_REGISTRY
        self.install_timeout = install_timeout
        
        # Cache of installed tools per environment
        self._installed_cache: Dict[str, Set[str]] = {}
        
        logger.info(f"ToolManager initialized with {len(self.registry)} tools")
    
    def get_tool_manifest(self, tool_name: str) -> Optional[ToolManifest]:
        """Get tool manifest by name."""
        return self.registry.get(tool_name.lower())
    
    def list_tools(
        self,
        category: Optional[ToolCategory] = None,
        platform: Optional[str] = None
    ) -> List[ToolManifest]:
        """List available tools, optionally filtered."""
        tools = list(self.registry.values())
        
        if category:
            tools = [t for t in tools if t.category == category]
        
        if platform:
            tools = [t for t in tools if platform in t.platforms]
        
        return tools
    
    async def is_tool_installed(
        self,
        env_id: str,
        tool_name: str,
        executor: Optional[Any] = None
    ) -> bool:
        """
        Check if a tool is installed on an environment.
        
        Args:
            env_id: Environment ID
            tool_name: Tool name
            executor: Optional executor for verification
            
        Returns:
            True if installed, False otherwise
        """
        # Check cache first
        if env_id in self._installed_cache:
            if tool_name in self._installed_cache[env_id]:
                return True
        
        manifest = self.get_tool_manifest(tool_name)
        if not manifest:
            logger.warning(f"Unknown tool: {tool_name}")
            return False
        
        if executor:
            try:
                result = await executor.execute_command(
                    manifest.verify_command,
                    timeout=30
                )
                
                if result.get("success") and manifest.expected_output:
                    if manifest.expected_output in result.get("stdout", ""):
                        self._cache_installed(env_id, tool_name)
                        return True
                        
            except Exception as e:
                logger.debug(f"Tool verification failed for {tool_name}: {e}")
        
        return False
    
    async def install_tool(
        self,
        env_id: str,
        tool_name: str,
        platform: str = "linux",
        executor: Optional[Any] = None
    ) -> ToolInstallResult:
        """
        Install a tool on an environment.
        
        Args:
            env_id: Environment ID
            tool_name: Tool name
            platform: Target platform
            executor: Executor for running commands
            
        Returns:
            ToolInstallResult with installation outcome
        """
        result = ToolInstallResult(
            tool_name=tool_name,
            status=ToolStatus.INSTALLING
        )
        
        manifest = self.get_tool_manifest(tool_name)
        if not manifest:
            result.status = ToolStatus.FAILED
            result.error_message = f"Unknown tool: {tool_name}"
            return result
        
        # Check platform support
        if platform not in manifest.platforms:
            result.status = ToolStatus.FAILED
            result.error_message = f"Tool {tool_name} not supported on {platform}"
            return result
        
        # Get install commands
        install_commands = manifest.install_commands.get(platform, [])
        if not install_commands:
            result.status = ToolStatus.FAILED
            result.error_message = f"No install commands for {platform}"
            return result
        
        # Install dependencies first
        for dep in manifest.dependencies:
            dep_result = await self.install_tool(env_id, dep, platform, executor)
            if dep_result.status != ToolStatus.INSTALLED:
                result.status = ToolStatus.FAILED
                result.error_message = f"Failed to install dependency: {dep}"
                return result
        
        # Execute installation
        if executor:
            try:
                full_output = []
                
                for cmd in install_commands:
                    logger.info(f"Installing {tool_name}: {cmd[:50]}...")
                    
                    cmd_result = await executor.execute_command(
                        cmd,
                        timeout=self.install_timeout
                    )
                    
                    full_output.append(cmd_result.get("stdout", ""))
                    
                    if not cmd_result.get("success"):
                        result.status = ToolStatus.FAILED
                        result.error_message = cmd_result.get("stderr", "Unknown error")
                        result.install_output = "\n".join(full_output)
                        return result
                
                result.install_output = "\n".join(full_output)
                
                # Verify installation
                verify_result = await executor.execute_command(
                    manifest.verify_command,
                    timeout=30
                )
                
                result.verify_output = verify_result.get("stdout", "")
                
                if manifest.expected_output and manifest.expected_output in result.verify_output:
                    result.status = ToolStatus.INSTALLED
                    self._cache_installed(env_id, tool_name)
                    logger.info(f"Tool {tool_name} installed successfully")
                else:
                    result.status = ToolStatus.FAILED
                    result.error_message = "Verification failed"
                    
            except asyncio.TimeoutError:
                result.status = ToolStatus.FAILED
                result.error_message = "Installation timed out"
            except Exception as e:
                result.status = ToolStatus.FAILED
                result.error_message = str(e)
        else:
            # Simulation mode - assume success
            result.status = ToolStatus.INSTALLED
            self._cache_installed(env_id, tool_name)
        
        result.completed_at = datetime.utcnow()
        result.duration_seconds = (result.completed_at - result.started_at).total_seconds()
        
        return result
    
    async def ensure_tools_installed(
        self,
        env_id: str,
        tools: List[str],
        platform: str = "linux",
        executor: Optional[Any] = None
    ) -> Dict[str, ToolInstallResult]:
        """
        Ensure multiple tools are installed.
        
        Args:
            env_id: Environment ID
            tools: List of tool names
            platform: Target platform
            executor: Executor for running commands
            
        Returns:
            Dict mapping tool name to install result
        """
        results = {}
        
        for tool in tools:
            # Check if already installed
            if await self.is_tool_installed(env_id, tool, executor):
                results[tool] = ToolInstallResult(
                    tool_name=tool,
                    status=ToolStatus.INSTALLED
                )
            else:
                # Install tool
                results[tool] = await self.install_tool(
                    env_id, tool, platform, executor
                )
        
        # Log summary
        installed = sum(1 for r in results.values() if r.status == ToolStatus.INSTALLED)
        failed = sum(1 for r in results.values() if r.status == ToolStatus.FAILED)
        
        logger.info(
            f"Tool installation complete: {installed} installed, {failed} failed "
            f"(out of {len(tools)} requested)"
        )
        
        return results
    
    def _cache_installed(self, env_id: str, tool_name: str) -> None:
        """Cache that a tool is installed."""
        if env_id not in self._installed_cache:
            self._installed_cache[env_id] = set()
        self._installed_cache[env_id].add(tool_name)
    
    def clear_cache(self, env_id: Optional[str] = None) -> None:
        """Clear installation cache."""
        if env_id:
            self._installed_cache.pop(env_id, None)
        else:
            self._installed_cache.clear()
    
    def get_tools_for_goal(self, goal: str) -> List[str]:
        """
        Get recommended tools for a mission goal.
        
        Args:
            goal: Mission goal (e.g., "domain_admin", "data_exfil")
            
        Returns:
            List of recommended tool names
        """
        goal_tools = {
            "domain_admin": ["nmap", "impacket", "crackmapexec", "hydra"],
            "credential_harvest": ["mimikatz", "lazagne", "john", "hashcat"],
            "lateral_movement": ["impacket", "crackmapexec", "evil-winrm"],
            "data_exfil": ["curl", "netcat", "socat"],
            "persistence": ["linpeas", "pspy"],
            "web_pentest": ["nuclei", "nikto", "wpscan", "curl", "jq"],
            "recon": ["nmap", "masscan", "amass"],
        }
        
        return goal_tools.get(goal.lower().replace(" ", "_"), ["nmap", "curl"])


# ═══════════════════════════════════════════════════════════════
# Singleton Accessor
# ═══════════════════════════════════════════════════════════════

_tool_manager: Optional[ToolManager] = None


def get_tool_manager() -> ToolManager:
    """Get or create the tool manager singleton."""
    global _tool_manager
    
    if _tool_manager is None:
        _tool_manager = ToolManager()
    
    return _tool_manager
