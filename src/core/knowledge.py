# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Embedded Knowledge Module
# In-memory knowledge base with RX Modules from Atomic Red Team
# ═══════════════════════════════════════════════════════════════

import json
import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple

from .config import Settings, get_settings

logger = logging.getLogger("raglox.core.knowledge")


# ═══════════════════════════════════════════════════════════════
# Data Classes for Type Safety
# ═══════════════════════════════════════════════════════════════

@dataclass
class ExecutionInfo:
    """Execution details for an RX Module."""
    platforms: List[str]
    executor_type: str
    command: str
    elevation_required: bool = False
    cleanup_command: Optional[str] = None


@dataclass
class Variable:
    """Input variable for an RX Module."""
    name: str
    description: str
    type: str
    default_value: Optional[str] = None


@dataclass
class Prerequisite:
    """Prerequisite check for an RX Module."""
    description: str
    check_command: Optional[str] = None
    install_command: Optional[str] = None


@dataclass
class RXModule:
    """
    RX Module - An executable atomic test.
    
    Based on Atomic Red Team tests, enhanced for RAGLOX.
    """
    index: int
    technique_id: str
    technique_name: str
    description: str
    execution: ExecutionInfo
    variables: List[Variable] = field(default_factory=list)
    prerequisites: List[Prerequisite] = field(default_factory=list)
    
    # Computed fields
    rx_module_id: str = ""  # e.g., rx-t1003-001
    
    def __post_init__(self):
        """Generate rx_module_id after initialization."""
        if not self.rx_module_id:
            # Generate ID: rx-{technique_id}-{index:03d}
            tech_id = self.technique_id.lower().replace(".", "-")
            self.rx_module_id = f"rx-{tech_id}-{self.index:03d}"


@dataclass
class Technique:
    """MITRE ATT&CK Technique."""
    id: str
    name: str
    description: str = ""
    tactic_ids: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    test_count: int = 0


@dataclass
class Tactic:
    """MITRE ATT&CK Tactic."""
    id: str
    name: str
    technique_ids: List[str] = field(default_factory=list)


@dataclass 
class KnowledgeStats:
    """Statistics about the knowledge base."""
    total_techniques: int = 0
    total_tactics: int = 0
    total_rx_modules: int = 0
    platforms: List[str] = field(default_factory=list)
    modules_per_platform: Dict[str, int] = field(default_factory=dict)
    modules_per_executor: Dict[str, int] = field(default_factory=dict)
    memory_size_mb: float = 0.0


# ═══════════════════════════════════════════════════════════════
# Singleton Knowledge Base
# ═══════════════════════════════════════════════════════════════

class EmbeddedKnowledge:
    """
    Embedded Knowledge Base - Singleton pattern.
    
    Loads RX Modules into memory at startup for O(1) access.
    All data is kept in optimized data structures for fast querying.
    
    Data Sources:
    - raglox_executable_modules.json: 1,761 RX Modules
    - raglox_threat_library.json: Techniques and tactics mapping
    
    Memory Usage: ~50MB
    Access Time: O(1) via HashMap
    """
    
    _instance: Optional['EmbeddedKnowledge'] = None
    _lock: Lock = Lock()
    _initialized: bool = False
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern - ensure only one instance exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, settings: Optional[Settings] = None, data_path: Optional[str] = None):
        """
        Initialize knowledge base.
        
        Args:
            settings: Application settings
            data_path: Override path to data directory
        """
        # Only initialize once
        if EmbeddedKnowledge._initialized:
            return
        
        self.settings = settings or get_settings()
        self.data_path = Path(data_path or self.settings.knowledge_data_path)
        
        # Primary indices - Main data storage
        self._rx_modules: Dict[str, RXModule] = {}  # rx_module_id -> RXModule
        self._techniques: Dict[str, Technique] = {}  # technique_id -> Technique
        self._tactics: Dict[str, Tactic] = {}  # tactic_id -> Tactic
        
        # Secondary indices - For fast queries
        self._technique_to_modules: Dict[str, List[str]] = {}  # technique_id -> [rx_module_ids]
        self._tactic_to_techniques: Dict[str, List[str]] = {}  # tactic_id -> [technique_ids]
        self._platform_to_modules: Dict[str, List[str]] = {}  # platform -> [rx_module_ids]
        self._executor_to_modules: Dict[str, List[str]] = {}  # executor_type -> [rx_module_ids]
        self._elevation_required_modules: Set[str] = set()  # rx_module_ids requiring elevation
        
        # Quick lookups from original data
        self._quick_index: Dict[str, Any] = {}
        
        # Stats
        self._stats: Optional[KnowledgeStats] = None
        
        # Mark as initialized
        EmbeddedKnowledge._initialized = True
        
        logger.info(f"EmbeddedKnowledge initialized (data_path: {self.data_path})")
    
    # ═══════════════════════════════════════════════════════════
    # Data Loading
    # ═══════════════════════════════════════════════════════════
    
    def load(self) -> bool:
        """
        Load all knowledge data into memory.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            logger.info("Loading knowledge base into memory...")
            
            # Load executable modules
            modules_loaded = self._load_executable_modules()
            
            # Load threat library (techniques, tactics)
            library_loaded = self._load_threat_library()
            
            # Build secondary indices
            self._build_secondary_indices()
            
            # Calculate stats
            self._calculate_stats()
            
            logger.info(
                f"Knowledge base loaded: "
                f"{len(self._rx_modules)} modules, "
                f"{len(self._techniques)} techniques, "
                f"{len(self._tactics)} tactics"
            )
            
            return modules_loaded or library_loaded
            
        except Exception as e:
            logger.error(f"Error loading knowledge base: {e}")
            return False
    
    def _load_executable_modules(self) -> bool:
        """Load RX Modules from raglox_executable_modules.json."""
        modules_file = self.data_path / "raglox_executable_modules.json"
        
        if not modules_file.exists():
            logger.warning(f"Modules file not found: {modules_file}")
            return False
        
        try:
            with open(modules_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Store quick index
            self._quick_index = data.get('quick_index', {})
            
            # Parse executable tests
            tests = data.get('executable_tests', [])
            
            for test_data in tests:
                rx_module = self._parse_rx_module(test_data)
                if rx_module:
                    self._rx_modules[rx_module.rx_module_id] = rx_module
                    
                    # Build technique_to_modules index
                    tech_id = rx_module.technique_id
                    if tech_id not in self._technique_to_modules:
                        self._technique_to_modules[tech_id] = []
                    self._technique_to_modules[tech_id].append(rx_module.rx_module_id)
            
            logger.info(f"Loaded {len(self._rx_modules)} RX modules")
            return True
            
        except Exception as e:
            logger.error(f"Error loading modules: {e}")
            return False
    
    def _parse_rx_module(self, data: Dict[str, Any]) -> Optional[RXModule]:
        """Parse a single RX Module from JSON data."""
        try:
            execution_data = data.get('execution', {})
            execution = ExecutionInfo(
                platforms=execution_data.get('platforms', []),
                executor_type=execution_data.get('executor_type', 'unknown'),
                command=execution_data.get('command', ''),
                elevation_required=execution_data.get('elevation_required', False),
                cleanup_command=execution_data.get('cleanup_command')
            )
            
            variables = [
                Variable(
                    name=v.get('name', ''),
                    description=v.get('description', ''),
                    type=v.get('type', 'string'),
                    default_value=v.get('default_value')
                )
                for v in data.get('variables', [])
            ]
            
            prerequisites = [
                Prerequisite(
                    description=p.get('description', ''),
                    check_command=p.get('check_command'),
                    install_command=p.get('install_command')
                )
                for p in data.get('prerequisites', [])
            ]
            
            return RXModule(
                index=data.get('index', 0),
                technique_id=data.get('technique_id', ''),
                technique_name=data.get('technique_name', ''),
                description=data.get('description', ''),
                execution=execution,
                variables=variables,
                prerequisites=prerequisites
            )
            
        except Exception as e:
            logger.warning(f"Error parsing RX module: {e}")
            return None
    
    def _load_threat_library(self) -> bool:
        """Load threat library (techniques, tactics) from raglox_threat_library.json."""
        library_file = self.data_path / "raglox_threat_library.json"
        
        if not library_file.exists():
            logger.warning(f"Threat library not found: {library_file}")
            return False
        
        try:
            with open(library_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Parse tactics
            for tactic_id, tactic_data in data.get('tactics', {}).items():
                self._tactics[tactic_id] = Tactic(
                    id=tactic_id,
                    name=tactic_data.get('name', ''),
                    technique_ids=tactic_data.get('techniques', [])
                )
                self._tactic_to_techniques[tactic_id] = tactic_data.get('techniques', [])
            
            # Parse techniques
            for tech_id, tech_data in data.get('techniques', {}).items():
                tests = tech_data.get('tests', [])
                platforms = set()
                for test in tests:
                    platforms.update(test.get('platforms', []))
                
                self._techniques[tech_id] = Technique(
                    id=tech_id,
                    name=tech_data.get('name', ''),
                    description=tech_data.get('description', ''),
                    platforms=list(platforms),
                    test_count=len(tests)
                )
            
            logger.info(
                f"Loaded threat library: "
                f"{len(self._tactics)} tactics, "
                f"{len(self._techniques)} techniques"
            )
            return True
            
        except Exception as e:
            logger.error(f"Error loading threat library: {e}")
            return False
    
    def _build_secondary_indices(self) -> None:
        """Build secondary indices for fast queries."""
        # Platform index
        for rx_id, rx_module in self._rx_modules.items():
            for platform in rx_module.execution.platforms:
                platform_lower = platform.lower()
                if platform_lower not in self._platform_to_modules:
                    self._platform_to_modules[platform_lower] = []
                self._platform_to_modules[platform_lower].append(rx_id)
            
            # Executor type index
            executor = rx_module.execution.executor_type
            if executor not in self._executor_to_modules:
                self._executor_to_modules[executor] = []
            self._executor_to_modules[executor].append(rx_id)
            
            # Elevation required index
            if rx_module.execution.elevation_required:
                self._elevation_required_modules.add(rx_id)
    
    def _calculate_stats(self) -> None:
        """Calculate knowledge base statistics."""
        modules_per_platform = {
            platform: len(modules) 
            for platform, modules in self._platform_to_modules.items()
        }
        
        modules_per_executor = {
            executor: len(modules)
            for executor, modules in self._executor_to_modules.items()
        }
        
        # Estimate memory size (rough approximation)
        import sys
        memory_bytes = sys.getsizeof(self._rx_modules) + sys.getsizeof(self._techniques)
        memory_mb = memory_bytes / (1024 * 1024)
        
        self._stats = KnowledgeStats(
            total_techniques=len(self._techniques),
            total_tactics=len(self._tactics),
            total_rx_modules=len(self._rx_modules),
            platforms=list(self._platform_to_modules.keys()),
            modules_per_platform=modules_per_platform,
            modules_per_executor=modules_per_executor,
            memory_size_mb=memory_mb
        )
    
    # ═══════════════════════════════════════════════════════════
    # Query Methods
    # ═══════════════════════════════════════════════════════════
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Get technique by ID.
        
        Args:
            technique_id: Technique ID (e.g., 'T1003')
            
        Returns:
            Technique data dict or None
        """
        technique = self._techniques.get(technique_id)
        if not technique:
            return None
        
        return {
            'id': technique.id,
            'name': technique.name,
            'description': technique.description,
            'platforms': technique.platforms,
            'test_count': technique.test_count
        }
    
    def get_module(self, module_id: str) -> Optional[Dict[str, Any]]:
        """
        Get RX Module by ID.
        
        Args:
            module_id: RX Module ID (e.g., 'rx-t1003-001')
            
        Returns:
            Module data dict or None
        """
        module = self._rx_modules.get(module_id)
        if not module:
            return None
        
        return self._module_to_dict(module)
    
    def _module_to_dict(self, module: RXModule) -> Dict[str, Any]:
        """Convert RXModule to dictionary."""
        return {
            'rx_module_id': module.rx_module_id,
            'index': module.index,
            'technique_id': module.technique_id,
            'technique_name': module.technique_name,
            'description': module.description,
            'execution': {
                'platforms': module.execution.platforms,
                'executor_type': module.execution.executor_type,
                'command': module.execution.command,
                'elevation_required': module.execution.elevation_required,
                'cleanup_command': module.execution.cleanup_command
            },
            'variables': [
                {
                    'name': v.name,
                    'description': v.description,
                    'type': v.type,
                    'default_value': v.default_value
                }
                for v in module.variables
            ],
            'prerequisites': [
                {
                    'description': p.description,
                    'check_command': p.check_command,
                    'install_command': p.install_command
                }
                for p in module.prerequisites
            ]
        }
    
    def get_modules_for_technique(
        self, 
        technique_id: str, 
        platform: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all modules for a technique, optionally filtered by platform.
        
        Args:
            technique_id: Technique ID
            platform: Optional platform filter
            
        Returns:
            List of module dicts
        """
        module_ids = self._technique_to_modules.get(technique_id, [])
        
        modules = []
        for mid in module_ids:
            module = self._rx_modules.get(mid)
            if not module:
                continue
            
            # Filter by platform if specified
            if platform:
                platform_lower = platform.lower()
                if platform_lower not in [p.lower() for p in module.execution.platforms]:
                    continue
            
            modules.append(self._module_to_dict(module))
        
        return modules
    
    def get_techniques_for_tactic(self, tactic_id: str) -> List[Dict[str, Any]]:
        """
        Get all techniques for a tactic.
        
        Args:
            tactic_id: Tactic ID (e.g., 'TA0001')
            
        Returns:
            List of technique dicts
        """
        technique_ids = self._tactic_to_techniques.get(tactic_id, [])
        
        return [
            self.get_technique(tid)
            for tid in technique_ids
            if self.get_technique(tid)
        ]
    
    def get_modules_for_platform(
        self, 
        platform: str,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all modules for a platform.
        
        Args:
            platform: Platform name (e.g., 'windows', 'linux')
            limit: Optional limit on results
            
        Returns:
            List of module dicts
        """
        platform_lower = platform.lower()
        module_ids = self._platform_to_modules.get(platform_lower, [])
        
        if limit:
            module_ids = module_ids[:limit]
        
        return [
            self._module_to_dict(self._rx_modules[mid])
            for mid in module_ids
            if mid in self._rx_modules
        ]
    
    def get_module_for_task(
        self,
        tactic: Optional[str] = None,
        technique: Optional[str] = None,
        platform: Optional[str] = None,
        executor_type: Optional[str] = None,
        require_elevation: Optional[bool] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get the best matching module for a task.
        
        Uses scoring to select the most appropriate module based on criteria.
        
        Args:
            tactic: Tactic ID or name
            technique: Technique ID
            platform: Target platform
            executor_type: Preferred executor type
            require_elevation: Whether elevation is required
            
        Returns:
            Best matching module or None
        """
        candidates = []
        
        # Start with technique modules if specified
        if technique:
            module_ids = self._technique_to_modules.get(technique, [])
        else:
            # Get all modules
            module_ids = list(self._rx_modules.keys())
        
        # Filter and score candidates
        for mid in module_ids:
            module = self._rx_modules.get(mid)
            if not module:
                continue
            
            score = 0
            
            # Platform match
            if platform:
                platform_lower = platform.lower()
                if platform_lower in [p.lower() for p in module.execution.platforms]:
                    score += 10
                else:
                    continue  # Skip if platform doesn't match
            
            # Executor type preference
            if executor_type and module.execution.executor_type == executor_type:
                score += 5
            
            # Elevation requirement match
            if require_elevation is not None:
                if module.execution.elevation_required == require_elevation:
                    score += 3
            
            # Prefer modules with lower index (usually simpler/more reliable)
            score -= module.index * 0.01
            
            candidates.append((score, module))
        
        if not candidates:
            return None
        
        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)
        
        return self._module_to_dict(candidates[0][1])
    
    def search_modules(
        self,
        query: str,
        platform: Optional[str] = None,
        tactic: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Search modules by keyword.
        
        Args:
            query: Search query string
            platform: Optional platform filter
            tactic: Optional tactic filter
            limit: Maximum results
            
        Returns:
            List of matching modules
        """
        query_lower = query.lower()
        results = []
        
        for module in self._rx_modules.values():
            score = 0
            
            # Check technique name
            if query_lower in module.technique_name.lower():
                score += 10
            
            # Check technique ID
            if query_lower in module.technique_id.lower():
                score += 8
            
            # Check description
            if query_lower in module.description.lower():
                score += 5
            
            # Skip if no match
            if score == 0:
                continue
            
            # Platform filter
            if platform:
                platform_lower = platform.lower()
                if platform_lower not in [p.lower() for p in module.execution.platforms]:
                    continue
            
            results.append((score, module))
        
        # Sort by score and limit
        results.sort(key=lambda x: x[0], reverse=True)
        
        return [
            self._module_to_dict(m)
            for _, m in results[:limit]
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get knowledge base statistics.
        
        Returns:
            Statistics dict
        """
        if not self._stats:
            self._calculate_stats()
        
        return {
            'total_techniques': self._stats.total_techniques,
            'total_tactics': self._stats.total_tactics,
            'total_rx_modules': self._stats.total_rx_modules,
            'platforms': self._stats.platforms,
            'modules_per_platform': self._stats.modules_per_platform,
            'modules_per_executor': self._stats.modules_per_executor,
            'memory_size_mb': self._stats.memory_size_mb,
            'loaded': len(self._rx_modules) > 0
        }
    
    def list_techniques(
        self,
        platform: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List techniques with pagination.
        
        Args:
            platform: Optional platform filter
            limit: Page size
            offset: Page offset
            
        Returns:
            Tuple of (techniques list, total count)
        """
        techniques = list(self._techniques.values())
        
        # Filter by platform if specified
        if platform:
            platform_lower = platform.lower()
            techniques = [
                t for t in techniques
                if platform_lower in [p.lower() for p in t.platforms]
            ]
        
        total = len(techniques)
        
        # Paginate
        techniques = techniques[offset:offset + limit]
        
        return (
            [
                {
                    'id': t.id,
                    'name': t.name,
                    'description': t.description,
                    'platforms': t.platforms,
                    'test_count': t.test_count
                }
                for t in techniques
            ],
            total
        )
    
    def list_modules(
        self,
        technique_id: Optional[str] = None,
        platform: Optional[str] = None,
        executor_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List RX modules with filtering and pagination.
        
        Args:
            technique_id: Filter by technique
            platform: Filter by platform
            executor_type: Filter by executor type
            limit: Page size
            offset: Page offset
            
        Returns:
            Tuple of (modules list, total count)
        """
        modules = list(self._rx_modules.values())
        
        # Apply filters
        if technique_id:
            modules = [m for m in modules if m.technique_id == technique_id]
        
        if platform:
            platform_lower = platform.lower()
            modules = [
                m for m in modules
                if platform_lower in [p.lower() for p in m.execution.platforms]
            ]
        
        if executor_type:
            modules = [
                m for m in modules
                if m.execution.executor_type == executor_type
            ]
        
        total = len(modules)
        
        # Paginate
        modules = modules[offset:offset + limit]
        
        return (
            [self._module_to_dict(m) for m in modules],
            total
        )
    
    def list_tactics(self) -> List[Dict[str, Any]]:
        """
        List all tactics.
        
        Returns:
            List of tactic dicts
        """
        return [
            {
                'id': t.id,
                'name': t.name,
                'technique_count': len(t.technique_ids)
            }
            for t in self._tactics.values()
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Specialized Queries for Specialists
    # ═══════════════════════════════════════════════════════════
    
    def get_exploit_modules(
        self,
        vuln_type: Optional[str] = None,
        platform: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get modules suitable for exploitation.
        
        Args:
            vuln_type: CVE or vulnerability type
            platform: Target platform
            
        Returns:
            List of exploit modules
        """
        # Map common vulnerabilities to techniques
        vuln_technique_map = {
            'ms17-010': 'T1210',  # Exploitation of Remote Services
            'eternalblue': 'T1210',
            'cve-2019-0708': 'T1210',  # BlueKeep
            'bluekeep': 'T1210',
            'cve-2021-44228': 'T1190',  # Log4Shell - Exploit Public-Facing Application
            'log4shell': 'T1190',
            'cve-2021-34527': 'T1547',  # PrintNightmare - Boot/Logon Autostart Execution
            'printnightmare': 'T1547',
        }
        
        technique = None
        if vuln_type:
            vuln_lower = vuln_type.lower().replace('_', '-')
            technique = vuln_technique_map.get(vuln_lower)
        
        if technique:
            return self.get_modules_for_technique(technique, platform)
        
        # Search for modules related to exploitation
        return self.search_modules('exploit', platform=platform)
    
    def get_recon_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get modules suitable for reconnaissance.
        
        Args:
            platform: Target platform
            
        Returns:
            List of recon modules
        """
        # Reconnaissance related techniques
        recon_techniques = [
            'T1016',  # System Network Configuration Discovery
            'T1018',  # Remote System Discovery
            'T1033',  # System Owner/User Discovery
            'T1049',  # System Network Connections Discovery
            'T1057',  # Process Discovery
            'T1069',  # Permission Groups Discovery
            'T1082',  # System Information Discovery
            'T1083',  # File and Directory Discovery
            'T1087',  # Account Discovery
            'T1135',  # Network Share Discovery
        ]
        
        modules = []
        for tech in recon_techniques:
            modules.extend(self.get_modules_for_technique(tech, platform))
        
        return modules
    
    def get_credential_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get modules for credential harvesting.
        
        Args:
            platform: Target platform
            
        Returns:
            List of credential harvesting modules
        """
        # Credential Access techniques
        cred_techniques = [
            'T1003',  # OS Credential Dumping
            'T1003.001',  # LSASS Memory
            'T1003.002',  # Security Account Manager
            'T1003.003',  # NTDS
            'T1003.004',  # LSA Secrets
            'T1003.005',  # Cached Domain Credentials
            'T1003.006',  # DCSync
            'T1003.007',  # Proc Filesystem
            'T1003.008',  # /etc/passwd and /etc/shadow
            'T1555',  # Credentials from Password Stores
            'T1552',  # Unsecured Credentials
        ]
        
        modules = []
        for tech in cred_techniques:
            modules.extend(self.get_modules_for_technique(tech, platform))
        
        return modules
    
    def get_privesc_modules(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get modules for privilege escalation.
        
        Args:
            platform: Target platform
            
        Returns:
            List of privilege escalation modules
        """
        # Privilege Escalation techniques
        privesc_techniques = [
            'T1055',  # Process Injection
            'T1068',  # Exploitation for Privilege Escalation
            'T1134',  # Access Token Manipulation
            'T1484',  # Domain Policy Modification
            'T1548',  # Abuse Elevation Control Mechanism
            'T1574',  # Hijack Execution Flow
        ]
        
        modules = []
        for tech in privesc_techniques:
            modules.extend(self.get_modules_for_technique(tech, platform))
        
        return modules
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    def is_loaded(self) -> bool:
        """Check if knowledge base is loaded."""
        return len(self._rx_modules) > 0
    
    def reload(self) -> bool:
        """
        Reload the knowledge base.
        
        Returns:
            True if reloaded successfully
        """
        # Clear existing data
        self._rx_modules.clear()
        self._techniques.clear()
        self._tactics.clear()
        self._technique_to_modules.clear()
        self._tactic_to_techniques.clear()
        self._platform_to_modules.clear()
        self._executor_to_modules.clear()
        self._elevation_required_modules.clear()
        self._quick_index.clear()
        self._stats = None
        
        # Reload
        return self.load()
    
    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (for testing)."""
        cls._instance = None
        cls._initialized = False


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

@lru_cache(maxsize=1)
def get_knowledge() -> EmbeddedKnowledge:
    """
    Get cached knowledge base instance.
    
    Uses lru_cache to ensure knowledge is only loaded once.
    """
    knowledge = EmbeddedKnowledge()
    knowledge.load()
    return knowledge


def init_knowledge(data_path: Optional[str] = None) -> EmbeddedKnowledge:
    """
    Initialize knowledge base with custom path.
    
    Args:
        data_path: Path to data directory
        
    Returns:
        EmbeddedKnowledge instance
    """
    # Reset cache
    get_knowledge.cache_clear()
    EmbeddedKnowledge.reset()
    
    # Create with custom path
    knowledge = EmbeddedKnowledge(data_path=data_path)
    knowledge.load()
    
    return knowledge
