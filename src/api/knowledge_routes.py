# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Knowledge API Routes
# REST API endpoints for knowledge base queries
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ..core.knowledge import EmbeddedKnowledge, get_knowledge


router = APIRouter(prefix="/knowledge", tags=["Knowledge"])


# ═══════════════════════════════════════════════════════════════
# Dependencies
# ═══════════════════════════════════════════════════════════════

def get_knowledge_base(request: Request) -> EmbeddedKnowledge:
    """Get the knowledge base from app state or create it."""
    if hasattr(request.app.state, 'knowledge') and request.app.state.knowledge:
        return request.app.state.knowledge
    
    # Fallback to singleton
    knowledge = get_knowledge()
    if not knowledge.is_loaded():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge base not loaded"
        )
    return knowledge


# ═══════════════════════════════════════════════════════════════
# Response Models
# ═══════════════════════════════════════════════════════════════

class TechniqueResponse(BaseModel):
    """Technique response model."""
    id: str
    name: str
    description: str = ""
    platforms: List[str] = []
    test_count: int = 0


class ModuleResponse(BaseModel):
    """RX Module response model."""
    rx_module_id: str
    index: int
    technique_id: str
    technique_name: str
    description: str = ""
    execution: Dict[str, Any] = {}
    variables: List[Dict[str, Any]] = []
    prerequisites: List[Dict[str, Any]] = []


class TacticResponse(BaseModel):
    """Tactic response model."""
    id: str
    name: str
    technique_count: int = 0


class KnowledgeStatsResponse(BaseModel):
    """Knowledge base statistics response."""
    total_techniques: int
    total_tactics: int
    total_rx_modules: int
    platforms: List[str]
    modules_per_platform: Dict[str, int]
    modules_per_executor: Dict[str, int]
    memory_size_mb: float
    loaded: bool
    # Nuclei Templates stats
    total_nuclei_templates: int = 0
    nuclei_by_severity: Dict[str, int] = {}
    nuclei_by_protocol: Dict[str, int] = {}


class PaginatedResponse(BaseModel):
    """Generic paginated response."""
    items: List[Any]
    total: int
    limit: int
    offset: int


class SearchRequest(BaseModel):
    """Search request model."""
    query: str = Field(..., min_length=1, max_length=200)
    platform: Optional[str] = None
    tactic: Optional[str] = None
    limit: int = Field(default=20, ge=1, le=100)


class TaskModuleRequest(BaseModel):
    """Request for best module for a task."""
    tactic: Optional[str] = None
    technique: Optional[str] = None
    platform: Optional[str] = None
    executor_type: Optional[str] = None
    require_elevation: Optional[bool] = None


# ═══════════════════════════════════════════════════════════════
# Statistics Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get("/stats", response_model=KnowledgeStatsResponse)
async def get_knowledge_stats(
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> KnowledgeStatsResponse:
    """
    Get knowledge base statistics.
    
    Returns overview of the loaded knowledge including:
    - Total techniques, tactics, and RX modules
    - Supported platforms
    - Distribution by platform and executor type
    """
    stats = knowledge.get_statistics()
    return KnowledgeStatsResponse(**stats)


# ═══════════════════════════════════════════════════════════════
# Techniques Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/techniques", response_model=PaginatedResponse)
async def list_techniques(
    platform: Optional[str] = Query(None, description="Filter by platform"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> PaginatedResponse:
    """
    List all techniques with optional filtering.
    
    - **platform**: Filter by platform (windows, linux, macos, etc.)
    - **limit**: Maximum items to return
    - **offset**: Pagination offset
    """
    techniques, total = knowledge.list_techniques(
        platform=platform,
        limit=limit,
        offset=offset
    )
    
    return PaginatedResponse(
        items=techniques,
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueResponse)
async def get_technique(
    technique_id: str,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> TechniqueResponse:
    """
    Get a specific technique by ID.
    
    - **technique_id**: MITRE ATT&CK technique ID (e.g., T1003, T1003.001)
    """
    technique = knowledge.get_technique(technique_id)
    
    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found"
        )
    
    return TechniqueResponse(**technique)


@router.get("/techniques/{technique_id}/modules", response_model=List[ModuleResponse])
async def get_technique_modules(
    technique_id: str,
    platform: Optional[str] = Query(None, description="Filter by platform"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get all RX modules for a technique.
    
    - **technique_id**: Technique ID
    - **platform**: Optional platform filter
    """
    modules = knowledge.get_modules_for_technique(technique_id, platform=platform)
    
    if not modules:
        # Check if technique exists
        technique = knowledge.get_technique(technique_id)
        if not technique:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Technique {technique_id} not found"
            )
    
    return [ModuleResponse(**m) for m in modules]


# ═══════════════════════════════════════════════════════════════
# Modules Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/modules", response_model=PaginatedResponse)
async def list_modules(
    technique_id: Optional[str] = Query(None, description="Filter by technique"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    executor_type: Optional[str] = Query(None, description="Filter by executor type"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> PaginatedResponse:
    """
    List RX modules with filtering and pagination.
    
    - **technique_id**: Filter by technique
    - **platform**: Filter by platform (windows, linux, macos)
    - **executor_type**: Filter by executor type (powershell, sh, cmd)
    - **limit**: Maximum items to return
    - **offset**: Pagination offset
    """
    modules, total = knowledge.list_modules(
        technique_id=technique_id,
        platform=platform,
        executor_type=executor_type,
        limit=limit,
        offset=offset
    )
    
    return PaginatedResponse(
        items=modules,
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/modules/{module_id}", response_model=ModuleResponse)
async def get_module(
    module_id: str,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> ModuleResponse:
    """
    Get a specific RX module by ID.
    
    - **module_id**: RX Module ID (e.g., rx-t1003-001)
    """
    module = knowledge.get_module(module_id)
    
    if not module:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Module {module_id} not found"
        )
    
    return ModuleResponse(**module)


# ═══════════════════════════════════════════════════════════════
# Tactics Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/tactics", response_model=List[TacticResponse])
async def list_tactics(
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[TacticResponse]:
    """
    List all MITRE ATT&CK tactics.
    
    Returns all tactics with their technique counts.
    """
    tactics = knowledge.list_tactics()
    return [TacticResponse(**t) for t in tactics]


@router.get("/tactics/{tactic_id}/techniques", response_model=List[TechniqueResponse])
async def get_tactic_techniques(
    tactic_id: str,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[TechniqueResponse]:
    """
    Get all techniques for a tactic.
    
    - **tactic_id**: MITRE ATT&CK tactic ID (e.g., TA0001)
    """
    techniques = knowledge.get_techniques_for_tactic(tactic_id)
    
    if not techniques:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tactic {tactic_id} not found or has no techniques"
        )
    
    return [TechniqueResponse(**t) for t in techniques]


# ═══════════════════════════════════════════════════════════════
# Platform Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("/platforms", response_model=List[str])
async def list_platforms(
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[str]:
    """
    List all supported platforms.
    
    Returns list of platform names that have RX modules.
    """
    stats = knowledge.get_statistics()
    return stats.get('platforms', [])


@router.get("/platforms/{platform}/modules", response_model=List[ModuleResponse])
async def get_platform_modules(
    platform: str,
    limit: int = Query(50, ge=1, le=200, description="Maximum items"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get RX modules for a specific platform.
    
    - **platform**: Platform name (windows, linux, macos, etc.)
    - **limit**: Maximum items to return
    """
    modules = knowledge.get_modules_for_platform(platform, limit=limit)
    return [ModuleResponse(**m) for m in modules]


# ═══════════════════════════════════════════════════════════════
# Search Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get("/search", response_model=List[ModuleResponse])
async def search_modules(
    q: str = Query(..., min_length=1, max_length=200, description="Search query"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    tactic: Optional[str] = Query(None, description="Filter by tactic"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Search RX modules by keyword.
    
    Searches in technique names, IDs, and descriptions.
    
    - **q**: Search query
    - **platform**: Optional platform filter
    - **tactic**: Optional tactic filter
    - **limit**: Maximum results
    """
    modules = knowledge.search_modules(
        query=q,
        platform=platform,
        tactic=tactic,
        limit=limit
    )
    
    return [ModuleResponse(**m) for m in modules]


@router.post("/search", response_model=List[ModuleResponse])
async def search_modules_post(
    request: SearchRequest,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Search RX modules by keyword (POST variant).
    
    Use this for complex searches with multiple filters.
    """
    modules = knowledge.search_modules(
        query=request.query,
        platform=request.platform,
        tactic=request.tactic,
        limit=request.limit
    )
    
    return [ModuleResponse(**m) for m in modules]


# ═══════════════════════════════════════════════════════════════
# Task-Oriented Endpoints (For Specialists)
# ═══════════════════════════════════════════════════════════════

@router.post("/best-module", response_model=Optional[ModuleResponse])
async def get_best_module_for_task(
    request: TaskModuleRequest,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> Optional[ModuleResponse]:
    """
    Get the best matching module for a task.
    
    Uses intelligent scoring to select the most appropriate module
    based on tactic, technique, platform, and other criteria.
    
    - **tactic**: Target tactic
    - **technique**: Target technique
    - **platform**: Target platform
    - **executor_type**: Preferred executor type
    - **require_elevation**: Whether elevation is required
    """
    module = knowledge.get_module_for_task(
        tactic=request.tactic,
        technique=request.technique,
        platform=request.platform,
        executor_type=request.executor_type,
        require_elevation=request.require_elevation
    )
    
    if not module:
        return None
    
    return ModuleResponse(**module)


@router.get("/exploit-modules", response_model=List[ModuleResponse])
async def get_exploit_modules(
    vuln_type: Optional[str] = Query(None, description="Vulnerability type or CVE"),
    platform: Optional[str] = Query(None, description="Target platform"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get modules suitable for exploitation.
    
    Maps common vulnerabilities to exploit modules.
    
    - **vuln_type**: CVE ID or vulnerability name (e.g., MS17-010, EternalBlue)
    - **platform**: Target platform
    """
    modules = knowledge.get_exploit_modules(vuln_type=vuln_type, platform=platform)
    return [ModuleResponse(**m) for m in modules[:limit]]


@router.get("/recon-modules", response_model=List[ModuleResponse])
async def get_recon_modules(
    platform: Optional[str] = Query(None, description="Target platform"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get modules suitable for reconnaissance.
    
    Returns modules for system discovery, network enumeration, etc.
    
    - **platform**: Target platform
    """
    modules = knowledge.get_recon_modules(platform=platform)
    return [ModuleResponse(**m) for m in modules[:limit]]


@router.get("/credential-modules", response_model=List[ModuleResponse])
async def get_credential_modules(
    platform: Optional[str] = Query(None, description="Target platform"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get modules for credential harvesting.
    
    Returns modules for dumping credentials, accessing password stores, etc.
    
    - **platform**: Target platform
    """
    modules = knowledge.get_credential_modules(platform=platform)
    return [ModuleResponse(**m) for m in modules[:limit]]


@router.get("/privesc-modules", response_model=List[ModuleResponse])
async def get_privesc_modules(
    platform: Optional[str] = Query(None, description="Target platform"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[ModuleResponse]:
    """
    Get modules for privilege escalation.
    
    Returns modules for elevating privileges on compromised systems.
    
    - **platform**: Target platform
    """
    modules = knowledge.get_privesc_modules(platform=platform)
    return [ModuleResponse(**m) for m in modules[:limit]]


# ═══════════════════════════════════════════════════════════════
# Nuclei Templates Endpoints
# ═══════════════════════════════════════════════════════════════

class NucleiTemplateResponse(BaseModel):
    """Nuclei template response model."""
    template_id: str
    name: str
    severity: str = ""
    protocol: List[str] = []
    cve_id: Union[str, List[str]] = ""  # Can be string or list
    cwe_id: Union[str, List[str]] = ""  # Can be string or list
    cvss_score: Optional[float] = None
    cvss_metrics: Optional[str] = ""
    tags: List[str] = []
    description: Optional[str] = ""
    author: Optional[str] = ""
    reference: List[str] = []  # References list
    file_path: Optional[str] = ""


@router.get("/nuclei/templates", response_model=PaginatedResponse)
async def list_nuclei_templates(
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (http, tcp, dns, ssl)"),
    tag: Optional[str] = Query(None, description="Filter by tag (rce, sqli, xss, cve)"),
    limit: int = Query(100, ge=1, le=500, description="Page size"),
    offset: int = Query(0, ge=0, description="Page offset"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> PaginatedResponse:
    """
    List Nuclei templates with filtering and pagination.
    
    - **severity**: Filter by severity level
    - **protocol**: Filter by protocol type
    - **tag**: Filter by tag
    - **limit**: Maximum items to return
    - **offset**: Pagination offset
    """
    templates, total = knowledge.list_nuclei_templates(
        severity=severity,
        protocol=protocol,
        tag=tag,
        limit=limit,
        offset=offset
    )
    
    return PaginatedResponse(
        items=templates,
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/nuclei/templates/{template_id}", response_model=NucleiTemplateResponse)
async def get_nuclei_template(
    template_id: str,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> NucleiTemplateResponse:
    """
    Get a specific Nuclei template by ID.
    
    - **template_id**: Nuclei template ID (e.g., CVE-2021-44228)
    """
    template = knowledge.get_nuclei_template(template_id)
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Nuclei template {template_id} not found"
        )
    
    return NucleiTemplateResponse(**template)


@router.get("/nuclei/search", response_model=List[NucleiTemplateResponse])
async def search_nuclei_templates(
    q: str = Query(..., min_length=1, max_length=200, description="Search query"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Search Nuclei templates by keyword.
    
    Searches in template IDs, names, CVE IDs, and tags.
    
    - **q**: Search query
    - **severity**: Optional severity filter
    - **protocol**: Optional protocol filter
    - **limit**: Maximum results
    """
    templates = knowledge.search_nuclei_templates(
        query=q,
        severity=severity,
        protocol=protocol,
        limit=limit
    )
    
    return [NucleiTemplateResponse(**t) for t in templates]


@router.get("/nuclei/cve/{cve_id}", response_model=NucleiTemplateResponse)
async def get_nuclei_template_by_cve(
    cve_id: str,
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> NucleiTemplateResponse:
    """
    Get Nuclei template for a specific CVE.
    
    - **cve_id**: CVE ID (e.g., CVE-2021-44228)
    """
    template = knowledge.get_nuclei_template_by_cve(cve_id)
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No Nuclei template found for {cve_id}"
        )
    
    return NucleiTemplateResponse(**template)


@router.get("/nuclei/severity/{severity}", response_model=List[NucleiTemplateResponse])
async def get_nuclei_templates_by_severity(
    severity: str,
    limit: int = Query(100, ge=1, le=500, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Get Nuclei templates by severity level.
    
    - **severity**: Severity level (critical, high, medium, low, info)
    - **limit**: Maximum results
    """
    templates = knowledge.get_nuclei_templates_by_severity(severity, limit=limit)
    return [NucleiTemplateResponse(**t) for t in templates]


@router.get("/nuclei/critical", response_model=List[NucleiTemplateResponse])
async def get_critical_nuclei_templates(
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Get critical severity Nuclei templates.
    
    Shortcut for /nuclei/severity/critical.
    """
    templates = knowledge.get_nuclei_critical_templates(limit=limit)
    return [NucleiTemplateResponse(**t) for t in templates]


@router.get("/nuclei/rce", response_model=List[NucleiTemplateResponse])
async def get_rce_nuclei_templates(
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Get Remote Code Execution (RCE) Nuclei templates.
    
    Filters templates with 'rce' tag.
    """
    templates = knowledge.get_nuclei_rce_templates(limit=limit)
    return [NucleiTemplateResponse(**t) for t in templates]


@router.get("/nuclei/sqli", response_model=List[NucleiTemplateResponse])
async def get_sqli_nuclei_templates(
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Get SQL Injection (SQLi) Nuclei templates.
    
    Filters templates with 'sqli' tag.
    """
    templates = knowledge.get_nuclei_sqli_templates(limit=limit)
    return [NucleiTemplateResponse(**t) for t in templates]


@router.get("/nuclei/xss", response_model=List[NucleiTemplateResponse])
async def get_xss_nuclei_templates(
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    knowledge: EmbeddedKnowledge = Depends(get_knowledge_base)
) -> List[NucleiTemplateResponse]:
    """
    Get Cross-Site Scripting (XSS) Nuclei templates.
    
    Filters templates with 'xss' tag.
    """
    templates = knowledge.get_nuclei_xss_templates(limit=limit)
    return [NucleiTemplateResponse(**t) for t in templates]
