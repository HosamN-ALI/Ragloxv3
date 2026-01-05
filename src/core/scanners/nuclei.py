# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Nuclei Scanner Integration
# Async wrapper for Nuclei vulnerability scanner
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from ..models import Vulnerability, Severity

# Constants for RX module ID generation
RX_MODULE_PREFIX = "rx-"
RX_NUCLEI_PREFIX = "rx-nuclei-"


class NucleiSeverity(str, Enum):
    """Nuclei severity levels mapped to RAGLOX severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class NucleiVulnerability:
    """
    Parsed Nuclei vulnerability finding.
    
    This represents a single finding from Nuclei's JSON output,
    containing all relevant context for analysis and exploitation.
    """
    # Identification
    template_id: str
    template_name: str
    severity: NucleiSeverity
    
    # Target info
    host: str
    matched_at: str  # Full URL or host:port
    
    # Vulnerability details
    vuln_type: Optional[str] = None  # CVE-XXXX-XXXX or custom
    name: str = ""
    description: str = ""
    
    # Extraction data
    extracted_results: List[str] = field(default_factory=list)
    matcher_name: Optional[str] = None
    
    # HTTP context (for web vulns)
    curl_command: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    reference: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Raw data for debugging
    raw_json: Dict[str, Any] = field(default_factory=dict)
    
    def to_vulnerability(
        self,
        mission_id: UUID,
        target_id: UUID
    ) -> Vulnerability:
        """
        Convert to RAGLOX Vulnerability object.
        
        This provides unified data format for the rest of the system.
        """
        # Map Nuclei severity to RAGLOX Severity
        severity_map = {
            NucleiSeverity.CRITICAL: Severity.CRITICAL,
            NucleiSeverity.HIGH: Severity.HIGH,
            NucleiSeverity.MEDIUM: Severity.MEDIUM,
            NucleiSeverity.LOW: Severity.LOW,
            NucleiSeverity.INFO: Severity.INFO,
            NucleiSeverity.UNKNOWN: Severity.INFO,
        }
        
        # Build RX modules suggestion based on vulnerability type
        rx_modules = []
        if self.vuln_type and self.vuln_type.startswith("CVE-"):
            # Generate RX module ID from CVE using constant prefix
            rx_module_id = f"{RX_MODULE_PREFIX}{self.vuln_type.lower().replace('-', '_')}"
            rx_modules.append(rx_module_id)
        
        # Add template-based module suggestion using constant prefix
        if self.template_id:
            rx_modules.append(f"{RX_NUCLEI_PREFIX}{self.template_id}")
        
        return Vulnerability(
            mission_id=mission_id,
            target_id=target_id,
            type=self.vuln_type or self.template_id,
            name=self.name or self.template_name,
            description=self._build_description(),
            severity=severity_map.get(self.severity, Severity.INFO),
            status="discovered",
            exploit_available=self.severity in (NucleiSeverity.CRITICAL, NucleiSeverity.HIGH),
            rx_modules=rx_modules,
            discovered_by="nuclei_scanner",
            metadata={
                "nuclei_template": self.template_id,
                "matched_at": self.matched_at,
                "extracted_results": self.extracted_results,
                "matcher_name": self.matcher_name,
                "tags": self.tags,
                "reference": self.reference,
                "curl_command": self.curl_command,
            }
        )
    
    def _build_description(self) -> str:
        """Build rich description from Nuclei findings."""
        parts = []
        
        if self.description:
            parts.append(self.description)
        
        if self.extracted_results:
            parts.append(f"Extracted data: {', '.join(self.extracted_results[:5])}")
        
        if self.matcher_name:
            parts.append(f"Matcher: {self.matcher_name}")
        
        if self.reference:
            parts.append(f"References: {', '.join(self.reference[:3])}")
        
        return " | ".join(parts) if parts else f"Vulnerability detected by {self.template_id}"


@dataclass
class NucleiScanResult:
    """
    Result of a Nuclei scan operation.
    """
    success: bool
    target: str
    vulnerabilities: List[NucleiVulnerability] = field(default_factory=list)
    templates_used: List[str] = field(default_factory=list)
    duration_ms: int = 0
    error_message: Optional[str] = None
    stderr: Optional[str] = None
    stdout: Optional[str] = None
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == NucleiSeverity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == NucleiSeverity.HIGH)
    
    @property
    def info_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == NucleiSeverity.INFO)
    
    def get_exploitable_vulnerabilities(self) -> List[NucleiVulnerability]:
        """Get vulnerabilities worth exploiting (Critical/High severity)."""
        return [
            v for v in self.vulnerabilities
            if v.severity in (NucleiSeverity.CRITICAL, NucleiSeverity.HIGH)
        ]
    
    def get_info_vulnerabilities(self) -> List[NucleiVulnerability]:
        """Get informational vulnerabilities (not worth exploiting)."""
        return [
            v for v in self.vulnerabilities
            if v.severity in (NucleiSeverity.INFO, NucleiSeverity.LOW)
        ]


class NucleiScanner:
    """
    Async Nuclei vulnerability scanner wrapper.
    
    This class wraps the Nuclei CLI tool and provides:
    - Async subprocess execution (non-blocking)
    - Template management and selection
    - JSON output parsing
    - Conversion to RAGLOX Vulnerability objects
    
    Example usage:
        scanner = NucleiScanner()
        result = await scanner.scan(
            target="https://example.com",
            templates=["cves", "vulnerabilities"],
            severity=["critical", "high"]
        )
        
        for vuln in result.get_exploitable_vulnerabilities():
            print(f"Found {vuln.severity}: {vuln.name}")
    """
    
    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_dir: Optional[str] = None,
        timeout: int = 600,
        rate_limit: int = 150,
        concurrency: int = 25,
    ):
        """
        Initialize Nuclei scanner.
        
        Args:
            nuclei_path: Path to nuclei binary (default: assumes in PATH)
            templates_dir: Custom templates directory
            timeout: Scan timeout in seconds
            rate_limit: Request rate limit per second
            concurrency: Number of concurrent templates
        """
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.logger = logging.getLogger("raglox.scanner.nuclei")
    
    async def scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        rate_limit: Optional[int] = None,
        timeout: Optional[int] = None,
        include_request_response: bool = False,
    ) -> NucleiScanResult:
        """
        Execute Nuclei scan on target.
        
        This method runs Nuclei as an async subprocess, ensuring
        the event loop is not blocked during scanning.
        
        Args:
            target: Target URL or IP address
            templates: List of template IDs or directories
            severity: Filter by severity levels (critical, high, medium, low, info)
            tags: Include only templates with these tags
            exclude_tags: Exclude templates with these tags
            rate_limit: Override default rate limit
            timeout: Override default timeout
            include_request_response: Include HTTP request/response in output
            
        Returns:
            NucleiScanResult with parsed vulnerabilities
        """
        start_time = datetime.utcnow()
        
        # Build command
        cmd = await self._build_command(
            target=target,
            templates=templates,
            severity=severity,
            tags=tags,
            exclude_tags=exclude_tags,
            rate_limit=rate_limit or self.rate_limit,
            include_request_response=include_request_response,
        )
        
        self.logger.info(f"Starting Nuclei scan on {target}")
        self.logger.debug(f"Command: {' '.join(cmd)}")
        
        try:
            # Execute as async subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Wait for completion with timeout
            scan_timeout = timeout or self.timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=scan_timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                return NucleiScanResult(
                    success=False,
                    target=target,
                    duration_ms=duration,
                    error_message=f"Scan timed out after {scan_timeout}s",
                )
            
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            
            duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            # Parse results
            vulnerabilities = self._parse_json_output(stdout)
            
            self.logger.info(
                f"Nuclei scan completed: {len(vulnerabilities)} findings "
                f"(critical={sum(1 for v in vulnerabilities if v.severity == NucleiSeverity.CRITICAL)}, "
                f"high={sum(1 for v in vulnerabilities if v.severity == NucleiSeverity.HIGH)})"
            )
            
            return NucleiScanResult(
                success=True,
                target=target,
                vulnerabilities=vulnerabilities,
                templates_used=templates or ["default"],
                duration_ms=duration,
                stdout=stdout,
                stderr=stderr if stderr else None,
            )
            
        except FileNotFoundError:
            self.logger.error(f"Nuclei binary not found at: {self.nuclei_path}")
            return NucleiScanResult(
                success=False,
                target=target,
                error_message=f"Nuclei binary not found at: {self.nuclei_path}",
            )
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return NucleiScanResult(
                success=False,
                target=target,
                error_message=str(e),
            )
    
    async def scan_multiple(
        self,
        targets: List[str],
        **kwargs
    ) -> Dict[str, NucleiScanResult]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of target URLs or IPs
            **kwargs: Additional arguments passed to scan()
            
        Returns:
            Dictionary mapping target to scan result
        """
        tasks = [self.scan(target, **kwargs) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            target: result if isinstance(result, NucleiScanResult)
            else NucleiScanResult(
                success=False,
                target=target,
                error_message=str(result)
            )
            for target, result in zip(targets, results)
        }
    
    async def _build_command(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        rate_limit: int = 150,
        include_request_response: bool = False,
    ) -> List[str]:
        """Build Nuclei command line arguments."""
        cmd = [
            self.nuclei_path,
            "-u", target,
            "-json",  # JSON output for parsing
            "-silent",  # No banner
            "-rate-limit", str(rate_limit),
            "-concurrency", str(self.concurrency),
            "-no-color",
        ]
        
        # Add templates directory if specified
        if self.templates_dir:
            cmd.extend(["-templates", self.templates_dir])
        
        # Add specific templates
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        
        # Add severity filter
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        
        # Add tag filters
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        
        # Include request/response for deep analysis
        if include_request_response:
            cmd.append("-include-rr")
        
        return cmd
    
    def _parse_json_output(self, output: str) -> List[NucleiVulnerability]:
        """
        Parse Nuclei JSON output into NucleiVulnerability objects.
        
        Nuclei outputs one JSON object per line for each finding.
        """
        vulnerabilities = []
        
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                vuln = self._parse_single_finding(data)
                if vuln:
                    vulnerabilities.append(vuln)
            except json.JSONDecodeError as e:
                self.logger.debug(f"Failed to parse line as JSON: {line[:100]}... Error: {e}")
                continue
        
        return vulnerabilities
    
    def _parse_single_finding(self, data: Dict[str, Any]) -> Optional[NucleiVulnerability]:
        """Parse a single Nuclei JSON finding."""
        try:
            # Get template info
            template_info = data.get("info", {})
            
            # Map severity
            severity_str = template_info.get("severity", "unknown").lower()
            try:
                severity = NucleiSeverity(severity_str)
            except ValueError:
                severity = NucleiSeverity.UNKNOWN
            
            # Extract CVE if present
            vuln_type = None
            classification = template_info.get("classification", {})
            cve_ids = classification.get("cve-id") or []
            if cve_ids:
                vuln_type = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
            
            # Build vulnerability object
            return NucleiVulnerability(
                template_id=data.get("template-id", data.get("templateID", "unknown")),
                template_name=template_info.get("name", "Unknown"),
                severity=severity,
                host=data.get("host", ""),
                matched_at=data.get("matched-at", data.get("matched", "")),
                vuln_type=vuln_type,
                name=template_info.get("name", ""),
                description=template_info.get("description", ""),
                extracted_results=data.get("extracted-results", []) or [],
                matcher_name=data.get("matcher-name"),
                curl_command=data.get("curl-command"),
                request=data.get("request"),
                response=data.get("response"),
                tags=template_info.get("tags", []) or [],
                reference=template_info.get("reference", []) or [],
                raw_json=data,
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse Nuclei finding: {e}")
            return None
    
    async def check_available(self) -> bool:
        """Check if Nuclei is available on the system."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except FileNotFoundError:
            return False
    
    async def get_version(self) -> Optional[str]:
        """Get Nuclei version."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            return stdout.decode().strip()
        except Exception:
            return None
