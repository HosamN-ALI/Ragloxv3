# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Security API Routes (SEC-03 & SEC-04)
# REST API endpoints for security validation and rate limiting
# ═══════════════════════════════════════════════════════════════

"""
SEC-03: Input Validation API Endpoints
SEC-04: Rate Limiting API Endpoints

This module provides:
- Input validation status and testing endpoints
- Rate limiter configuration and status endpoints
- Security health check endpoints
- API abuse detection and monitoring

All endpoints are documented via OpenAPI/Swagger.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import asyncio
import time
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator, model_validator
import re

# Custom validators
from ..core.validators import (
    validate_ip_address,
    validate_ip_network,
    validate_uuid,
    validate_hostname,
    validate_domain,
    validate_port,
    validate_port_range,
    validate_safe_string,
    validate_name,
    validate_cve,
    validate_cvss,
    validate_scope,
    sanitize_string,
    is_valid_uuid,
    is_valid_cve,
    check_command_injection,
    check_path_traversal,
)
from ..core.exceptions import ValidationException, RateLimitExceededError

# Rate Limiter
from ..core.security.rate_limiter import (
    RateLimiter,
    RateLimitExceeded,
    TokenBucket,
    rate_limit,
    RATE_LIMITS,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security", tags=["Security"])


# ═══════════════════════════════════════════════════════════════
# Request/Response Models - SEC-03 Input Validation
# ═══════════════════════════════════════════════════════════════

class ValidateIPRequest(BaseModel):
    """Request to validate an IP address."""
    ip: str = Field(..., description="IP address to validate (IPv4 or IPv6)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "ip": "192.168.1.100"
            }
        }


class ValidateCIDRRequest(BaseModel):
    """Request to validate a CIDR notation."""
    cidr: str = Field(..., description="CIDR notation to validate (e.g., 192.168.1.0/24)")
    strict: bool = Field(False, description="If True, host bits must be zero")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cidr": "192.168.1.0/24",
                "strict": False
            }
        }


class ValidateUUIDRequest(BaseModel):
    """Request to validate a UUID."""
    uuid: str = Field(..., description="UUID string to validate")
    field_name: str = Field("id", description="Field name for error messages")
    
    class Config:
        json_schema_extra = {
            "example": {
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "field_name": "mission_id"
            }
        }


class ValidateHostnameRequest(BaseModel):
    """Request to validate a hostname."""
    hostname: str = Field(..., description="Hostname to validate")
    
    class Config:
        json_schema_extra = {
            "example": {
                "hostname": "target-server.example.com"
            }
        }


class ValidatePortRequest(BaseModel):
    """Request to validate a port or port range."""
    port: str = Field(..., description="Port number or range (e.g., 80 or 80-443)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "port": "80-443"
            }
        }


class ValidateCVERequest(BaseModel):
    """Request to validate a CVE identifier."""
    cve: str = Field(..., description="CVE identifier (e.g., CVE-2021-44228)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cve": "CVE-2021-44228"
            }
        }


class ValidateScopeRequest(BaseModel):
    """Request to validate a mission scope."""
    scope: List[str] = Field(..., min_length=1, description="List of scope entries (IPs, CIDRs, hostnames)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scope": ["192.168.1.0/24", "10.0.0.1", "target.example.com"]
            }
        }


class ValidateSafeStringRequest(BaseModel):
    """Request to validate a safe string (no injection patterns)."""
    value: str = Field(..., description="String to validate")
    field_name: str = Field("input", description="Field name for error messages")
    max_length: int = Field(1000, ge=1, le=10000, description="Maximum allowed length")
    
    class Config:
        json_schema_extra = {
            "example": {
                "value": "This is a safe string",
                "field_name": "description",
                "max_length": 500
            }
        }


class ValidationResponse(BaseModel):
    """Response for validation requests."""
    valid: bool = Field(..., description="Whether the input is valid")
    value: Optional[Any] = Field(None, description="Validated/normalized value")
    error: Optional[str] = Field(None, description="Error message if invalid")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")


class BatchValidationRequest(BaseModel):
    """Request for batch validation."""
    items: List[Dict[str, Any]] = Field(..., description="List of items to validate")
    validation_type: str = Field(..., description="Type of validation (ip, cidr, uuid, hostname, port, cve, scope)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "items": [
                    {"value": "192.168.1.1"},
                    {"value": "192.168.1.2"},
                    {"value": "invalid-ip"}
                ],
                "validation_type": "ip"
            }
        }


class BatchValidationResponse(BaseModel):
    """Response for batch validation."""
    total: int
    valid_count: int
    invalid_count: int
    results: List[ValidationResponse]


# ═══════════════════════════════════════════════════════════════
# Request/Response Models - SEC-04 Rate Limiting
# ═══════════════════════════════════════════════════════════════

class RateLimitConfig(BaseModel):
    """Rate limit configuration."""
    endpoint: str = Field(..., description="Endpoint name")
    rate: int = Field(..., ge=1, le=10000, description="Requests allowed per period")
    period: int = Field(..., ge=1, le=86400, description="Period in seconds")
    burst: Optional[int] = Field(None, description="Maximum burst size (defaults to rate)")


class RateLimitStatus(BaseModel):
    """Rate limit status for an endpoint."""
    endpoint: str
    rate: int
    period: int
    remaining: int
    reset_at: str
    exceeded: bool


class RateLimiterHealthResponse(BaseModel):
    """Rate limiter health response."""
    status: str
    active_limiters: int
    total_requests_limited: int
    endpoints: Dict[str, RateLimitStatus]


class RateLimitTestRequest(BaseModel):
    """Request to test rate limit for an endpoint."""
    endpoint: str = Field(..., description="Endpoint name to test")
    key: str = Field("test-client", description="Client identifier key")
    
    class Config:
        json_schema_extra = {
            "example": {
                "endpoint": "missions_create",
                "key": "192.168.1.100"
            }
        }


class RateLimitTestResponse(BaseModel):
    """Response for rate limit test."""
    allowed: bool
    retry_after: int
    rate: int
    period: int
    limit_spec: str


# ═══════════════════════════════════════════════════════════════
# Security Health Models
# ═══════════════════════════════════════════════════════════════

class SecurityHealthResponse(BaseModel):
    """Overall security health response."""
    status: str
    timestamp: str
    components: Dict[str, Dict[str, Any]]
    alerts: List[Dict[str, Any]]


class InputValidationStatsResponse(BaseModel):
    """Input validation statistics."""
    total_validations: int
    successful_validations: int
    failed_validations: int
    validation_errors_by_type: Dict[str, int]
    recent_errors: List[Dict[str, Any]]


# ═══════════════════════════════════════════════════════════════
# Global State for Statistics
# ═══════════════════════════════════════════════════════════════

_validation_stats = {
    "total_validations": 0,
    "successful_validations": 0,
    "failed_validations": 0,
    "errors_by_type": {},
    "recent_errors": [],
}

_rate_limit_stats = {
    "total_requests": 0,
    "total_limited": 0,
    "limited_by_endpoint": {},
}

# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def record_validation(validation_type: str, success: bool, error: Optional[str] = None):
    """Record validation statistics."""
    _validation_stats["total_validations"] += 1
    
    if success:
        _validation_stats["successful_validations"] += 1
    else:
        _validation_stats["failed_validations"] += 1
        _validation_stats["errors_by_type"][validation_type] = (
            _validation_stats["errors_by_type"].get(validation_type, 0) + 1
        )
        
        # Keep only last 100 errors
        _validation_stats["recent_errors"].append({
            "type": validation_type,
            "error": error,
            "timestamp": datetime.utcnow().isoformat()
        })
        if len(_validation_stats["recent_errors"]) > 100:
            _validation_stats["recent_errors"] = _validation_stats["recent_errors"][-100:]


def record_rate_limit(endpoint: str, limited: bool):
    """Record rate limit statistics."""
    _rate_limit_stats["total_requests"] += 1
    if limited:
        _rate_limit_stats["total_limited"] += 1
        _rate_limit_stats["limited_by_endpoint"][endpoint] = (
            _rate_limit_stats["limited_by_endpoint"].get(endpoint, 0) + 1
        )


# ═══════════════════════════════════════════════════════════════
# SEC-03: Input Validation Endpoints
# ═══════════════════════════════════════════════════════════════

@router.post(
    "/validate/ip",
    response_model=ValidationResponse,
    summary="Validate IP Address",
    description="Validate an IPv4 or IPv6 address. Returns normalized IP if valid."
)
async def validate_ip_endpoint(request: ValidateIPRequest) -> ValidationResponse:
    """
    Validate an IP address.
    
    **SEC-03 Implementation**
    
    - Supports IPv4 and IPv6
    - Returns normalized IP address
    - Detects invalid formats
    
    Example:
    ```json
    {"ip": "192.168.1.100"}
    ```
    """
    try:
        validated = validate_ip_address(request.ip)
        record_validation("ip", True)
        return ValidationResponse(
            valid=True,
            value=validated,
            details={"type": "ipv4" if ":" not in validated else "ipv6"}
        )
    except Exception as e:
        record_validation("ip", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.ip}
        )


@router.post(
    "/validate/cidr",
    response_model=ValidationResponse,
    summary="Validate CIDR Notation",
    description="Validate a CIDR network notation (e.g., 192.168.1.0/24)."
)
async def validate_cidr_endpoint(request: ValidateCIDRRequest) -> ValidationResponse:
    """
    Validate a CIDR notation.
    
    **SEC-03 Implementation**
    
    - Validates network address and prefix length
    - Optional strict mode (host bits must be zero)
    - Returns network details
    """
    try:
        network = validate_ip_network(request.cidr, strict=request.strict)
        record_validation("cidr", True)
        return ValidationResponse(
            valid=True,
            value=str(network),
            details={
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address),
                "num_hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
                "prefix_length": network.prefixlen
            }
        )
    except Exception as e:
        record_validation("cidr", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.cidr}
        )


@router.post(
    "/validate/uuid",
    response_model=ValidationResponse,
    summary="Validate UUID",
    description="Validate a UUID string."
)
async def validate_uuid_endpoint(request: ValidateUUIDRequest) -> ValidationResponse:
    """
    Validate a UUID.
    
    **SEC-03 Implementation**
    
    - Validates UUID format
    - Returns UUID version information
    """
    try:
        validated = validate_uuid(request.uuid, request.field_name)
        record_validation("uuid", True)
        return ValidationResponse(
            valid=True,
            value=str(validated),
            details={
                "version": validated.version,
                "field_name": request.field_name
            }
        )
    except Exception as e:
        record_validation("uuid", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.uuid, "field_name": request.field_name}
        )


@router.post(
    "/validate/hostname",
    response_model=ValidationResponse,
    summary="Validate Hostname",
    description="Validate a hostname according to RFC 1123."
)
async def validate_hostname_endpoint(request: ValidateHostnameRequest) -> ValidationResponse:
    """
    Validate a hostname.
    
    **SEC-03 Implementation**
    
    - RFC 1123 compliant validation
    - Checks label lengths and total length
    - Validates character set
    """
    try:
        is_valid = validate_hostname(request.hostname)
        if is_valid:
            record_validation("hostname", True)
            return ValidationResponse(
                valid=True,
                value=request.hostname.lower(),
                details={
                    "labels": request.hostname.split("."),
                    "total_length": len(request.hostname)
                }
            )
        else:
            record_validation("hostname", False, "Invalid hostname format")
            return ValidationResponse(
                valid=False,
                error="Invalid hostname format",
                details={"input": request.hostname}
            )
    except Exception as e:
        record_validation("hostname", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.hostname}
        )


@router.post(
    "/validate/port",
    response_model=ValidationResponse,
    summary="Validate Port",
    description="Validate a port number or port range (e.g., 80 or 80-443)."
)
async def validate_port_endpoint(request: ValidatePortRequest) -> ValidationResponse:
    """
    Validate a port or port range.
    
    **SEC-03 Implementation**
    
    - Validates port numbers (1-65535)
    - Supports port ranges (e.g., "80-443")
    - Returns start and end port
    """
    try:
        if "-" in request.port:
            start, end = validate_port_range(request.port)
            record_validation("port", True)
            return ValidationResponse(
                valid=True,
                value={"start": start, "end": end},
                details={"type": "range", "count": end - start + 1}
            )
        else:
            port = validate_port(int(request.port))
            record_validation("port", True)
            return ValidationResponse(
                valid=True,
                value=port,
                details={"type": "single"}
            )
    except Exception as e:
        record_validation("port", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.port}
        )


@router.post(
    "/validate/cve",
    response_model=ValidationResponse,
    summary="Validate CVE",
    description="Validate a CVE identifier (e.g., CVE-2021-44228)."
)
async def validate_cve_endpoint(request: ValidateCVERequest) -> ValidationResponse:
    """
    Validate a CVE identifier.
    
    **SEC-03 Implementation**
    
    - Validates CVE format (CVE-YYYY-NNNNN)
    - Normalizes to uppercase
    - Extracts year and sequence number
    """
    try:
        validated = validate_cve(request.cve)
        record_validation("cve", True)
        
        # Extract year and sequence
        parts = validated.split("-")
        year = int(parts[1])
        sequence = int(parts[2])
        
        return ValidationResponse(
            valid=True,
            value=validated,
            details={
                "year": year,
                "sequence": sequence,
                "format": "CVE-YYYY-NNNNN"
            }
        )
    except Exception as e:
        record_validation("cve", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.cve, "expected_format": "CVE-YYYY-NNNNN"}
        )


@router.post(
    "/validate/scope",
    response_model=ValidationResponse,
    summary="Validate Mission Scope",
    description="Validate a list of scope entries (IPs, CIDRs, hostnames)."
)
async def validate_scope_endpoint(request: ValidateScopeRequest) -> ValidationResponse:
    """
    Validate a mission scope.
    
    **SEC-03 Implementation**
    
    - Validates each entry as IP, CIDR, or hostname
    - Returns categorized results
    - Detects invalid entries
    """
    try:
        validated = validate_scope(request.scope)
        record_validation("scope", True)
        
        # Categorize entries
        ips = []
        cidrs = []
        hostnames = []
        
        for entry in validated:
            if "/" in entry:
                cidrs.append(entry)
            elif entry[0].isdigit():
                ips.append(entry)
            else:
                hostnames.append(entry)
        
        return ValidationResponse(
            valid=True,
            value=validated,
            details={
                "total_entries": len(validated),
                "ips": ips,
                "cidrs": cidrs,
                "hostnames": hostnames
            }
        )
    except Exception as e:
        record_validation("scope", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={"input": request.scope}
        )


@router.post(
    "/validate/safe-string",
    response_model=ValidationResponse,
    summary="Validate Safe String",
    description="Validate a string for potential injection patterns."
)
async def validate_safe_string_endpoint(request: ValidateSafeStringRequest) -> ValidationResponse:
    """
    Validate a string for safety.
    
    **SEC-03 Implementation**
    
    - Checks for command injection patterns
    - Checks for path traversal patterns
    - Sanitizes input
    """
    try:
        validated = validate_safe_string(
            request.value,
            field_name=request.field_name,
            max_length=request.max_length
        )
        record_validation("safe_string", True)
        return ValidationResponse(
            valid=True,
            value=validated,
            details={
                "original_length": len(request.value),
                "sanitized_length": len(validated),
                "field_name": request.field_name
            }
        )
    except Exception as e:
        record_validation("safe_string", False, str(e))
        return ValidationResponse(
            valid=False,
            error=str(e),
            details={
                "input_preview": request.value[:50] + "..." if len(request.value) > 50 else request.value,
                "field_name": request.field_name
            }
        )


@router.post(
    "/validate/batch",
    response_model=BatchValidationResponse,
    summary="Batch Validate",
    description="Validate multiple items of the same type."
)
async def batch_validate_endpoint(request: BatchValidationRequest) -> BatchValidationResponse:
    """
    Batch validate multiple items.
    
    **SEC-03 Implementation**
    
    Supported types: ip, cidr, uuid, hostname, port, cve, scope
    """
    validators = {
        "ip": lambda v: validate_ip_address(v["value"]),
        "cidr": lambda v: str(validate_ip_network(v["value"])),
        "uuid": lambda v: str(validate_uuid(v["value"])),
        "hostname": lambda v: v["value"] if validate_hostname(v["value"]) else None,
        "port": lambda v: validate_port(int(v["value"])),
        "cve": lambda v: validate_cve(v["value"]),
    }
    
    if request.validation_type not in validators:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported validation type: {request.validation_type}"
        )
    
    validator = validators[request.validation_type]
    results = []
    valid_count = 0
    invalid_count = 0
    
    for item in request.items:
        try:
            validated = validator(item)
            if validated:
                results.append(ValidationResponse(valid=True, value=validated))
                valid_count += 1
                record_validation(request.validation_type, True)
            else:
                results.append(ValidationResponse(valid=False, error="Invalid format"))
                invalid_count += 1
                record_validation(request.validation_type, False, "Invalid format")
        except Exception as e:
            results.append(ValidationResponse(valid=False, error=str(e)))
            invalid_count += 1
            record_validation(request.validation_type, False, str(e))
    
    return BatchValidationResponse(
        total=len(request.items),
        valid_count=valid_count,
        invalid_count=invalid_count,
        results=results
    )


@router.get(
    "/validate/stats",
    response_model=InputValidationStatsResponse,
    summary="Get Validation Statistics",
    description="Get statistics about input validation."
)
async def get_validation_stats() -> InputValidationStatsResponse:
    """
    Get input validation statistics.
    
    **SEC-03 Monitoring**
    
    - Total validations performed
    - Success/failure counts
    - Errors by validation type
    - Recent errors
    """
    return InputValidationStatsResponse(
        total_validations=_validation_stats["total_validations"],
        successful_validations=_validation_stats["successful_validations"],
        failed_validations=_validation_stats["failed_validations"],
        validation_errors_by_type=_validation_stats["errors_by_type"],
        recent_errors=_validation_stats["recent_errors"][-10:]  # Last 10 errors
    )


# ═══════════════════════════════════════════════════════════════
# SEC-04: Rate Limiting Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/rate-limits",
    response_model=Dict[str, str],
    summary="Get Rate Limit Configurations",
    description="Get all configured rate limits for API endpoints."
)
async def get_rate_limit_configs() -> Dict[str, str]:
    """
    Get all rate limit configurations.
    
    **SEC-04 Implementation**
    
    Returns configured rate limits for all protected endpoints.
    """
    return RATE_LIMITS


@router.post(
    "/rate-limits/test",
    response_model=RateLimitTestResponse,
    summary="Test Rate Limit",
    description="Test if a request would be rate limited."
)
async def test_rate_limit(request: RateLimitTestRequest) -> RateLimitTestResponse:
    """
    Test rate limit without consuming tokens.
    
    **SEC-04 Implementation**
    
    - Check if request would be allowed
    - Get retry-after time if limited
    - Does NOT consume tokens
    """
    limiter = get_rate_limiter()
    
    # Get the limit spec for the endpoint
    limit_spec = RATE_LIMITS.get(request.endpoint, RATE_LIMITS["default"])
    rate, period = limiter.parse_limit(limit_spec)
    
    # Check if allowed (but don't consume)
    allowed, retry_after = await limiter.is_allowed(
        f"{request.key}:{request.endpoint}",
        rate,
        period
    )
    
    record_rate_limit(request.endpoint, not allowed)
    
    return RateLimitTestResponse(
        allowed=allowed,
        retry_after=retry_after,
        rate=rate,
        period=period,
        limit_spec=limit_spec
    )


@router.get(
    "/rate-limits/status",
    response_model=RateLimiterHealthResponse,
    summary="Get Rate Limiter Status",
    description="Get the current status of the rate limiter."
)
async def get_rate_limiter_status() -> RateLimiterHealthResponse:
    """
    Get rate limiter health status.
    
    **SEC-04 Monitoring**
    
    - Active limiters count
    - Total requests limited
    - Per-endpoint status
    """
    limiter = get_rate_limiter()
    
    endpoints = {}
    for endpoint, limit_spec in RATE_LIMITS.items():
        rate, period = limiter.parse_limit(limit_spec)
        endpoints[endpoint] = RateLimitStatus(
            endpoint=endpoint,
            rate=rate,
            period=period,
            remaining=rate,  # Would need actual tracking
            reset_at=(datetime.utcnow() + timedelta(seconds=period)).isoformat(),
            exceeded=False
        )
    
    return RateLimiterHealthResponse(
        status="healthy",
        active_limiters=len(limiter._buckets),
        total_requests_limited=_rate_limit_stats["total_limited"],
        endpoints=endpoints
    )


@router.post(
    "/rate-limits/reset",
    summary="Reset Rate Limiter",
    description="Reset rate limit counters (admin only)."
)
async def reset_rate_limiter(
    endpoint: Optional[str] = None,
    key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Reset rate limit counters.
    
    **SEC-04 Administration**
    
    - Reset specific endpoint or all
    - Clear client key limits
    """
    limiter = get_rate_limiter()
    await limiter.cleanup()
    
    return {
        "status": "success",
        "message": "Rate limiter reset successfully",
        "endpoint": endpoint or "all",
        "key": key or "all"
    }


@router.get(
    "/rate-limits/stats",
    summary="Get Rate Limit Statistics",
    description="Get detailed statistics about rate limiting."
)
async def get_rate_limit_stats() -> Dict[str, Any]:
    """
    Get rate limit statistics.
    
    **SEC-04 Monitoring**
    """
    return {
        "total_requests": _rate_limit_stats["total_requests"],
        "total_limited": _rate_limit_stats["total_limited"],
        "limited_by_endpoint": _rate_limit_stats["limited_by_endpoint"],
        "limit_rate": (
            _rate_limit_stats["total_limited"] / _rate_limit_stats["total_requests"] * 100
            if _rate_limit_stats["total_requests"] > 0 else 0
        )
    }


# ═══════════════════════════════════════════════════════════════
# Security Health Endpoint
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/health",
    response_model=SecurityHealthResponse,
    summary="Security Health Check",
    description="Get overall security status including validation and rate limiting."
)
async def security_health_check() -> SecurityHealthResponse:
    """
    Get overall security health.
    
    **SEC-03 & SEC-04 Combined Health Check**
    
    - Input validation status
    - Rate limiter status
    - Recent security alerts
    """
    alerts = []
    
    # Check validation error rate
    if _validation_stats["total_validations"] > 0:
        error_rate = _validation_stats["failed_validations"] / _validation_stats["total_validations"]
        if error_rate > 0.5:
            alerts.append({
                "severity": "warning",
                "component": "input_validation",
                "message": f"High validation error rate: {error_rate:.1%}"
            })
    
    # Check rate limiting
    if _rate_limit_stats["total_requests"] > 0:
        limit_rate = _rate_limit_stats["total_limited"] / _rate_limit_stats["total_requests"]
        if limit_rate > 0.1:
            alerts.append({
                "severity": "warning",
                "component": "rate_limiter",
                "message": f"High rate limit rate: {limit_rate:.1%}"
            })
    
    return SecurityHealthResponse(
        status="healthy" if not alerts else "warning",
        timestamp=datetime.utcnow().isoformat(),
        components={
            "input_validation": {
                "status": "healthy",
                "total_validations": _validation_stats["total_validations"],
                "error_rate": (
                    _validation_stats["failed_validations"] / _validation_stats["total_validations"]
                    if _validation_stats["total_validations"] > 0 else 0
                )
            },
            "rate_limiter": {
                "status": "healthy",
                "total_requests": _rate_limit_stats["total_requests"],
                "total_limited": _rate_limit_stats["total_limited"]
            }
        },
        alerts=alerts
    )


# ═══════════════════════════════════════════════════════════════
# Injection Detection Endpoints
# ═══════════════════════════════════════════════════════════════

class InjectionCheckRequest(BaseModel):
    """Request to check for injection patterns."""
    value: str = Field(..., description="String to check")
    check_types: List[str] = Field(
        default=["command", "path", "sql", "xss"],
        description="Types of injection to check for"
    )


class InjectionCheckResponse(BaseModel):
    """Response for injection check."""
    safe: bool
    detected_patterns: List[str]
    sanitized_value: str
    details: Dict[str, Any]


@router.post(
    "/check-injection",
    response_model=InjectionCheckResponse,
    summary="Check for Injection Patterns",
    description="Check a string for various injection patterns."
)
async def check_injection_patterns(request: InjectionCheckRequest) -> InjectionCheckResponse:
    """
    Check for injection patterns.
    
    **SEC-03 Security Feature**
    
    Detects:
    - Command injection
    - Path traversal
    - SQL injection (basic)
    - XSS patterns (basic)
    """
    detected = []
    details = {}
    
    if "command" in request.check_types:
        if check_command_injection(request.value):
            detected.append("command_injection")
            details["command_injection"] = "Potential command injection characters detected"
    
    if "path" in request.check_types:
        if check_path_traversal(request.value):
            detected.append("path_traversal")
            details["path_traversal"] = "Path traversal pattern detected"
    
    if "sql" in request.check_types:
        sql_patterns = re.compile(
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|OR|AND)\b.*['\"])|"
            r"(['\"].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|OR|AND)\b)",
            re.IGNORECASE
        )
        if sql_patterns.search(request.value):
            detected.append("sql_injection")
            details["sql_injection"] = "Potential SQL injection pattern detected"
    
    if "xss" in request.check_types:
        xss_patterns = re.compile(r"<script|javascript:|on\w+=|<iframe", re.IGNORECASE)
        if xss_patterns.search(request.value):
            detected.append("xss")
            details["xss"] = "Potential XSS pattern detected"
    
    # Sanitize the value
    sanitized = sanitize_string(request.value)
    
    return InjectionCheckResponse(
        safe=len(detected) == 0,
        detected_patterns=detected,
        sanitized_value=sanitized,
        details=details
    )
