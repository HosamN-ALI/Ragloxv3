# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Input Validators
# Comprehensive validation utilities for all inputs
# ═══════════════════════════════════════════════════════════════

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import UUID
from functools import wraps

from pydantic import BaseModel, ValidationError

from .exceptions import (
    InvalidIPAddressError,
    InvalidCIDRError,
    InvalidUUIDError,
    MissingRequiredFieldError,
    ValidationException,
    TargetOutOfScopeError,
)


# ═══════════════════════════════════════════════════════════════
# IP Address Validation
# ═══════════════════════════════════════════════════════════════

def validate_ip_address(ip: str) -> str:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address string
        
    Returns:
        Normalized IP address string
        
    Raises:
        InvalidIPAddressError: If IP is invalid
    """
    try:
        # This normalizes the IP address
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as e:
        raise InvalidIPAddressError(ip, details={"reason": str(e)})


def validate_ip_network(cidr: str, strict: bool = False) -> ipaddress.IPv4Network:
    """
    Validate a CIDR network notation.
    
    Args:
        cidr: CIDR notation string (e.g., "192.168.1.0/24")
        strict: If True, host bits must be zero
        
    Returns:
        ipaddress.IPv4Network object
        
    Raises:
        InvalidCIDRError: If CIDR is invalid
    """
    try:
        return ipaddress.ip_network(cidr.strip(), strict=strict)
    except ValueError as e:
        raise InvalidCIDRError(cidr, details={"reason": str(e)})


def is_ip_in_networks(
    ip: str,
    networks: List[str]
) -> bool:
    """
    Check if an IP address is within any of the given networks.
    
    Args:
        ip: IP address to check
        networks: List of CIDR notations
        
    Returns:
        True if IP is in any network
    """
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        
        for network in networks:
            try:
                net = ipaddress.ip_network(network.strip(), strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                # Also check if network is a single IP
                try:
                    if ip_obj == ipaddress.ip_address(network.strip()):
                        return True
                except ValueError:
                    continue
        
        return False
    except ValueError:
        return False


def validate_target_in_scope(
    target_ip: str,
    mission_scope: List[str]
) -> None:
    """
    Validate that a target IP is within mission scope.
    
    Args:
        target_ip: Target IP address
        mission_scope: List of in-scope CIDRs/IPs
        
    Raises:
        TargetOutOfScopeError: If target is out of scope
    """
    if not is_ip_in_networks(target_ip, mission_scope):
        raise TargetOutOfScopeError(target_ip, mission_scope)


def parse_scope(scope_list: List[str]) -> Tuple[List[str], List[str]]:
    """
    Parse and validate a scope list.
    
    Args:
        scope_list: List of IPs, CIDRs, or hostnames
        
    Returns:
        Tuple of (valid_networks, hostnames)
    """
    networks = []
    hostnames = []
    
    for item in scope_list:
        item = item.strip()
        
        # Try as network/CIDR
        try:
            ipaddress.ip_network(item, strict=False)
            networks.append(item)
            continue
        except ValueError:
            pass
        
        # Try as IP address
        try:
            ipaddress.ip_address(item)
            networks.append(item)
            continue
        except ValueError:
            pass
        
        # Treat as hostname
        if validate_hostname(item):
            hostnames.append(item)
    
    return networks, hostnames


# ═══════════════════════════════════════════════════════════════
# UUID Validation
# ═══════════════════════════════════════════════════════════════

def validate_uuid(
    uuid_str: str,
    field_name: str = "id"
) -> UUID:
    """
    Validate and parse a UUID string.
    
    Args:
        uuid_str: UUID string
        field_name: Field name for error messages
        
    Returns:
        UUID object
        
    Raises:
        InvalidUUIDError: If UUID is invalid
    """
    try:
        return UUID(uuid_str.strip())
    except (ValueError, AttributeError) as e:
        raise InvalidUUIDError(uuid_str, field_name, details={"reason": str(e)})


def is_valid_uuid(uuid_str: str) -> bool:
    """Check if a string is a valid UUID."""
    try:
        UUID(uuid_str)
        return True
    except (ValueError, AttributeError):
        return False


# ═══════════════════════════════════════════════════════════════
# Hostname Validation
# ═══════════════════════════════════════════════════════════════

# RFC 1123 hostname pattern
HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)'  # Total length
    r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)'  # Labels
    r'(\.[A-Za-z0-9-]{1,63})*$'  # Additional labels
)

# Domain name pattern
DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
)


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.
    
    Args:
        hostname: Hostname string
        
    Returns:
        True if valid, False otherwise
    """
    if not hostname or len(hostname) > 253:
        return False
    
    # Remove trailing dot for validation
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    return bool(HOSTNAME_PATTERN.match(hostname))


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name.
    
    Args:
        domain: Domain name string
        
    Returns:
        True if valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False
    
    # Remove trailing dot for validation
    if domain.endswith('.'):
        domain = domain[:-1]
    
    return bool(DOMAIN_PATTERN.match(domain))


# ═══════════════════════════════════════════════════════════════
# Port Validation
# ═══════════════════════════════════════════════════════════════

def validate_port(port: int) -> int:
    """
    Validate a port number.
    
    Args:
        port: Port number
        
    Returns:
        Validated port number
        
    Raises:
        ValidationException: If port is invalid
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise ValidationException(
                f"Invalid port: {port}",
                field="port",
                value=port
            )
    
    if port < 1 or port > 65535:
        raise ValidationException(
            f"Port must be between 1 and 65535: {port}",
            field="port",
            value=port
        )
    
    return port


def validate_port_range(port_range: str) -> Tuple[int, int]:
    """
    Validate a port range string (e.g., "80-443").
    
    Args:
        port_range: Port range string
        
    Returns:
        Tuple of (start_port, end_port)
        
    Raises:
        ValidationException: If range is invalid
    """
    if '-' not in port_range:
        port = validate_port(int(port_range))
        return (port, port)
    
    try:
        parts = port_range.split('-')
        if len(parts) != 2:
            raise ValueError("Invalid format")
        
        start = validate_port(int(parts[0].strip()))
        end = validate_port(int(parts[1].strip()))
        
        if start > end:
            raise ValidationException(
                f"Start port must be <= end port: {port_range}",
                field="port_range",
                value=port_range
            )
        
        return (start, end)
        
    except ValueError as e:
        raise ValidationException(
            f"Invalid port range: {port_range}",
            field="port_range",
            value=port_range,
            details={"reason": str(e)}
        )


# ═══════════════════════════════════════════════════════════════
# String Validation & Sanitization
# ═══════════════════════════════════════════════════════════════

# Characters that might be dangerous in various contexts
DANGEROUS_CHARS = re.compile(r'[<>&\'"\x00-\x1f\x7f-\x9f]')

# Pattern for command injection
CMD_INJECTION_PATTERN = re.compile(r'[;|&`$(){}[\]\\]')

# Path traversal pattern
PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')


def sanitize_string(
    value: str,
    max_length: int = 1000,
    allow_newlines: bool = False,
    strip: bool = True
) -> str:
    """
    Sanitize a string input.
    
    Args:
        value: Input string
        max_length: Maximum allowed length
        allow_newlines: Whether to allow newline characters
        strip: Whether to strip whitespace
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        value = str(value)
    
    if strip:
        value = value.strip()
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Remove newlines if not allowed
    if not allow_newlines:
        value = value.replace('\n', ' ').replace('\r', ' ')
    
    # Truncate to max length
    if len(value) > max_length:
        value = value[:max_length]
    
    return value


def escape_html(value: str) -> str:
    """
    Escape HTML special characters.
    
    Args:
        value: Input string
        
    Returns:
        HTML-escaped string
    """
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c, c) for c in value)


def check_command_injection(value: str) -> bool:
    """
    Check if a string contains potential command injection characters.
    
    Args:
        value: Input string
        
    Returns:
        True if potential injection detected
    """
    return bool(CMD_INJECTION_PATTERN.search(value))


def check_path_traversal(value: str) -> bool:
    """
    Check if a string contains path traversal patterns.
    
    Args:
        value: Input string
        
    Returns:
        True if path traversal detected
    """
    return bool(PATH_TRAVERSAL_PATTERN.search(value))


def validate_safe_string(
    value: str,
    field_name: str = "input",
    max_length: int = 1000
) -> str:
    """
    Validate and sanitize a string, checking for injection patterns.
    
    Args:
        value: Input string
        field_name: Field name for error messages
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
        
    Raises:
        ValidationException: If dangerous patterns detected
    """
    value = sanitize_string(value, max_length=max_length)
    
    if check_command_injection(value):
        raise ValidationException(
            f"Invalid characters in {field_name}",
            field=field_name,
            value=value[:50] + "..." if len(value) > 50 else value,
            details={"reason": "potential_command_injection"}
        )
    
    if check_path_traversal(value):
        raise ValidationException(
            f"Invalid path pattern in {field_name}",
            field=field_name,
            value=value[:50] + "..." if len(value) > 50 else value,
            details={"reason": "potential_path_traversal"}
        )
    
    return value


# ═══════════════════════════════════════════════════════════════
# Name Validation
# ═══════════════════════════════════════════════════════════════

# Pattern for safe names (alphanumeric, underscores, hyphens, spaces)
SAFE_NAME_PATTERN = re.compile(r'^[A-Za-z0-9_\- ]+$')


def validate_name(
    name: str,
    field_name: str = "name",
    min_length: int = 1,
    max_length: int = 255
) -> str:
    """
    Validate a name field.
    
    Args:
        name: Name string
        field_name: Field name for error messages
        min_length: Minimum length
        max_length: Maximum length
        
    Returns:
        Validated name
        
    Raises:
        ValidationException: If name is invalid
    """
    name = sanitize_string(name, max_length=max_length)
    
    if len(name) < min_length:
        raise MissingRequiredFieldError(field_name, "name")
    
    if not SAFE_NAME_PATTERN.match(name):
        raise ValidationException(
            f"Invalid {field_name}: only alphanumeric, underscores, hyphens, and spaces allowed",
            field=field_name,
            value=name
        )
    
    return name


# ═══════════════════════════════════════════════════════════════
# CVE Validation
# ═══════════════════════════════════════════════════════════════

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')


def validate_cve(cve: str) -> str:
    """
    Validate a CVE identifier.
    
    Args:
        cve: CVE string (e.g., "CVE-2021-44228")
        
    Returns:
        Normalized CVE string
        
    Raises:
        ValidationException: If CVE is invalid
    """
    cve = cve.strip().upper()
    
    if not CVE_PATTERN.match(cve):
        raise ValidationException(
            f"Invalid CVE format: {cve}",
            field="cve",
            value=cve,
            details={"expected_format": "CVE-YYYY-NNNNN"}
        )
    
    return cve


def is_valid_cve(cve: str) -> bool:
    """Check if a string is a valid CVE identifier."""
    return bool(CVE_PATTERN.match(cve.strip().upper()))


# ═══════════════════════════════════════════════════════════════
# CVSS Validation
# ═══════════════════════════════════════════════════════════════

def validate_cvss(score: float) -> float:
    """
    Validate a CVSS score.
    
    Args:
        score: CVSS score (0.0 to 10.0)
        
    Returns:
        Validated score
        
    Raises:
        ValidationException: If score is invalid
    """
    try:
        score = float(score)
    except (ValueError, TypeError):
        raise ValidationException(
            f"Invalid CVSS score: {score}",
            field="cvss",
            value=score
        )
    
    if score < 0.0 or score > 10.0:
        raise ValidationException(
            f"CVSS score must be between 0.0 and 10.0: {score}",
            field="cvss",
            value=score
        )
    
    return round(score, 1)


# ═══════════════════════════════════════════════════════════════
# Mission Scope Validation
# ═══════════════════════════════════════════════════════════════

def validate_scope(scope: List[str]) -> List[str]:
    """
    Validate a mission scope list.
    
    Args:
        scope: List of scope entries (IPs, CIDRs, hostnames)
        
    Returns:
        Validated scope list
        
    Raises:
        ValidationException: If scope is invalid
    """
    if not scope:
        raise MissingRequiredFieldError("scope", "mission")
    
    validated = []
    errors = []
    
    for i, entry in enumerate(scope):
        entry = entry.strip()
        
        if not entry:
            continue
        
        # Try as IP
        try:
            ipaddress.ip_address(entry)
            validated.append(entry)
            continue
        except ValueError:
            pass
        
        # Try as CIDR
        try:
            ipaddress.ip_network(entry, strict=False)
            validated.append(entry)
            continue
        except ValueError:
            pass
        
        # Try as hostname/domain
        if validate_hostname(entry) or validate_domain(entry):
            validated.append(entry)
            continue
        
        errors.append(f"Invalid scope entry at index {i}: {entry}")
    
    if errors:
        raise ValidationException(
            f"Invalid scope entries: {len(errors)} errors",
            field="scope",
            details={"errors": errors}
        )
    
    if not validated:
        raise ValidationException(
            "Scope must contain at least one valid entry",
            field="scope"
        )
    
    return validated


# ═══════════════════════════════════════════════════════════════
# Enum Validation
# ═══════════════════════════════════════════════════════════════

def validate_enum(
    value: str,
    enum_class,
    field_name: str = "value"
) -> Any:
    """
    Validate an enum value.
    
    Args:
        value: Value to validate
        enum_class: Enum class to validate against
        field_name: Field name for error messages
        
    Returns:
        Enum member
        
    Raises:
        ValidationException: If value is not a valid enum member
    """
    try:
        return enum_class(value)
    except ValueError:
        valid_values = [e.value for e in enum_class]
        raise ValidationException(
            f"Invalid {field_name}: {value}",
            field=field_name,
            value=value,
            details={"valid_values": valid_values}
        )


# ═══════════════════════════════════════════════════════════════
# Pydantic Model Validation
# ═══════════════════════════════════════════════════════════════

def validate_model(
    data: Dict[str, Any],
    model_class: type,
    partial: bool = False
) -> BaseModel:
    """
    Validate data against a Pydantic model.
    
    Args:
        data: Data to validate
        model_class: Pydantic model class
        partial: If True, allow missing required fields
        
    Returns:
        Validated model instance
        
    Raises:
        ValidationException: If validation fails
    """
    try:
        if partial:
            # Create with defaults for missing fields
            return model_class.model_construct(**data)
        return model_class(**data)
    except ValidationError as e:
        errors = []
        for error in e.errors():
            field = '.'.join(str(loc) for loc in error['loc'])
            errors.append({
                'field': field,
                'message': error['msg'],
                'type': error['type']
            })
        
        raise ValidationException(
            f"Validation failed for {model_class.__name__}",
            details={"validation_errors": errors}
        )


# ═══════════════════════════════════════════════════════════════
# Decorator for Input Validation
# ═══════════════════════════════════════════════════════════════

def validate_inputs(**validators):
    """
    Decorator to validate function inputs.
    
    Args:
        **validators: Mapping of parameter names to validator functions
        
    Usage:
        @validate_inputs(
            ip=validate_ip_address,
            port=validate_port
        )
        def process_target(ip: str, port: int):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get function signature
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            
            # Validate each parameter
            for param_name, validator in validators.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    if value is not None:
                        bound.arguments[param_name] = validator(value)
            
            return func(*bound.args, **bound.kwargs)
        
        return wrapper
    
    return decorator


def validate_inputs_async(**validators):
    """Async version of validate_inputs decorator."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            
            for param_name, validator in validators.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    if value is not None:
                        bound.arguments[param_name] = validator(value)
            
            return await func(*bound.args, **bound.kwargs)
        
        return wrapper
    
    return decorator
