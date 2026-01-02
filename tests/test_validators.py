# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Validator Tests
# Comprehensive tests for input validation
# ═══════════════════════════════════════════════════════════════

import pytest
from uuid import uuid4

from src.core.validators import (
    # IP validation
    validate_ip_address,
    validate_ip_network,
    is_ip_in_networks,
    validate_target_in_scope,
    parse_scope,
    
    # UUID validation
    validate_uuid,
    is_valid_uuid,
    
    # Hostname validation
    validate_hostname,
    validate_domain,
    
    # Port validation
    validate_port,
    validate_port_range,
    
    # String validation
    sanitize_string,
    escape_html,
    check_command_injection,
    check_path_traversal,
    validate_safe_string,
    validate_name,
    
    # CVE validation
    validate_cve,
    is_valid_cve,
    
    # CVSS validation
    validate_cvss,
    
    # Scope validation
    validate_scope,
    
    # Enum validation
    validate_enum,
    
    # Decorator
    validate_inputs,
)

from src.core.exceptions import (
    InvalidIPAddressError,
    InvalidCIDRError,
    InvalidUUIDError,
    TargetOutOfScopeError,
    ValidationException,
    MissingRequiredFieldError,
)


# ═══════════════════════════════════════════════════════════════
# IP Address Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestIPAddressValidation:
    """Tests for IP address validation."""
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert validate_ip_address("10.0.0.1") == "10.0.0.1"
        assert validate_ip_address("127.0.0.1") == "127.0.0.1"
        assert validate_ip_address("255.255.255.255") == "255.255.255.255"
        assert validate_ip_address("0.0.0.0") == "0.0.0.0"
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip_address("::1") == "::1"
        assert validate_ip_address("2001:db8::1") == "2001:db8::1"
        assert validate_ip_address("fe80::1") == "fe80::1"
    
    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        assert validate_ip_address("  192.168.1.1  ") == "192.168.1.1"
    
    def test_invalid_ip_raises_error(self):
        """Test that invalid IPs raise errors."""
        invalid_ips = [
            "not.an.ip",
            "192.168.1.256",
            "192.168.1",
            "192.168.1.1.1",
            "",
            "abc",
            "192.168.1.-1",
        ]
        
        for ip in invalid_ips:
            with pytest.raises(InvalidIPAddressError):
                validate_ip_address(ip)


class TestIPNetworkValidation:
    """Tests for CIDR network validation."""
    
    def test_valid_cidr(self):
        """Test valid CIDR notation."""
        network = validate_ip_network("192.168.1.0/24")
        assert str(network) == "192.168.1.0/24"
        
        network = validate_ip_network("10.0.0.0/8")
        assert str(network) == "10.0.0.0/8"
    
    def test_non_strict_mode(self):
        """Test non-strict mode allows host bits set."""
        network = validate_ip_network("192.168.1.5/24", strict=False)
        assert str(network) == "192.168.1.0/24"
    
    def test_invalid_cidr_raises_error(self):
        """Test that invalid CIDRs raise errors."""
        with pytest.raises(InvalidCIDRError):
            validate_ip_network("not.a.cidr/24")
        
        with pytest.raises(InvalidCIDRError):
            validate_ip_network("192.168.1.0/99")


class TestIPInNetworks:
    """Tests for IP in networks check."""
    
    def test_ip_in_network(self):
        """Test IP in network detection."""
        assert is_ip_in_networks("192.168.1.50", ["192.168.1.0/24"]) is True
        assert is_ip_in_networks("192.168.2.50", ["192.168.1.0/24"]) is False
    
    def test_ip_in_multiple_networks(self):
        """Test IP in multiple networks."""
        networks = ["10.0.0.0/8", "192.168.0.0/16"]
        assert is_ip_in_networks("10.5.5.5", networks) is True
        assert is_ip_in_networks("192.168.50.50", networks) is True
        assert is_ip_in_networks("172.16.0.1", networks) is False
    
    def test_single_ip_in_scope(self):
        """Test single IP matching."""
        assert is_ip_in_networks("192.168.1.1", ["192.168.1.1"]) is True
        assert is_ip_in_networks("192.168.1.2", ["192.168.1.1"]) is False


class TestTargetInScope:
    """Tests for target scope validation."""
    
    def test_in_scope_passes(self):
        """Test that in-scope targets pass."""
        validate_target_in_scope("192.168.1.50", ["192.168.1.0/24"])
        # Should not raise
    
    def test_out_of_scope_raises(self):
        """Test that out-of-scope targets raise error."""
        with pytest.raises(TargetOutOfScopeError) as exc_info:
            validate_target_in_scope("10.0.0.1", ["192.168.1.0/24"])
        
        assert exc_info.value.target_ip == "10.0.0.1"


# ═══════════════════════════════════════════════════════════════
# UUID Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestUUIDValidation:
    """Tests for UUID validation."""
    
    def test_valid_uuid(self):
        """Test valid UUID."""
        test_uuid = str(uuid4())
        result = validate_uuid(test_uuid)
        assert str(result) == test_uuid
    
    def test_valid_uuid_with_whitespace(self):
        """Test UUID with whitespace."""
        test_uuid = str(uuid4())
        result = validate_uuid(f"  {test_uuid}  ")
        assert str(result) == test_uuid
    
    def test_invalid_uuid_raises_error(self):
        """Test that invalid UUIDs raise errors."""
        with pytest.raises(InvalidUUIDError):
            validate_uuid("not-a-uuid")
        
        with pytest.raises(InvalidUUIDError):
            validate_uuid("12345")
    
    def test_is_valid_uuid(self):
        """Test is_valid_uuid helper."""
        assert is_valid_uuid(str(uuid4())) is True
        assert is_valid_uuid("not-a-uuid") is False


# ═══════════════════════════════════════════════════════════════
# Hostname Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestHostnameValidation:
    """Tests for hostname validation."""
    
    def test_valid_hostnames(self):
        """Test valid hostnames."""
        assert validate_hostname("localhost") is True
        assert validate_hostname("server1") is True
        assert validate_hostname("web-server") is True
        assert validate_hostname("db.internal") is True
        assert validate_hostname("app.company.local") is True
    
    def test_invalid_hostnames(self):
        """Test invalid hostnames."""
        assert validate_hostname("") is False
        assert validate_hostname("-invalid") is False
        assert validate_hostname("invalid-") is False
        assert validate_hostname("a" * 300) is False  # Too long
    
    def test_valid_domains(self):
        """Test valid domain names."""
        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("a.b.c.d.example.com") is True
    
    def test_invalid_domains(self):
        """Test invalid domain names."""
        assert validate_domain("") is False
        assert validate_domain(".example.com") is False


# ═══════════════════════════════════════════════════════════════
# Port Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestPortValidation:
    """Tests for port validation."""
    
    def test_valid_ports(self):
        """Test valid port numbers."""
        assert validate_port(80) == 80
        assert validate_port(443) == 443
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535
    
    def test_port_from_string(self):
        """Test port from string."""
        assert validate_port("80") == 80
    
    def test_invalid_ports_raise_error(self):
        """Test that invalid ports raise errors."""
        with pytest.raises(ValidationException):
            validate_port(0)
        
        with pytest.raises(ValidationException):
            validate_port(65536)
        
        with pytest.raises(ValidationException):
            validate_port(-1)
        
        with pytest.raises(ValidationException):
            validate_port("abc")


class TestPortRangeValidation:
    """Tests for port range validation."""
    
    def test_valid_ranges(self):
        """Test valid port ranges."""
        assert validate_port_range("80-443") == (80, 443)
        assert validate_port_range("1-65535") == (1, 65535)
    
    def test_single_port(self):
        """Test single port as range."""
        assert validate_port_range("80") == (80, 80)
    
    def test_invalid_range_raises_error(self):
        """Test that invalid ranges raise errors."""
        with pytest.raises(ValidationException):
            validate_port_range("443-80")  # Start > End
        
        with pytest.raises(ValidationException):
            validate_port_range("abc-def")


# ═══════════════════════════════════════════════════════════════
# String Sanitization Tests
# ═══════════════════════════════════════════════════════════════

class TestStringSanitization:
    """Tests for string sanitization."""
    
    def test_basic_sanitization(self):
        """Test basic string sanitization."""
        assert sanitize_string("  hello  ") == "hello"
        assert sanitize_string("hello\x00world") == "helloworld"
    
    def test_newline_handling(self):
        """Test newline handling."""
        assert sanitize_string("hello\nworld") == "hello world"
        assert sanitize_string("hello\nworld", allow_newlines=True) == "hello\nworld"
    
    def test_max_length(self):
        """Test max length truncation."""
        long_string = "a" * 100
        assert len(sanitize_string(long_string, max_length=50)) == 50
    
    def test_html_escape(self):
        """Test HTML escaping."""
        assert escape_html("<script>") == "&lt;script&gt;"
        assert escape_html("a & b") == "a &amp; b"
        assert escape_html('"quotes"') == "&quot;quotes&quot;"


class TestInjectionDetection:
    """Tests for injection pattern detection."""
    
    def test_command_injection_detection(self):
        """Test command injection detection."""
        assert check_command_injection("normal string") is False
        assert check_command_injection("hello; ls") is True
        assert check_command_injection("cmd | grep") is True
        assert check_command_injection("$(whoami)") is True
        assert check_command_injection("`id`") is True
    
    def test_path_traversal_detection(self):
        """Test path traversal detection."""
        assert check_path_traversal("normal/path") is False
        assert check_path_traversal("../etc/passwd") is True
        assert check_path_traversal("..\\windows\\system32") is True
    
    def test_validate_safe_string(self):
        """Test safe string validation."""
        assert validate_safe_string("normal string") == "normal string"
        
        with pytest.raises(ValidationException):
            validate_safe_string("hello; rm -rf /")
        
        with pytest.raises(ValidationException):
            validate_safe_string("../../../etc/passwd")


class TestNameValidation:
    """Tests for name field validation."""
    
    def test_valid_names(self):
        """Test valid names."""
        assert validate_name("MyProject") == "MyProject"
        assert validate_name("project-1") == "project-1"
        assert validate_name("project_2") == "project_2"
        assert validate_name("My Project Name") == "My Project Name"
    
    def test_invalid_names(self):
        """Test invalid names."""
        with pytest.raises(ValidationException):
            validate_name("project@123")
        
        with pytest.raises(ValidationException):
            validate_name("project<>name")
    
    def test_empty_name(self):
        """Test empty name."""
        with pytest.raises(MissingRequiredFieldError):
            validate_name("")


# ═══════════════════════════════════════════════════════════════
# CVE Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestCVEValidation:
    """Tests for CVE identifier validation."""
    
    def test_valid_cve(self):
        """Test valid CVE identifiers."""
        assert validate_cve("CVE-2021-44228") == "CVE-2021-44228"
        assert validate_cve("cve-2021-44228") == "CVE-2021-44228"  # Normalized
        assert validate_cve("CVE-2020-1234") == "CVE-2020-1234"
        assert validate_cve("CVE-2025-12345678") == "CVE-2025-12345678"  # Long ID
    
    def test_invalid_cve(self):
        """Test invalid CVE identifiers."""
        with pytest.raises(ValidationException):
            validate_cve("CVE-21-44228")  # 2-digit year
        
        with pytest.raises(ValidationException):
            validate_cve("CVE-2021-123")  # 3-digit ID
        
        with pytest.raises(ValidationException):
            validate_cve("not-a-cve")
    
    def test_is_valid_cve(self):
        """Test is_valid_cve helper."""
        assert is_valid_cve("CVE-2021-44228") is True
        assert is_valid_cve("not-a-cve") is False


# ═══════════════════════════════════════════════════════════════
# CVSS Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestCVSSValidation:
    """Tests for CVSS score validation."""
    
    def test_valid_scores(self):
        """Test valid CVSS scores."""
        assert validate_cvss(0.0) == 0.0
        assert validate_cvss(5.5) == 5.5
        assert validate_cvss(10.0) == 10.0
    
    def test_score_rounding(self):
        """Test score rounding."""
        # Python uses banker's rounding, so 5.55 rounds to 5.5
        assert validate_cvss(5.55) == 5.5  # Banker's rounding
        assert validate_cvss(7.14) == 7.1
    
    def test_invalid_scores(self):
        """Test invalid CVSS scores."""
        with pytest.raises(ValidationException):
            validate_cvss(-0.1)
        
        with pytest.raises(ValidationException):
            validate_cvss(10.1)
        
        with pytest.raises(ValidationException):
            validate_cvss("not-a-number")


# ═══════════════════════════════════════════════════════════════
# Scope Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestScopeValidation:
    """Tests for mission scope validation."""
    
    def test_valid_scope(self):
        """Test valid scope list."""
        scope = validate_scope(["192.168.1.0/24", "10.0.0.1", "example.com"])
        assert len(scope) == 3
    
    def test_empty_scope_raises(self):
        """Test that empty scope raises error."""
        with pytest.raises(MissingRequiredFieldError):
            validate_scope([])
    
    def test_scope_with_whitespace(self):
        """Test scope with whitespace in entries."""
        scope = validate_scope(["  192.168.1.0/24  ", " 10.0.0.1 "])
        assert "192.168.1.0/24" in scope
        assert "10.0.0.1" in scope
    
    def test_mixed_scope(self):
        """Test mixed scope with IPs, CIDRs, and hostnames."""
        scope = validate_scope([
            "192.168.1.0/24",
            "10.0.0.1",
            "web.example.com",
            "db.internal"
        ])
        assert len(scope) == 4


class TestParseScope:
    """Tests for scope parsing."""
    
    def test_parse_mixed_scope(self):
        """Test parsing mixed scope."""
        networks, hostnames = parse_scope([
            "192.168.1.0/24",
            "10.0.0.1",
            "example.com"
        ])
        
        assert len(networks) == 2
        assert len(hostnames) == 1
        assert "example.com" in hostnames


# ═══════════════════════════════════════════════════════════════
# Enum Validation Tests
# ═══════════════════════════════════════════════════════════════

class TestEnumValidation:
    """Tests for enum validation."""
    
    def test_valid_enum_value(self):
        """Test valid enum value."""
        from src.core.models import MissionStatus
        
        result = validate_enum("running", MissionStatus)
        assert result == MissionStatus.RUNNING
    
    def test_invalid_enum_value(self):
        """Test invalid enum value."""
        from src.core.models import MissionStatus
        
        with pytest.raises(ValidationException) as exc_info:
            validate_enum("invalid_status", MissionStatus)
        
        assert "valid_values" in exc_info.value.details


# ═══════════════════════════════════════════════════════════════
# Input Validation Decorator Tests
# ═══════════════════════════════════════════════════════════════

class TestValidateInputsDecorator:
    """Tests for input validation decorator."""
    
    def test_decorator_validates(self):
        """Test decorator validates inputs."""
        @validate_inputs(ip=validate_ip_address, port=validate_port)
        def process(ip: str, port: int):
            return f"{ip}:{port}"
        
        result = process("192.168.1.1", 80)
        assert result == "192.168.1.1:80"
    
    def test_decorator_raises_on_invalid(self):
        """Test decorator raises on invalid input."""
        @validate_inputs(ip=validate_ip_address)
        def process(ip: str):
            return ip
        
        with pytest.raises(InvalidIPAddressError):
            process("not.an.ip")
    
    def test_decorator_handles_none(self):
        """Test decorator handles None values."""
        @validate_inputs(ip=validate_ip_address)
        def process(ip: str = None):
            return ip
        
        result = process(None)
        assert result is None


# ═══════════════════════════════════════════════════════════════
# Edge Cases and Negative Tests
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge case and boundary tests."""
    
    def test_empty_string_inputs(self):
        """Test empty string handling."""
        with pytest.raises(InvalidIPAddressError):
            validate_ip_address("")
        
        with pytest.raises(InvalidUUIDError):
            validate_uuid("")
    
    def test_none_inputs(self):
        """Test None input handling."""
        with pytest.raises((InvalidIPAddressError, AttributeError)):
            validate_ip_address(None)
    
    def test_unicode_inputs(self):
        """Test Unicode input handling."""
        # Unicode should fail for IP
        with pytest.raises(InvalidIPAddressError):
            validate_ip_address("١٩٢.١٦٨.١.١")  # Arabic numerals
    
    def test_very_long_inputs(self):
        """Test very long input handling."""
        long_string = "a" * 10000
        sanitized = sanitize_string(long_string, max_length=100)
        assert len(sanitized) == 100
    
    def test_special_characters(self):
        """Test special character handling."""
        # These should be detected as injection attempts
        assert check_command_injection("test && whoami") is True
        assert check_command_injection("test || true") is True
        assert check_command_injection("test `date`") is True
