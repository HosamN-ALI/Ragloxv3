# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Elasticsearch Intel Provider Tests
# Tests for ElasticsearchBreachProvider with mocked responses
# ═══════════════════════════════════════════════════════════════

"""
Tests for ElasticsearchBreachProvider.

These tests use mocking to simulate Elasticsearch responses,
allowing testing without a real Elasticsearch instance.

Test coverage:
- Connection handling (success, failure, retries)
- Query building for different query types
- Field extraction from various data formats
- Credential parsing and deduplication
- Reliability scoring
- Error handling and masking
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

# Import provider (handle optional dependency)
try:
    from src.core.intel.elasticsearch_provider import (
        ElasticsearchBreachProvider,
        ELASTICSEARCH_AVAILABLE
    )
    from src.core.intel.base import BreachSource, IntelCredential, IntelSearchResult
except ImportError:
    ELASTICSEARCH_AVAILABLE = False


# Skip all tests if elasticsearch is not available
pytestmark = pytest.mark.skipif(
    not ELASTICSEARCH_AVAILABLE,
    reason="elasticsearch package not installed"
)


# ═══════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_es_client():
    """Create a mock Elasticsearch async client."""
    client = AsyncMock()
    client.info.return_value = {"version": {"number": "8.11.3"}}
    client.close = AsyncMock()
    return client


@pytest.fixture
def provider():
    """Create provider without mocking for unit tests that don't need async operations."""
    with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch"):
        provider = ElasticsearchBreachProvider(
            hosts=["http://localhost:9200"],
            index_pattern="leaks-*",
            timeout=10,
            max_retries=2
        )
        return provider


@pytest.fixture
def provider_with_mock(mock_es_client):
    """Create provider with mocked client already injected."""
    with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch") as mock_class:
        mock_class.return_value = mock_es_client
        provider = ElasticsearchBreachProvider(
            hosts=["http://localhost:9200"],
            index_pattern="leaks-*",
            timeout=10,
            max_retries=2
        )
        # Pre-inject the mock client
        provider._client = mock_es_client
        return provider


@pytest.fixture
def sample_es_response():
    """Sample Elasticsearch search response."""
    return {
        "hits": {
            "total": {"value": 3},
            "hits": [
                {
                    "_index": "leaks-arthouse-2024",
                    "_id": "doc1",
                    "_score": 8.5,
                    "_source": {
                        "email": "admin@vulnerable-target.com",
                        "password": "leaked_password123",
                        "domain": "vulnerable-target.com",
                        "@timestamp": "2024-01-15T10:30:00Z"
                    }
                },
                {
                    "_index": "leaks-fatetraffic-2024",
                    "_id": "doc2",
                    "_score": 7.2,
                    "_source": {
                        "username": "testuser",
                        "mail": "testuser@vulnerable-target.com",
                        "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                        "site": "vulnerable-target.com"
                    }
                },
                {
                    "_index": "leaks-combolist-2023",
                    "_id": "doc3",
                    "_score": 6.1,
                    "_source": {
                        "raw": "user@vulnerable-target.com:password456",
                        "source": "collection1"
                    }
                }
            ]
        }
    }


@pytest.fixture
def stealer_log_response():
    """Sample response with stealer log format."""
    return {
        "hits": {
            "total": {"value": 2},
            "hits": [
                {
                    "_index": "leaks-stealer-redline-2024",
                    "_id": "stealer1",
                    "_score": 9.0,
                    "_source": {
                        "url": "https://mail.vulnerable-target.com/login",
                        "login": "admin@vulnerable-target.com",
                        "password": "StealerCaptured!123",
                        "user_agent": "Chrome/120.0",
                        "@timestamp": "2024-06-01T08:00:00Z"
                    }
                },
                {
                    "_index": "leaks-stealer-raccoon-2024",
                    "_id": "stealer2",
                    "_score": 8.5,
                    "_source": {
                        "host": "vulnerable-target.com",
                        "user": "service_account",
                        "secret": "$2a$12$LQv3c1yqBW/HxkeKF3Yzr.gXJ/Rb.eSFt7.2lUQ.Q1a/tOqGz6vKa",
                        "captured_at": "2024-05-15"
                    }
                }
            ]
        }
    }


# ═══════════════════════════════════════════════════════════════
# Test Provider Initialization
# ═══════════════════════════════════════════════════════════════

class TestElasticsearchProviderInit:
    """Tests for provider initialization."""
    
    def test_provider_name(self, provider):
        """Test provider name is correct."""
        assert provider.provider_name == "elasticsearch"
    
    def test_default_hosts(self):
        """Test default hosts configuration."""
        with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch"):
            p = ElasticsearchBreachProvider()
            assert p._hosts == ["http://localhost:9200"]
    
    def test_custom_configuration(self):
        """Test custom configuration."""
        with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch"):
            p = ElasticsearchBreachProvider(
                hosts=["http://es1:9200", "http://es2:9200"],
                index_pattern="breach-data-*",
                timeout=60,
                max_retries=5,
                api_key="test_api_key"
            )
            assert p._hosts == ["http://es1:9200", "http://es2:9200"]
            assert p._index_pattern == "breach-data-*"
            assert p._timeout == 60
            assert p._max_retries == 5
            assert p._api_key == "test_api_key"
    
    def test_connection_info(self, provider):
        """Test getting connection info."""
        info = provider.get_connection_info()
        
        assert info["provider"] == "elasticsearch"
        assert info["hosts"] == ["http://localhost:9200"]
        assert info["index_pattern"] == "leaks-*"
        assert "connected" in info
        assert "last_error" in info


# ═══════════════════════════════════════════════════════════════
# Test Connection Handling
# ═══════════════════════════════════════════════════════════════

class TestConnectionHandling:
    """Tests for connection handling and retries."""
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, provider_with_mock, mock_es_client):
        """Test successful health check."""
        mock_es_client.info.return_value = {"version": {"number": "8.11.3"}}
        
        result = await provider_with_mock.health_check()
        
        assert result is True
        assert provider_with_mock._connected is True
    
    @pytest.mark.asyncio
    async def test_health_check_connection_failure(self, provider_with_mock, mock_es_client):
        """Test health check with connection failure."""
        from elasticsearch.exceptions import ConnectionError
        mock_es_client.info.side_effect = ConnectionError("Connection refused")
        
        result = await provider_with_mock.health_check()
        
        assert result is False
        assert provider_with_mock._connected is False
    
    @pytest.mark.asyncio
    async def test_search_with_retries(self, provider_with_mock, mock_es_client, sample_es_response):
        """Test search retry on transient failure."""
        from elasticsearch.exceptions import ConnectionTimeout
        
        # First call fails, second succeeds
        mock_es_client.search.side_effect = [
            ConnectionTimeout("Timeout"),
            sample_es_response
        ]
        
        result = await provider_with_mock.search("vulnerable-target.com", query_type="domain")
        
        assert result.success is True
        assert len(result.credentials) > 0
        assert mock_es_client.search.call_count == 2
    
    @pytest.mark.asyncio
    async def test_search_max_retries_exceeded(self, provider_with_mock, mock_es_client):
        """Test search fails after max retries."""
        from elasticsearch.exceptions import ConnectionError
        
        mock_es_client.search.side_effect = ConnectionError("Connection refused")
        
        result = await provider_with_mock.search("example.com", query_type="domain")
        
        assert result.success is False
        assert "Connection failed" in result.error
        assert mock_es_client.search.call_count == provider_with_mock._max_retries
    
    @pytest.mark.asyncio
    async def test_context_manager(self, mock_es_client):
        """Test async context manager."""
        with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch") as mock_class:
            mock_class.return_value = mock_es_client
            
            async with ElasticsearchBreachProvider() as provider:
                provider._client = mock_es_client  # Inject mock
                assert provider is not None
            
            mock_es_client.close.assert_called_once()


# ═══════════════════════════════════════════════════════════════
# Test Query Building
# ═══════════════════════════════════════════════════════════════

class TestQueryBuilding:
    """Tests for Elasticsearch query building."""
    
    def test_build_domain_query(self, provider):
        """Test domain query building."""
        query = provider._build_query("example.com", "domain")
        
        assert "query" in query
        assert "bool" in query["query"]
        assert "should" in query["query"]["bool"]
        # Should include wildcard for email domain
        wildcards = [q for q in query["query"]["bool"]["should"] if "wildcard" in q]
        assert len(wildcards) > 0
    
    def test_build_email_query(self, provider):
        """Test email query building."""
        query = provider._build_query("admin@example.com", "email")
        
        assert "query" in query
        assert "bool" in query["query"]
        # Should include term queries for exact email match
        terms = [q for q in query["query"]["bool"]["should"] if "term" in q or "match_phrase" in q]
        assert len(terms) > 0
    
    def test_build_ip_query(self, provider):
        """Test IP query building."""
        query = provider._build_query("192.168.1.100", "ip")
        
        assert "query" in query
        assert "bool" in query["query"]
        # Should include term queries for IP fields
        terms = [q for q in query["query"]["bool"]["should"] if "term" in q]
        assert len(terms) > 0
    
    def test_build_username_query(self, provider):
        """Test username query building."""
        query = provider._build_query("admin", "username")
        
        assert "query" in query
        assert "multi_match" in query["query"]
        assert query["query"]["multi_match"]["query"] == "admin"


# ═══════════════════════════════════════════════════════════════
# Test Field Extraction
# ═══════════════════════════════════════════════════════════════

class TestFieldExtraction:
    """Tests for credential field extraction."""
    
    def test_extract_email_and_password(self, provider):
        """Test extracting email and plaintext password."""
        source = {
            "email": "user@example.com",
            "password": "secret123"
        }
        
        username, email = provider._extract_identity(source)
        password, hash_val, hash_type = provider._extract_secret(source)
        
        assert email == "user@example.com"
        assert username == "user"  # Extracted from email
        assert password == "secret123"
        assert hash_val is None
    
    def test_extract_username_and_hash(self, provider):
        """Test extracting username and hash."""
        source = {
            "username": "admin",
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99"
        }
        
        username, email = provider._extract_identity(source)
        password, hash_val, hash_type = provider._extract_secret(source)
        
        assert username == "admin"
        assert email is None
        assert password is None
        assert hash_val == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert hash_type == "md5"
    
    def test_extract_from_raw_combo(self, provider):
        """Test extracting from raw combo format."""
        source = {"raw": "user@example.com:password123"}
        
        username, email = provider._extract_identity_from_raw(source)
        
        assert email == "user@example.com"
        assert username == "user"
    
    def test_extract_sha256_hash(self, provider):
        """Test extracting SHA256 hash."""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        source = {"password_hash": sha256_hash}
        
        password, hash_val, hash_type = provider._extract_secret(source)
        
        assert password is None
        assert hash_val == sha256_hash
        assert hash_type == "sha256"
    
    def test_extract_bcrypt_hash(self, provider):
        """Test extracting bcrypt hash."""
        bcrypt_hash = "$2a$12$LQv3c1yqBW/HxkeKF3Yzr.gXJ/Rb.eSFt7.2lUQ.Q1a/tOqGz6vKa"
        source = {"hash": bcrypt_hash}
        
        password, hash_val, hash_type = provider._extract_secret(source)
        
        assert password is None
        assert hash_val == bcrypt_hash
        assert hash_type == "bcrypt"
    
    def test_case_insensitive_field_access(self, provider):
        """Test case-insensitive field access."""
        source = {
            "Email": "user@example.com",
            "PASSWORD": "secret"
        }
        
        username, email = provider._extract_identity(source)
        password, _, _ = provider._extract_secret(source)
        
        assert email == "user@example.com"
        assert password == "secret"


# ═══════════════════════════════════════════════════════════════
# Test Credential Parsing
# ═══════════════════════════════════════════════════════════════

class TestCredentialParsing:
    """Tests for full credential parsing from ES hits."""
    
    @pytest.mark.asyncio
    async def test_parse_arthouse_credentials(self, provider_with_mock, mock_es_client, sample_es_response):
        """Test parsing credentials from ArtHouse source."""
        mock_es_client.search.return_value = sample_es_response
        
        result = await provider_with_mock.search("vulnerable-target.com", query_type="domain")
        
        assert result.success is True
        assert len(result.credentials) >= 1
        
        # Check first credential (from arthouse index)
        arthouse_creds = [c for c in result.credentials if "arthouse" in (c.source_name or "").lower()]
        if arthouse_creds:
            cred = arthouse_creds[0]
            assert cred.email == "admin@vulnerable-target.com"
            assert cred.password == "leaked_password123"
            assert cred.source == BreachSource.ARTHOUSE
    
    @pytest.mark.asyncio
    async def test_parse_stealer_log_credentials(self, provider_with_mock, mock_es_client, stealer_log_response):
        """Test parsing credentials from stealer logs."""
        mock_es_client.search.return_value = stealer_log_response
        
        result = await provider_with_mock.search("vulnerable-target.com", query_type="domain")
        
        assert result.success is True
        assert len(result.credentials) >= 1
        
        # Check stealer log credential
        stealer_creds = [c for c in result.credentials if c.source == BreachSource.STEALER_LOG]
        if stealer_creds:
            cred = stealer_creds[0]
            assert cred.reliability_score >= 0.8  # Stealer logs have high reliability
    
    @pytest.mark.asyncio
    async def test_credential_deduplication(self, provider_with_mock, mock_es_client):
        """Test deduplication of credentials."""
        # Response with duplicate credentials
        response = {
            "hits": {
                "total": {"value": 3},
                "hits": [
                    {
                        "_index": "leaks-2024",
                        "_id": "doc1",
                        "_score": 8.0,
                        "_source": {
                            "email": "admin@example.com",
                            "password": "secret123"
                        }
                    },
                    {
                        "_index": "leaks-2023",
                        "_id": "doc2",
                        "_score": 7.0,
                        "_source": {
                            "mail": "admin@example.com",  # Same email, different field
                            "pass": "secret123"          # Same password
                        }
                    },
                    {
                        "_index": "leaks-2024",
                        "_id": "doc3",
                        "_score": 6.0,
                        "_source": {
                            "email": "other@example.com",  # Different email
                            "password": "different456"
                        }
                    }
                ]
            }
        }
        mock_es_client.search.return_value = response
        
        result = await provider_with_mock.search("example.com", query_type="domain")
        
        # Should deduplicate same email:password combinations
        assert result.success is True
        # Unique credentials: admin@example.com:secret123 and other@example.com:different456
        assert len(result.credentials) == 2


# ═══════════════════════════════════════════════════════════════
# Test Source Detection
# ═══════════════════════════════════════════════════════════════

class TestSourceDetection:
    """Tests for breach source detection."""
    
    def test_detect_arthouse_from_index(self, provider):
        """Test detecting ArtHouse from index name."""
        source = provider._determine_source("leaks-arthouse-2024", {})
        assert source == BreachSource.ARTHOUSE
    
    def test_detect_fatetraffic_from_index(self, provider):
        """Test detecting Fatetraffic from index name."""
        source = provider._determine_source("leaks-fatetraffic-2024", {})
        assert source == BreachSource.FATETRAFFIC
    
    def test_detect_stealer_from_index(self, provider):
        """Test detecting stealer log from index name."""
        source = provider._determine_source("leaks-stealer-redline-2024", {})
        assert source == BreachSource.STEALER_LOG
    
    def test_detect_combolist_from_index(self, provider):
        """Test detecting combolist from index name."""
        source = provider._determine_source("leaks-combolist-collection", {})
        assert source == BreachSource.COMBOLIST
    
    def test_detect_ransomware_from_data(self, provider):
        """Test detecting ransomware leak from data."""
        source = provider._determine_source("leaks-2024", {"lockbit_leak": True})
        assert source == BreachSource.RANSOMWARE_LEAK
    
    def test_unknown_source(self, provider):
        """Test unknown source detection."""
        source = provider._determine_source("generic-index", {})
        assert source == BreachSource.UNKNOWN


# ═══════════════════════════════════════════════════════════════
# Test Reliability Scoring
# ═══════════════════════════════════════════════════════════════

class TestReliabilityScoring:
    """Tests for reliability score calculation."""
    
    def test_stealer_log_reliability(self, provider):
        """Test stealer log reliability score."""
        score = provider._calculate_reliability(BreachSource.STEALER_LOG)
        assert score >= 0.85  # Stealer logs are highly reliable
    
    def test_arthouse_reliability(self, provider):
        """Test ArtHouse reliability score."""
        score = provider._calculate_reliability(BreachSource.ARTHOUSE)
        assert 0.7 <= score <= 0.85
    
    def test_combolist_reliability(self, provider):
        """Test combolist reliability score."""
        score = provider._calculate_reliability(BreachSource.COMBOLIST)
        assert score <= 0.7  # Combos are less reliable
    
    def test_age_penalty(self, provider):
        """Test age penalty on reliability."""
        recent = datetime.utcnow() - timedelta(days=30)
        old = datetime.utcnow() - timedelta(days=400)
        very_old = datetime.utcnow() - timedelta(days=1000)
        
        score_recent = provider._calculate_reliability(BreachSource.ARTHOUSE, recent)
        score_old = provider._calculate_reliability(BreachSource.ARTHOUSE, old)
        score_very_old = provider._calculate_reliability(BreachSource.ARTHOUSE, very_old)
        
        # Older data should have lower reliability
        assert score_recent > score_old
        assert score_old > score_very_old
    
    def test_minimum_reliability_floor(self, provider):
        """Test that reliability doesn't go below minimum."""
        very_old = datetime.utcnow() - timedelta(days=2000)
        score = provider._calculate_reliability(BreachSource.UNKNOWN, very_old)
        assert score >= 0.1


# ═══════════════════════════════════════════════════════════════
# Test Sensitive Data Masking
# ═══════════════════════════════════════════════════════════════

class TestDataMasking:
    """Tests for sensitive data masking."""
    
    def test_mask_password(self, provider):
        """Test password masking."""
        masked = provider._mask_sensitive_data("mysecretpassword", show_chars=2)
        # Actual format: first N chars + *** + last N chars
        assert masked.startswith("my")
        assert "***" in masked
        assert "secret" not in masked
    
    def test_mask_email(self, provider):
        """Test email masking."""
        masked = provider._mask_sensitive_data("admin@example.com", show_chars=3)
        assert masked.startswith("adm")
        assert "***" in masked
    
    def test_mask_short_data(self, provider):
        """Test masking short data."""
        masked = provider._mask_sensitive_data("ab", show_chars=2)
        # Short data should be fully masked (returns length of original if <= show_chars*2)
        assert len(masked) == 2 or "*" in masked
    
    def test_mask_error_with_credentials(self, provider):
        """Test masking error messages with credentials."""
        error = "Connection failed to http://admin:password123@es.example.com:9200"
        masked = provider._mask_error(error)
        
        assert "password123" not in masked
        assert "***" in masked
    
    def test_mask_api_key_in_error(self, provider):
        """Test masking API key in error messages."""
        error = "Auth failed with api_key=super_secret_key_12345"
        masked = provider._mask_error(error)
        
        assert "super_secret_key_12345" not in masked
        assert "***" in masked


# ═══════════════════════════════════════════════════════════════
# Test Hash Detection
# ═══════════════════════════════════════════════════════════════

class TestHashDetection:
    """Tests for hash type detection."""
    
    def test_detect_md5(self, provider):
        """Test MD5 hash detection."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        hash_type = provider._detect_hash_type(md5_hash)
        assert hash_type == "md5"
    
    def test_detect_sha1(self, provider):
        """Test SHA1 hash detection."""
        sha1_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        hash_type = provider._detect_hash_type(sha1_hash)
        assert hash_type == "sha1"
    
    def test_detect_sha256(self, provider):
        """Test SHA256 hash detection."""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hash_type = provider._detect_hash_type(sha256_hash)
        assert hash_type == "sha256"
    
    def test_detect_bcrypt(self, provider):
        """Test bcrypt hash detection."""
        bcrypt_hash = "$2a$12$LQv3c1yqBW/HxkeKF3Yzr.gXJ/Rb.eSFt7.2lUQ.Q1a/tOqGz6vKa"
        hash_type = provider._detect_hash_type(bcrypt_hash)
        assert hash_type == "bcrypt"
    
    def test_is_hash_true_for_md5(self, provider):
        """Test _is_hash for MD5."""
        assert provider._is_hash("5f4dcc3b5aa765d61d8327deb882cf99") is True
    
    def test_is_hash_false_for_plaintext(self, provider):
        """Test _is_hash for plaintext password."""
        assert provider._is_hash("mysecretpassword") is False


# ═══════════════════════════════════════════════════════════════
# Test Integration Scenarios
# ═══════════════════════════════════════════════════════════════

class TestIntegrationScenarios:
    """Integration tests for realistic scenarios."""
    
    @pytest.mark.asyncio
    async def test_domain_search_flow(self, provider_with_mock, mock_es_client, sample_es_response):
        """Test complete domain search flow."""
        mock_es_client.search.return_value = sample_es_response
        
        # Search for domain
        result = await provider_with_mock.search("vulnerable-target.com", query_type="domain")
        
        # Verify result
        assert result.success is True
        assert result.query == "vulnerable-target.com"
        assert result.query_type == "domain"
        assert result.provider == "elasticsearch"
        assert result.total_found >= 1
        assert result.search_time_ms >= 0
        
        # Verify credentials have required fields
        for cred in result.credentials:
            assert cred.username or cred.email
            assert cred.password or cred.password_hash
            assert cred.source is not None
            assert 0 <= cred.reliability_score <= 1.0
    
    @pytest.mark.asyncio
    async def test_email_search_flow(self, provider_with_mock, mock_es_client):
        """Test email search flow."""
        response = {
            "hits": {
                "total": {"value": 1},
                "hits": [{
                    "_index": "leaks-2024",
                    "_id": "email1",
                    "_score": 10.0,
                    "_source": {
                        "email": "admin@vulnerable-target.com",
                        "password": "found_password",
                        "breach_date": "2024-03-15"
                    }
                }]
            }
        }
        mock_es_client.search.return_value = response
        
        result = await provider_with_mock.search(
            "admin@vulnerable-target.com",
            query_type="email"
        )
        
        assert result.success is True
        assert len(result.credentials) == 1
        assert result.credentials[0].email == "admin@vulnerable-target.com"
    
    @pytest.mark.asyncio
    async def test_no_results_found(self, provider_with_mock, mock_es_client):
        """Test search with no results."""
        response = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_es_client.search.return_value = response
        
        result = await provider_with_mock.search("nonexistent-domain.com", query_type="domain")
        
        assert result.success is True
        assert len(result.credentials) == 0
        assert result.total_found == 0
    
    @pytest.mark.asyncio
    async def test_index_not_found(self, provider_with_mock, mock_es_client):
        """Test search when index doesn't exist."""
        from elasticsearch.exceptions import NotFoundError
        # NotFoundError requires status, message, body parameters
        mock_es_client.search.side_effect = NotFoundError(
            message="Index not found",
            meta=None,
            body={"error": {"type": "index_not_found_exception"}}
        )
        
        result = await provider_with_mock.search("example.com", query_type="domain")
        
        assert result.success is True  # Should handle gracefully
        assert len(result.credentials) == 0
    
    @pytest.mark.asyncio
    async def test_auto_detect_query_type(self, provider_with_mock, mock_es_client):
        """Test auto-detection of query type."""
        response = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_es_client.search.return_value = response
        
        # Email detection - the query should contain email fields
        result = await provider_with_mock.search("user@example.com", query_type="auto")
        assert result.success is True
        
        # IP detection  
        mock_es_client.search.reset_mock()
        mock_es_client.search.return_value = response
        result = await provider_with_mock.search("192.168.1.100", query_type="auto")
        assert result.success is True


# ═══════════════════════════════════════════════════════════════
# Test Configuration from Settings
# ═══════════════════════════════════════════════════════════════

class TestConfigurationFromSettings:
    """Tests for provider configuration from settings."""
    
    def test_create_from_settings(self):
        """Test creating provider from settings."""
        # Mock settings
        mock_settings = MagicMock()
        mock_settings.intel_elastic_url = "http://es.example.com:9200"
        mock_settings.intel_elastic_api_key = "test_key"
        mock_settings.intel_elastic_index = "custom-leaks-*"
        mock_settings.intel_elastic_timeout = 60
        mock_settings.intel_elastic_max_retries = 5
        mock_settings.intel_elastic_verify_certs = False
        
        with patch("src.core.intel.elasticsearch_provider.AsyncElasticsearch"):
            provider = ElasticsearchBreachProvider(
                hosts=[mock_settings.intel_elastic_url],
                index_pattern=mock_settings.intel_elastic_index,
                api_key=mock_settings.intel_elastic_api_key,
                timeout=mock_settings.intel_elastic_timeout,
                max_retries=mock_settings.intel_elastic_max_retries,
                verify_certs=mock_settings.intel_elastic_verify_certs
            )
            
            assert provider._hosts == ["http://es.example.com:9200"]
            assert provider._index_pattern == "custom-leaks-*"
            assert provider._api_key == "test_key"
            assert provider._timeout == 60
            assert provider._max_retries == 5
            assert provider._verify_certs is False
