# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Elasticsearch Breach Data Provider
# Search leaked credentials in Elasticsearch Data Lake
# ═══════════════════════════════════════════════════════════════

"""
ElasticsearchBreachProvider - Search for leaked credentials in Elasticsearch.

This provider is designed to work with large, potentially unstructured
breach data stored in Elasticsearch. It implements smart field extraction
to handle various data formats commonly found in leaked data:

- Combo lists (email:password)
- Database dumps (structured with various column names)
- Stealer logs (URL, login, password format)
- Raw data with various field naming conventions

Features:
- Async Elasticsearch client
- Smart field extraction from unstructured data
- Automatic retry on connection failures
- Reliability scoring based on data source and age
- Sensitive data masking in logs

Usage:
    provider = ElasticsearchBreachProvider(
        hosts=["http://localhost:9200"],
        index_pattern="leaks-*"
    )
    result = await provider.search("example.com", query_type="domain")
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from .base import BreachDataProvider, BreachSource, IntelCredential, IntelSearchResult

# Elasticsearch imports - optional dependency
try:
    from elasticsearch import AsyncElasticsearch
    from elasticsearch.exceptions import (
        ConnectionError as ESConnectionError,
        ConnectionTimeout,
        TransportError,
        NotFoundError,
        AuthenticationException
    )
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False
    AsyncElasticsearch = None
    ESConnectionError = Exception
    ConnectionTimeout = Exception
    TransportError = Exception
    NotFoundError = Exception
    AuthenticationException = Exception


class ElasticsearchBreachProvider(BreachDataProvider):
    """
    Elasticsearch Breach Data Provider.
    
    Searches for leaked credentials in Elasticsearch indices.
    Handles various data formats and field naming conventions.
    
    Configuration:
        - hosts: List of Elasticsearch hosts
        - index_pattern: Index pattern to search (default: "leaks-*")
        - api_key: Optional API key for authentication
        - timeout: Request timeout in seconds
        - max_retries: Maximum connection retries
    
    Supported Data Formats:
        - email:password combos
        - user/username + pass/password pairs
        - login/credential with secret/hash
        - Nested structures with various naming
    """
    
    # Common field names for credentials in leaked data
    USERNAME_FIELDS = [
        "username", "user", "login", "email", "mail", "e-mail",
        "user_name", "userName", "account", "id", "userid", "user_id",
        "login_name", "loginName", "name", "uname", "usr"
    ]
    
    PASSWORD_FIELDS = [
        "password", "pass", "passwd", "pwd", "secret", "credential",
        "hash", "password_hash", "passwordHash", "pw", "passwort",
        "contraseña", "mot_de_passe", "senha"
    ]
    
    EMAIL_FIELDS = [
        "email", "mail", "e-mail", "email_address", "emailAddress",
        "correo", "courriel", "e_mail"
    ]
    
    DOMAIN_FIELDS = [
        "domain", "site", "website", "url", "host", "target",
        "source_domain", "origen", "dominio"
    ]
    
    HASH_FIELDS = [
        "hash", "password_hash", "passwordHash", "md5", "sha1",
        "sha256", "ntlm", "lm_hash", "nt_hash", "bcrypt"
    ]
    
    # Source indicators in field names or data
    SOURCE_INDICATORS = {
        BreachSource.ARTHOUSE: ["arthouse", "art_house", "arthouseleaks"],
        BreachSource.FATETRAFFIC: ["fatetraffic", "fate_traffic", "fatetraff"],
        BreachSource.STEALER_LOG: ["stealer", "log", "infostealer", "redline", "raccoon"],
        BreachSource.DATABASE_DUMP: ["dump", "database", "db_", "sql"],
        BreachSource.COMBOLIST: ["combo", "combolist", "collection"],
        BreachSource.PASTE_SITE: ["paste", "pastebin", "ghostbin"],
        BreachSource.RANSOMWARE_LEAK: ["ransom", "lockbit", "conti", "revil"],
    }
    
    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        index_pattern: str = "leaks-*",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        verify_certs: bool = True,
        ca_certs: Optional[str] = None
    ):
        """
        Initialize Elasticsearch provider.
        
        Args:
            hosts: List of Elasticsearch hosts (default: ["http://localhost:9200"])
            index_pattern: Index pattern to search
            api_key: API key for authentication (base64 encoded or tuple)
            username: Username for basic auth
            password: Password for basic auth
            timeout: Request timeout in seconds
            max_retries: Maximum connection retries
            retry_delay: Delay between retries in seconds
            verify_certs: Verify SSL certificates
            ca_certs: Path to CA certificates
        """
        if not ELASTICSEARCH_AVAILABLE:
            raise ImportError(
                "elasticsearch package not installed. "
                "Install with: pip install elasticsearch[async]"
            )
        
        self._hosts = hosts or ["http://localhost:9200"]
        self._index_pattern = index_pattern
        self._api_key = api_key
        self._username = username
        self._password = password
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._verify_certs = verify_certs
        self._ca_certs = ca_certs
        
        self.logger = logging.getLogger("raglox.intel.elasticsearch")
        
        # Client is lazily initialized
        self._client: Optional[AsyncElasticsearch] = None
        
        # Connection state
        self._connected = False
        self._last_error: Optional[str] = None
    
    @property
    def provider_name(self) -> str:
        return "elasticsearch"
    
    async def _get_client(self) -> AsyncElasticsearch:
        """Get or create Elasticsearch client."""
        if self._client is None:
            client_kwargs = {
                "hosts": self._hosts,
                "request_timeout": self._timeout,
                "retry_on_timeout": True,
                "max_retries": self._max_retries,
            }
            
            # Authentication
            if self._api_key:
                client_kwargs["api_key"] = self._api_key
            elif self._username and self._password:
                client_kwargs["basic_auth"] = (self._username, self._password)
            
            # SSL/TLS
            if not self._verify_certs:
                client_kwargs["verify_certs"] = False
            if self._ca_certs:
                client_kwargs["ca_certs"] = self._ca_certs
            
            self._client = AsyncElasticsearch(**client_kwargs)
        
        return self._client
    
    async def _ensure_connected(self) -> bool:
        """Ensure connection to Elasticsearch is established."""
        try:
            client = await self._get_client()
            info = await client.info()
            self._connected = True
            self._last_error = None
            self.logger.debug(f"Connected to Elasticsearch {info['version']['number']}")
            return True
        except (ESConnectionError, ConnectionTimeout, TransportError) as e:
            self._connected = False
            self._last_error = str(e)
            self.logger.error(f"Elasticsearch connection failed: {self._mask_error(str(e))}")
            return False
        except AuthenticationException as e:
            self._connected = False
            self._last_error = f"Authentication failed: {e}"
            self.logger.error("Elasticsearch authentication failed")
            return False
    
    async def search(
        self,
        query: str,
        query_type: str = "domain",
        limit: int = 100
    ) -> IntelSearchResult:
        """
        Search for credentials in Elasticsearch.
        
        Args:
            query: Search query (domain, email, IP, username)
            query_type: Type of query
            limit: Maximum results to return
            
        Returns:
            IntelSearchResult with found credentials
        """
        start_time = datetime.utcnow()
        
        # Auto-detect query type
        if query_type == "auto":
            query_type = self._detect_query_type(query)
        
        # Build Elasticsearch query
        es_query = self._build_query(query, query_type)
        
        credentials: List[IntelCredential] = []
        total_hits = 0
        
        # Retry logic for transient failures
        for attempt in range(self._max_retries):
            try:
                client = await self._get_client()
                
                # Execute search with error handling
                response = await client.search(
                    index=self._index_pattern,
                    body=es_query,
                    size=limit,
                    request_timeout=self._timeout
                )
                
                total_hits = response["hits"]["total"]["value"]
                
                # Parse results
                for hit in response["hits"]["hits"]:
                    cred = self._extract_credential_from_hit(hit, query, query_type)
                    if cred:
                        credentials.append(cred)
                
                # Success - break retry loop
                break
                
            except NotFoundError:
                self.logger.warning(f"Index pattern '{self._index_pattern}' not found")
                break
                
            except (ESConnectionError, ConnectionTimeout, TransportError) as e:
                self._last_error = str(e)
                
                if attempt < self._max_retries - 1:
                    self.logger.warning(
                        f"Elasticsearch error (attempt {attempt + 1}/{self._max_retries}): "
                        f"{self._mask_error(str(e))}. Retrying..."
                    )
                    await asyncio.sleep(self._retry_delay * (attempt + 1))
                else:
                    self.logger.error(
                        f"Elasticsearch search failed after {self._max_retries} attempts"
                    )
                    return IntelSearchResult(
                        query=query,
                        query_type=query_type,
                        success=False,
                        error=f"Connection failed: {self._mask_error(str(e))}",
                        provider=self.provider_name,
                        search_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
                    )
            
            except Exception as e:
                self.logger.error(f"Unexpected error during search: {e}")
                return IntelSearchResult(
                    query=query,
                    query_type=query_type,
                    success=False,
                    error=f"Search error: {str(e)}",
                    provider=self.provider_name,
                    search_time_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
                )
        
        # Deduplicate
        unique_credentials = self._deduplicate_credentials(credentials)
        
        search_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        self.logger.info(
            f"Elasticsearch search for '{self._mask_sensitive_data(query)}' "
            f"found {len(unique_credentials)} credentials ({total_hits} total hits) "
            f"in {search_time:.1f}ms"
        )
        
        return IntelSearchResult(
            query=query,
            query_type=query_type,
            credentials=unique_credentials,
            total_found=len(unique_credentials),
            provider=self.provider_name,
            search_time_ms=search_time,
            success=True
        )
    
    def _build_query(self, query: str, query_type: str) -> Dict[str, Any]:
        """
        Build Elasticsearch query based on query type.
        
        Uses multi_match to search across various field naming conventions.
        """
        if query_type == "domain":
            # Search for domain in email fields and domain fields
            return {
                "query": {
                    "bool": {
                        "should": [
                            # Match in email fields
                            {"multi_match": {
                                "query": query,
                                "fields": self.EMAIL_FIELDS + self.DOMAIN_FIELDS,
                                "type": "phrase_prefix"
                            }},
                            # Wildcard for email domain
                            {"wildcard": {
                                "email": f"*@{query}"
                            }},
                            {"wildcard": {
                                "mail": f"*@{query}"
                            }},
                        ],
                        "minimum_should_match": 1
                    }
                },
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
                ]
            }
        
        elif query_type == "email":
            # Exact email search
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"email.keyword": query}},
                            {"term": {"mail.keyword": query}},
                            {"term": {"e-mail.keyword": query}},
                            {"match_phrase": {"email": query}},
                            {"match_phrase": {"mail": query}},
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        
        elif query_type == "ip":
            # IP address search
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"ip": query}},
                            {"term": {"ip_address": query}},
                            {"term": {"target_ip": query}},
                            {"term": {"host": query}},
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        
        elif query_type == "username":
            # Username search
            return {
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": self.USERNAME_FIELDS,
                        "type": "best_fields"
                    }
                }
            }
        
        else:
            # Generic search across all fields
            return {
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["*"],
                        "type": "best_fields"
                    }
                }
            }
    
    def _extract_credential_from_hit(
        self,
        hit: Dict[str, Any],
        query: str,
        query_type: str
    ) -> Optional[IntelCredential]:
        """
        Extract credential from Elasticsearch hit.
        
        Handles various data formats and field naming conventions.
        Returns None if no valid credential can be extracted.
        """
        source = hit.get("_source", {})
        index_name = hit.get("_index", "")
        score = hit.get("_score", 0)
        
        if not source:
            return None
        
        # Extract username/email
        username, email = self._extract_identity(source)
        
        if not username and not email:
            # Try to extract from raw/combined fields
            username, email = self._extract_identity_from_raw(source)
        
        if not username and not email:
            return None
        
        # Extract password/hash
        password, password_hash, hash_type = self._extract_secret(source)
        
        if not password and not password_hash:
            return None
        
        # Extract domain
        domain = self._extract_domain_from_source(source, email)
        
        # Determine source type from index name or data
        breach_source = self._determine_source(index_name, source)
        
        # Extract timestamp for age calculation
        source_date = self._extract_timestamp(source)
        
        # Calculate reliability score
        # Note: Plaintext passwords get a small boost as they're more useful
        reliability = self._calculate_reliability(breach_source, source_date)
        if password:  # Small boost for plaintext passwords
            reliability = min(reliability + 0.05, 1.0)
        
        # Build raw log (masked)
        raw_log = self._build_raw_log(source)
        
        return IntelCredential(
            username=username,
            email=email,
            password=password,
            password_hash=password_hash,
            hash_type=hash_type,
            domain=domain,
            target_domain=query if query_type == "domain" else None,
            source=breach_source,
            source_name=f"ES:{index_name}",
            source_date=source_date,
            raw_log=raw_log,
            reliability_score=reliability,
            metadata={
                "es_index": index_name,
                "es_score": score,
                "es_id": hit.get("_id")
            }
        )
    
    def _extract_identity(self, source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract username and email from source fields."""
        username = None
        email = None
        
        # Look for email first
        for field in self.EMAIL_FIELDS:
            value = self._get_field_value(source, field)
            if value and self._is_valid_email(value):
                email = value
                break
        
        # Look for username
        for field in self.USERNAME_FIELDS:
            value = self._get_field_value(source, field)
            if value and not self._is_valid_email(value):
                username = value
                break
        
        # If we only found email, extract username from it
        if email and not username:
            username = email.split("@")[0]
        
        return username, email
    
    def _extract_identity_from_raw(self, source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract identity from raw/combined fields.
        
        Handles formats like:
        - "user:password"
        - "email:pass"
        - Raw text with embedded credentials
        """
        raw_fields = ["raw", "line", "data", "combo", "entry", "record"]
        
        for field in raw_fields:
            value = self._get_field_value(source, field)
            if not value:
                continue
            
            # Try email:password format
            match = re.match(r'^([^\s:]+@[^\s:]+):(.+)$', value)
            if match:
                return match.group(1).split("@")[0], match.group(1)
            
            # Try user:password format
            match = re.match(r'^([^\s:]+):(.+)$', value)
            if match:
                return match.group(1), None
        
        return None, None
    
    def _extract_secret(self, source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract password or hash from source fields."""
        password = None
        password_hash = None
        hash_type = None
        
        # Look for plaintext password
        for field in self.PASSWORD_FIELDS:
            value = self._get_field_value(source, field)
            if value:
                if self._is_hash(value):
                    if not password_hash:
                        password_hash = value
                        hash_type = self._detect_hash_type(value)
                else:
                    password = value
                    break
        
        # Look for hash if no plaintext found
        if not password and not password_hash:
            for field in self.HASH_FIELDS:
                value = self._get_field_value(source, field)
                if value and self._is_hash(value):
                    password_hash = value
                    hash_type = field if field in ["md5", "sha1", "sha256", "ntlm", "bcrypt"] else self._detect_hash_type(value)
                    break
        
        # Try extracting from raw field
        if not password and not password_hash:
            password, password_hash, hash_type = self._extract_secret_from_raw(source)
        
        return password, password_hash, hash_type
    
    def _extract_secret_from_raw(self, source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract secret from raw combined fields."""
        raw_fields = ["raw", "line", "data", "combo", "entry"]
        
        for field in raw_fields:
            value = self._get_field_value(source, field)
            if not value:
                continue
            
            # Try email:password or user:password format
            match = re.match(r'^[^\s:]+:(.+)$', value)
            if match:
                secret = match.group(1)
                if self._is_hash(secret):
                    return None, secret, self._detect_hash_type(secret)
                else:
                    return secret, None, None
        
        return None, None, None
    
    def _extract_domain_from_source(self, source: Dict[str, Any], email: Optional[str]) -> Optional[str]:
        """Extract domain from source or email."""
        # Try domain fields
        for field in self.DOMAIN_FIELDS:
            value = self._get_field_value(source, field)
            if value:
                return value
        
        # Extract from email
        if email and "@" in email:
            return email.split("@")[1]
        
        return None
    
    def _determine_source(self, index_name: str, source: Dict[str, Any]) -> BreachSource:
        """Determine breach source from index name and data."""
        combined = f"{index_name} {str(source)}".lower()
        
        for breach_source, indicators in self.SOURCE_INDICATORS.items():
            for indicator in indicators:
                if indicator in combined:
                    return breach_source
        
        return BreachSource.UNKNOWN
    
    def _extract_timestamp(self, source: Dict[str, Any]) -> Optional[datetime]:
        """Extract timestamp from source."""
        timestamp_fields = ["@timestamp", "timestamp", "date", "created_at", "leaked_at"]
        
        for field in timestamp_fields:
            value = self._get_field_value(source, field)
            if value:
                try:
                    if isinstance(value, datetime):
                        return value
                    elif isinstance(value, str):
                        # Try common formats
                        for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"]:
                            try:
                                return datetime.strptime(value[:len(fmt)], fmt)
                            except:
                                continue
                except:
                    pass
        
        return None
    
    def _get_field_value(self, source: Dict[str, Any], field: str) -> Optional[str]:
        """Get field value handling nested objects and case variations."""
        # Direct access
        if field in source:
            val = source[field]
            return str(val).strip() if val else None
        
        # Case-insensitive
        field_lower = field.lower()
        for key, val in source.items():
            if key.lower() == field_lower:
                return str(val).strip() if val else None
        
        # Nested access (e.g., "user.email")
        if "." in field:
            parts = field.split(".")
            current = source
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return str(current).strip() if current else None
        
        return None
    
    def _is_valid_email(self, value: str) -> bool:
        """Check if value is a valid email address."""
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value))
    
    def _is_hash(self, value: str) -> bool:
        """Check if value appears to be a hash."""
        # Common hash lengths: MD5=32, SHA1=40, SHA256=64, bcrypt=60
        if not value:
            return False
        
        # Hex hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
            return True
        if re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
            return True
        if re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
            return True
        if re.match(r'^[a-fA-F0-9]{128}$', value):  # SHA512
            return True
        
        # bcrypt pattern
        if re.match(r'^\$2[aby]?\$\d+\$.{53}$', value):
            return True
        
        # NTLM (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return True
        
        return False
    
    def _detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Detect hash type from value."""
        if not hash_value:
            return None
        
        length = len(hash_value)
        
        if re.match(r'^\$2[aby]?\$', hash_value):
            return "bcrypt"
        elif length == 32 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return "md5"
        elif length == 40 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return "sha1"
        elif length == 64 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return "sha256"
        elif length == 128 and re.match(r'^[a-fA-F0-9]+$', hash_value):
            return "sha512"
        
        return "unknown"
    
    def _build_raw_log(self, source: Dict[str, Any]) -> str:
        """Build masked raw log for reference."""
        # Create a summary of the source data with sensitive values masked
        summary_parts = []
        
        for key, value in list(source.items())[:5]:  # Limit to first 5 fields
            if value:
                masked_value = self._mask_sensitive_data(str(value), show_chars=2)
                summary_parts.append(f"{key}={masked_value}")
        
        return "; ".join(summary_parts)
    
    def _deduplicate_credentials(
        self,
        credentials: List[IntelCredential]
    ) -> List[IntelCredential]:
        """Remove duplicate credentials, keeping highest reliability."""
        seen: Dict[str, IntelCredential] = {}
        
        for cred in credentials:
            key = f"{cred.email or cred.username}:{cred.password or cred.password_hash}"
            
            if key not in seen or cred.reliability_score > seen[key].reliability_score:
                seen[key] = cred
        
        return sorted(seen.values(), key=lambda c: c.reliability_score, reverse=True)
    
    def _mask_error(self, error: str) -> str:
        """Mask potentially sensitive data in error messages."""
        # Mask URLs with credentials
        masked = re.sub(r'://([^:]+):([^@]+)@', r'://\1:***@', error)
        # Mask API keys
        masked = re.sub(r'(api[_-]?key[=:]\s*)[^\s]+', r'\1***', masked, flags=re.I)
        return masked
    
    async def health_check(self) -> bool:
        """Check if Elasticsearch connection is healthy."""
        try:
            return await self._ensure_connected()
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    async def close(self) -> None:
        """Close Elasticsearch client connection."""
        if self._client:
            await self._client.close()
            self._client = None
            self._connected = False
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get connection information (for diagnostics)."""
        return {
            "hosts": self._hosts,
            "index_pattern": self._index_pattern,
            "connected": self._connected,
            "last_error": self._last_error,
            "provider": self.provider_name
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_connected()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
