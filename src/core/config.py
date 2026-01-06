# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Configuration
# Application settings using Pydantic Settings
# ═══════════════════════════════════════════════════════════════

from functools import lru_cache
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Settings are loaded in the following order (later overrides earlier):
    1. Default values
    2. .env file
    3. Environment variables
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # ═══════════════════════════════════════════════════════════
    # Application
    # ═══════════════════════════════════════════════════════════
    app_name: str = Field(default="RAGLOX", description="Application name")
    app_version: str = Field(default="3.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    dev_mode: bool = Field(default=False, description="Development mode")
    
    # ═══════════════════════════════════════════════════════════
    # API
    # ═══════════════════════════════════════════════════════════
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    api_reload: bool = Field(default=False, description="Auto-reload on changes")
    cors_origins: str = Field(
        default="*",
        description="Comma-separated list of allowed CORS origins"
    )
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins into a list."""
        return [origin.strip() for origin in self.cors_origins.split(",")]
    
    # ═══════════════════════════════════════════════════════════
    # Redis
    # ═══════════════════════════════════════════════════════════
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    redis_password: Optional[str] = Field(
        default=None,
        description="Redis password"
    )
    redis_max_connections: int = Field(
        default=100,
        description="Maximum Redis connections"
    )
    
    # ═══════════════════════════════════════════════════════════
    # REL-01: Redis High Availability Settings
    # ═══════════════════════════════════════════════════════════
    redis_mode: str = Field(
        default="standalone",
        description="Redis mode: standalone, sentinel, cluster"
    )
    redis_sentinel_hosts: str = Field(
        default="",
        description="Comma-separated list of Sentinel hosts (host:port,host:port)"
    )
    redis_sentinel_master: str = Field(
        default="mymaster",
        description="Sentinel master name"
    )
    redis_cluster_nodes: str = Field(
        default="",
        description="Comma-separated list of cluster nodes (host:port,host:port)"
    )
    redis_health_check_interval: int = Field(
        default=30,
        description="Redis health check interval in seconds"
    )
    redis_reconnect_max_attempts: int = Field(
        default=10,
        description="Maximum Redis reconnection attempts"
    )
    redis_socket_timeout: float = Field(
        default=5.0,
        description="Redis socket timeout in seconds"
    )
    
    # ═══════════════════════════════════════════════════════════
    # REL-02: Approval Persistence Settings
    # ═══════════════════════════════════════════════════════════
    approval_ttl_pending: int = Field(
        default=86400,
        description="TTL for pending approvals in seconds (24 hours)"
    )
    approval_ttl_completed: int = Field(
        default=604800,
        description="TTL for completed approvals in seconds (7 days)"
    )
    chat_history_ttl: int = Field(
        default=2592000,
        description="TTL for chat history in seconds (30 days)"
    )
    approval_audit_ttl: int = Field(
        default=7776000,
        description="TTL for approval audit logs in seconds (90 days)"
    )
    
    # ═══════════════════════════════════════════════════════════
    # PostgreSQL
    # ═══════════════════════════════════════════════════════════
    database_url: str = Field(
        default="postgresql://raglox:password@localhost:5432/raglox",
        description="PostgreSQL connection URL"
    )
    db_pool_size: int = Field(default=10, description="Database pool size")
    db_max_overflow: int = Field(default=20, description="Database max overflow")
    
    # ═══════════════════════════════════════════════════════════
    # S3/MinIO
    # ═══════════════════════════════════════════════════════════
    s3_endpoint: str = Field(
        default="http://localhost:9000",
        description="S3/MinIO endpoint"
    )
    minio_access_key: str = Field(
        default="raglox_access",
        description="MinIO access key"
    )
    minio_secret_key: str = Field(
        default="",
        description="MinIO secret key"
    )
    s3_bucket_payloads: str = Field(default="payloads", description="Payloads bucket")
    s3_bucket_reports: str = Field(default="reports", description="Reports bucket")
    s3_bucket_logs: str = Field(default="logs", description="Logs bucket")
    s3_bucket_evidence: str = Field(default="evidence", description="Evidence bucket")
    
    # ═══════════════════════════════════════════════════════════
    # JWT Authentication (SEC-05: Hardened)
    # ═══════════════════════════════════════════════════════════
    jwt_secret: str = Field(
        default="",  # Empty default - will generate secure one if not set
        description="JWT secret key (minimum 32 characters for production)"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_hours: int = Field(
        default=24,
        ge=1,
        le=168,  # Max 1 week
        description="JWT expiration in hours (1-168)"
    )
    
    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """
        Validate JWT secret strength.
        
        SEC-05: JWT Security Hardening
        - Auto-generates secure secret if empty
        - Rejects insecure default values
        - Enforces minimum length of 32 characters in production
        - Checks for minimum entropy
        """
        import secrets
        import os
        import logging
        
        # Auto-generate if empty
        if not v:
            generated = secrets.token_urlsafe(48)
            logging.getLogger("raglox.config").warning(
                "JWT_SECRET not set. Auto-generated secure secret for this session. "
                "For production, set JWT_SECRET environment variable."
            )
            return generated
        
        # Reject known insecure defaults
        insecure_defaults = [
            "change-this-secret-in-production",
            "secret",
            "jwt_secret",
            "your-secret-key",
            "changeme",
        ]
        if v.lower() in [d.lower() for d in insecure_defaults]:
            # In dev mode, generate secure secret
            if os.environ.get("DEV_MODE", "").lower() in ("true", "1", "yes"):
                generated = secrets.token_urlsafe(48)
                logging.getLogger("raglox.config").warning(
                    "Insecure JWT_SECRET detected in dev mode. Auto-generated secure secret."
                )
                return generated
            raise ValueError(
                "JWT secret must be changed from default/insecure value. "
                "Generate a secure secret with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        
        # Enforce minimum length (warn in dev, error in production)
        if len(v) < 32:
            if os.environ.get("DEV_MODE", "").lower() in ("true", "1", "yes"):
                logging.getLogger("raglox.config").warning(
                    f"JWT secret is too short ({len(v)} chars). Should be at least 32 chars."
                )
                return v
            raise ValueError(
                f"JWT secret must be at least 32 characters (got {len(v)}). "
                "Generate a secure secret with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )
        
        # Check for minimum entropy (at least 10 unique characters)
        if len(set(v)) < 10:
            logging.getLogger("raglox.config").warning(
                "JWT secret has low entropy. Consider using a more random value."
            )
        
        return v
    
    @staticmethod
    def generate_jwt_secret() -> str:
        """Generate a cryptographically secure JWT secret."""
        import secrets
        return secrets.token_urlsafe(48)
    
    def is_jwt_secret_secure(self) -> bool:
        """Check if the current JWT secret meets security requirements."""
        if len(self.jwt_secret) < 32:
            return False
        if len(set(self.jwt_secret)) < 10:
            return False
        insecure_defaults = [
            "change-this-secret-in-production",
            "secret",
            "jwt_secret",
            "your-secret-key",
            "changeme",
        ]
        if self.jwt_secret.lower() in [d.lower() for d in insecure_defaults]:
            return False
        return True
    
    # ═══════════════════════════════════════════════════════════
    # Stripe Billing (SaaS)
    # ═══════════════════════════════════════════════════════════
    stripe_secret_key: str = Field(
        default="",
        description="Stripe API secret key (sk_test_... or sk_live_...)"
    )
    stripe_publishable_key: str = Field(
        default="",
        description="Stripe publishable key (pk_test_... or pk_live_...)"
    )
    stripe_webhook_secret: str = Field(
        default="",
        description="Stripe webhook signing secret (whsec_...)"
    )
    stripe_enabled: bool = Field(
        default=True,
        description="Enable Stripe billing integration"
    )
    
    @property
    def is_stripe_configured(self) -> bool:
        """Check if Stripe is properly configured."""
        return bool(
            self.stripe_secret_key and
            self.stripe_secret_key.startswith(("sk_test_", "sk_live_"))
        )
    
    # ═══════════════════════════════════════════════════════════
    # Security
    # ═══════════════════════════════════════════════════════════
    encryption_key: str = Field(
        default="",
        description="Base64 encoded 32-byte encryption key"
    )
    
    # ═══════════════════════════════════════════════════════════
    # SEC-03: Input Validation Settings
    # ═══════════════════════════════════════════════════════════
    security_validation_enabled: bool = Field(
        default=True,
        description="Enable input validation middleware (SEC-03)"
    )
    security_check_xss: bool = Field(
        default=True,
        description="Check for XSS patterns in inputs"
    )
    security_check_sql: bool = Field(
        default=True,
        description="Check for SQL injection patterns in inputs"
    )
    security_check_command: bool = Field(
        default=True,
        description="Check for command injection patterns in inputs"
    )
    security_check_path: bool = Field(
        default=True,
        description="Check for path traversal patterns in inputs"
    )
    security_max_body_size: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="Maximum request body size in bytes"
    )
    security_max_param_length: int = Field(
        default=10000,
        description="Maximum parameter length"
    )
    
    # ═══════════════════════════════════════════════════════════
    # SEC-04: Rate Limiting Settings
    # ═══════════════════════════════════════════════════════════
    rate_limiting_enabled: bool = Field(
        default=True,
        description="Enable rate limiting middleware (SEC-04)"
    )
    rate_limit_default: int = Field(
        default=100,
        description="Default requests per minute"
    )
    rate_limit_missions_create: int = Field(
        default=10,
        description="Rate limit for mission creation (per minute)"
    )
    rate_limit_exploit_execute: int = Field(
        default=5,
        description="Rate limit for exploit execution (per minute)"
    )
    rate_limit_chat: int = Field(
        default=30,
        description="Rate limit for chat messages (per minute)"
    )
    rate_limit_websocket: int = Field(
        default=10,
        description="Rate limit for WebSocket connections (per minute)"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Logging
    # ═══════════════════════════════════════════════════════════
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format (json/text)")
    
    # ═══════════════════════════════════════════════════════════
    # Mission Defaults
    # ═══════════════════════════════════════════════════════════
    mission_timeout_seconds: int = Field(
        default=86400,
        description="Default mission timeout (24 hours)"
    )
    max_concurrent_missions: int = Field(
        default=5,
        description="Maximum concurrent missions"
    )
    max_workers_per_specialist: int = Field(
        default=5,
        description="Maximum workers per specialist"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Knowledge Base
    # ═══════════════════════════════════════════════════════════
    knowledge_data_path: str = Field(
        default="data",
        description="Path to knowledge base data (relative to webapp or absolute)"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Intel - Elasticsearch (Leaked Data Lake)
    # ═══════════════════════════════════════════════════════════
    intel_elastic_enabled: bool = Field(
        default=False,
        description="Enable Elasticsearch intel provider"
    )
    intel_elastic_url: str = Field(
        default="http://localhost:9200",
        description="Elasticsearch URL for intel/leak data"
    )
    intel_elastic_api_key: Optional[str] = Field(
        default=None,
        description="Elasticsearch API key (base64 encoded)"
    )
    intel_elastic_username: Optional[str] = Field(
        default=None,
        description="Elasticsearch username for basic auth"
    )
    intel_elastic_password: Optional[str] = Field(
        default=None,
        description="Elasticsearch password for basic auth"
    )
    intel_elastic_index: str = Field(
        default="leaks-*",
        description="Elasticsearch index pattern for leaked data"
    )
    intel_elastic_timeout: int = Field(
        default=30,
        description="Elasticsearch request timeout in seconds"
    )
    intel_elastic_max_retries: int = Field(
        default=3,
        description="Maximum retries for Elasticsearch connection"
    )
    intel_elastic_verify_certs: bool = Field(
        default=True,
        description="Verify Elasticsearch SSL certificates"
    )
    intel_elastic_ca_certs: Optional[str] = Field(
        default=None,
        description="Path to CA certificates for Elasticsearch"
    )
    
    # Intel - General Settings
    intel_file_data_dir: str = Field(
        default="./data/breach_data",
        description="Directory for local breach data files"
    )
    intel_credential_priority_boost: float = Field(
        default=0.3,
        description="Priority boost for intel credentials over brute force (0.0-0.5)"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Metasploit & Exploitation Framework
    # ═══════════════════════════════════════════════════════════
    use_real_exploits: bool = Field(
        default=False,
        description="Enable real exploitation (requires Metasploit RPC)"
    )
    msf_rpc_host: str = Field(
        default="localhost",
        description="Metasploit RPC server host"
    )
    msf_rpc_port: int = Field(
        default=55553,
        description="Metasploit RPC server port"
    )
    msf_rpc_user: str = Field(
        default="msf",
        description="Metasploit RPC username"
    )
    msf_rpc_pass: str = Field(
        default="",
        description="Metasploit RPC password"
    )
    msf_rpc_ssl: bool = Field(
        default=False,
        description="Use SSL for Metasploit RPC connection"
    )
    msf_rpc_timeout: int = Field(
        default=30,
        description="Metasploit RPC connection timeout in seconds"
    )
    
    # Exploitation Listener Configuration
    lhost: str = Field(
        default="0.0.0.0",
        description="Listener host for reverse shells (LHOST)"
    )
    lport: int = Field(
        default=4444,
        description="Listener port for reverse shells (LPORT)"
    )
    
    # C2 Configuration
    c2_encryption_enabled: bool = Field(
        default=True,
        description="Enable AES-256-GCM encryption for C2 sessions"
    )
    c2_data_dir: str = Field(
        default="data/c2",
        description="Directory for C2 session data and logs"
    )
    c2_session_timeout: int = Field(
        default=3600,
        description="C2 session timeout in seconds (1 hour)"
    )
    c2_heartbeat_interval: int = Field(
        default=60,
        description="C2 heartbeat interval in seconds"
    )
    
    # Post-Exploitation Configuration
    mimikatz_enabled: bool = Field(
        default=True,
        description="Enable Mimikatz credential harvesting"
    )
    network_pivoting_enabled: bool = Field(
        default=True,
        description="Enable network pivoting and SOCKS proxy"
    )
    socks_proxy_port: int = Field(
        default=1080,
        description="SOCKS proxy port for network pivoting"
    )
    
    # ═══════════════════════════════════════════════════════════
    # OneProvider Cloud Integration
    # ═══════════════════════════════════════════════════════════
    oneprovider_enabled: bool = Field(
        default=False,
        description="Enable OneProvider cloud integration for VM provisioning"
    )
    oneprovider_api_key: str = Field(
        default="",
        description="OneProvider API key (Personal API Key)"
    )
    oneprovider_client_key: str = Field(
        default="",
        description="OneProvider CLIENT key (Secret Key)"
    )
    oneprovider_project_uuid: str = Field(
        default="",
        description="Default OneProvider project UUID for VM creation"
    )
    oneprovider_default_plan: str = Field(
        default="8GB-2CORE",
        description="Default VM plan (e.g., 8GB-2CORE, 16GB-4CORE)"
    )
    oneprovider_default_os: str = Field(
        default="ubuntu-22.04",
        description="Default OS for VM provisioning"
    )
    oneprovider_default_location: str = Field(
        default="us-east",
        description="Default datacenter location"
    )
    oneprovider_vm_timeout: int = Field(
        default=600,
        description="Timeout for VM provisioning in seconds (10 minutes)"
    )
    oneprovider_max_vms: int = Field(
        default=10,
        description="Maximum concurrent VMs per tenant"
    )
    
    # ═══════════════════════════════════════════════════════════
    # SSH Infrastructure
    # ═══════════════════════════════════════════════════════════
    ssh_enabled: bool = Field(
        default=True,
        description="Enable SSH infrastructure for remote connections"
    )
    ssh_max_connections: int = Field(
        default=50,
        description="Maximum concurrent SSH connections"
    )
    ssh_default_timeout: int = Field(
        default=30,
        description="Default SSH connection timeout in seconds"
    )
    ssh_keepalive_interval: int = Field(
        default=30,
        description="SSH keepalive interval in seconds"
    )
    ssh_key_directory: str = Field(
        default="data/ssh_keys",
        description="Directory for SSH key storage"
    )
    ssh_known_hosts_file: str = Field(
        default="data/known_hosts",
        description="SSH known hosts file path"
    )
    ssh_auto_add_host_keys: bool = Field(
        default=True,
        description="Automatically add host keys (development only)"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Agent Environment Configuration
    # ═══════════════════════════════════════════════════════════
    agent_max_environments_per_user: int = Field(
        default=10,
        description="Maximum environments per user"
    )
    agent_environment_timeout: int = Field(
        default=7200,
        description="Environment inactivity timeout in seconds (2 hours)"
    )
    agent_install_script_url: str = Field(
        default="",
        description="URL for agent installation script"
    )
    
    # ═══════════════════════════════════════════════════════════
    # LLM Configuration
    # ═══════════════════════════════════════════════════════════
    llm_enabled: bool = Field(
        default=True,
        description="Enable LLM-assisted analysis"
    )
    llm_provider: str = Field(
        default="blackbox",
        description="LLM provider (openai, blackbox, local, mock)"
    )
    
    # OpenAI-specific API key (takes precedence when provider is openai)
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key (from platform.openai.com)"
    )
    
    # Generic LLM API key (used by other providers or as fallback)
    llm_api_key: Optional[str] = Field(
        default=None,
        description="API key for BlackboxAI or other providers"
    )
    
    @property
    def effective_llm_api_key(self) -> Optional[str]:
        """
        Get the effective API key based on provider.
        
        - For OpenAI: Prefers OPENAI_API_KEY, falls back to LLM_API_KEY
        - For others: Uses LLM_API_KEY
        """
        if self.llm_provider.lower() == "openai":
            return self.openai_api_key or self.llm_api_key
        return self.llm_api_key or self.openai_api_key
    llm_api_base: Optional[str] = Field(
        default=None,
        description="API base URL for LLM providers"
    )
    llm_model: str = Field(
        default="gpt-4",
        description="LLM model name"
    )
    llm_temperature: float = Field(
        default=0.3,
        description="LLM temperature for generation (0-2)"
    )
    llm_max_tokens: int = Field(
        default=2048,
        description="Maximum tokens for LLM response"
    )
    llm_timeout: float = Field(
        default=60.0,
        description="LLM request timeout in seconds"
    )
    llm_max_retries: int = Field(
        default=3,
        description="Maximum retries for failed LLM requests"
    )
    llm_fallback_enabled: bool = Field(
        default=True,
        description="Enable fallback to rule-based analysis if LLM fails"
    )
    
    # ═══════════════════════════════════════════════════════════
    # LLM Safety Limits (Cost Control)
    # ═══════════════════════════════════════════════════════════
    llm_max_cost_limit: float = Field(
        default=2.0,
        description="Maximum cost limit in USD per mission (safety limit)"
    )
    llm_daily_requests_limit: int = Field(
        default=100,
        description="Maximum LLM requests per day (safety limit)"
    )
    llm_mission_requests_limit: int = Field(
        default=20,
        description="Maximum LLM requests per mission (safety limit)"
    )
    llm_cost_per_1k_tokens: float = Field(
        default=0.002,
        description="Estimated cost per 1000 tokens (for tracking)"
    )
    llm_safety_mode: bool = Field(
        default=True,
        description="Enable safety mode (stops on limit breach)"
    )
    
    @field_validator("llm_provider")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        """Validate LLM provider."""
        valid_providers = {"openai", "blackbox", "local", "mock", "anthropic"}
        if v.lower() not in valid_providers:
            raise ValueError(f"Invalid LLM provider: {v}. Must be one of {valid_providers}")
        return v.lower()
    
    @field_validator("llm_temperature")
    @classmethod
    def validate_llm_temperature(cls, v: float) -> float:
        """Validate LLM temperature."""
        if v < 0 or v > 2:
            raise ValueError("LLM temperature must be between 0 and 2")
        return v
    
    @field_validator("llm_max_cost_limit")
    @classmethod
    def validate_llm_max_cost_limit(cls, v: float) -> float:
        """Validate LLM max cost limit."""
        if v < 0:
            raise ValueError("LLM max cost limit must be non-negative")
        return v
    
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v.upper()


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    Uses lru_cache to ensure settings are only loaded once.
    """
    return Settings()
