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
    # JWT Authentication
    # ═══════════════════════════════════════════════════════════
    jwt_secret: str = Field(
        default="change-this-secret-in-production",
        description="JWT secret key"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_hours: int = Field(
        default=24,
        description="JWT expiration in hours"
    )
    
    # ═══════════════════════════════════════════════════════════
    # Security
    # ═══════════════════════════════════════════════════════════
    encryption_key: str = Field(
        default="",
        description="Base64 encoded 32-byte encryption key"
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
