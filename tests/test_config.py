# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Configuration Tests
# Testing application settings
# ═══════════════════════════════════════════════════════════════

import pytest
import os
from src.core.config import Settings, get_settings


class TestSettings:
    """Test Settings configuration."""
    
    def test_default_settings(self):
        """Test default settings values."""
        settings = Settings()
        
        # Application defaults
        assert settings.app_name == "RAGLOX"
        assert settings.app_version == "3.0.0"
        assert settings.debug == False
        
        # API defaults
        assert settings.api_host == "0.0.0.0"
        assert settings.api_port == 8000
        
        # Redis defaults
        assert "redis://" in settings.redis_url
        assert settings.redis_max_connections == 100
        
        # PostgreSQL defaults
        assert "postgresql://" in settings.database_url
        
        # JWT defaults
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_expiration_hours == 24
    
    def test_cors_origins_parsing(self):
        """Test CORS origins string is parsed to list."""
        settings = Settings(cors_origins="http://localhost:3000,http://localhost:8080")
        
        origins = settings.cors_origins_list
        
        assert len(origins) == 2
        assert "http://localhost:3000" in origins
        assert "http://localhost:8080" in origins
    
    def test_single_cors_origin(self):
        """Test single CORS origin."""
        settings = Settings(cors_origins="http://localhost:3000")
        
        origins = settings.cors_origins_list
        
        assert len(origins) == 1
        assert origins[0] == "http://localhost:3000"
    
    def test_log_level_validation_valid(self):
        """Test valid log levels are accepted."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            settings = Settings(log_level=level)
            assert settings.log_level == level
    
    def test_log_level_case_insensitive(self):
        """Test log level is case insensitive."""
        settings = Settings(log_level="debug")
        assert settings.log_level == "DEBUG"
        
        settings = Settings(log_level="Info")
        assert settings.log_level == "INFO"
    
    def test_log_level_validation_invalid(self):
        """Test invalid log level raises error."""
        with pytest.raises(ValueError, match="Invalid log level"):
            Settings(log_level="INVALID")
    
    def test_get_settings_cached(self):
        """Test get_settings returns cached instance."""
        # Clear cache first
        get_settings.cache_clear()
        
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2
    
    def test_s3_bucket_defaults(self):
        """Test S3 bucket defaults."""
        settings = Settings()
        
        assert settings.s3_bucket_payloads == "payloads"
        assert settings.s3_bucket_reports == "reports"
        assert settings.s3_bucket_logs == "logs"
        assert settings.s3_bucket_evidence == "evidence"
    
    def test_mission_defaults(self):
        """Test mission configuration defaults."""
        settings = Settings()
        
        assert settings.mission_timeout_seconds == 86400  # 24 hours
        assert settings.max_concurrent_missions == 5
        assert settings.max_workers_per_specialist == 5
    
    def test_knowledge_path_default(self):
        """Test knowledge base path default."""
        settings = Settings()
        
        assert settings.knowledge_data_path == "/opt/raglox/data"


class TestEnvironmentVariables:
    """Test settings from environment variables."""
    
    def test_redis_url_from_env(self):
        """Test REDIS_URL from environment."""
        os.environ["REDIS_URL"] = "redis://custom-redis:6380/1"
        
        # Clear cache and create new settings
        get_settings.cache_clear()
        settings = Settings()
        
        assert settings.redis_url == "redis://custom-redis:6380/1"
        
        # Cleanup
        del os.environ["REDIS_URL"]
    
    def test_database_url_from_env(self):
        """Test DATABASE_URL from environment."""
        os.environ["DATABASE_URL"] = "postgresql://user:pass@db:5432/raglox"
        
        settings = Settings()
        
        assert settings.database_url == "postgresql://user:pass@db:5432/raglox"
        
        # Cleanup
        del os.environ["DATABASE_URL"]
    
    def test_jwt_secret_from_env(self):
        """Test JWT_SECRET from environment."""
        os.environ["JWT_SECRET"] = "super-secret-key"
        
        settings = Settings()
        
        assert settings.jwt_secret == "super-secret-key"
        
        # Cleanup
        del os.environ["JWT_SECRET"]
    
    def test_api_port_from_env(self):
        """Test API_PORT from environment."""
        os.environ["API_PORT"] = "9000"
        
        settings = Settings()
        
        assert settings.api_port == 9000
        
        # Cleanup
        del os.environ["API_PORT"]


class TestSettingsIntegration:
    """Test settings integration with other components."""
    
    def test_settings_for_blackboard(self):
        """Test settings provide correct values for Blackboard."""
        settings = Settings(
            redis_url="redis://localhost:6379/0",
            redis_max_connections=50
        )
        
        # These values should be usable by Blackboard
        assert "redis://" in settings.redis_url
        assert settings.redis_max_connections > 0
    
    def test_settings_for_database(self):
        """Test settings provide correct values for database."""
        settings = Settings(
            database_url="postgresql://raglox:password@localhost:5432/raglox",
            db_pool_size=20
        )
        
        assert "postgresql://" in settings.database_url
        assert settings.db_pool_size == 20
    
    def test_settings_model_dump(self):
        """Test settings can be dumped to dict."""
        settings = Settings()
        data = settings.model_dump()
        
        assert "app_name" in data
        assert "redis_url" in data
        assert "database_url" in data
        assert data["app_name"] == "RAGLOX"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
