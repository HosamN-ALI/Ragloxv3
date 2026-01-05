# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Credential Vault
# Secure credential storage with encryption at rest
# ═══════════════════════════════════════════════════════════════

"""
Enterprise-grade credential management for RAGLOX.

Features:
- Encryption at rest using Fernet (AES-128-CBC)
- Secure credential passing between components
- Automatic masking in logs
- Audit logging for credential access
"""

from typing import Optional, Dict, Any, List
from functools import wraps
from datetime import datetime
import re
import os
import hashlib
import base64
import logging

# Try to import cryptography, fallback to basic encoding if not available
try:
    from cryptography.fernet import Fernet, InvalidToken
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False
    InvalidToken = Exception

logger = logging.getLogger(__name__)


class CredentialVault:
    """
    Secure credential storage with encryption at rest.
    
    Example:
        vault = CredentialVault.from_env()
        vault.store("db_password", "super_secret_123")
        password = vault.retrieve("db_password")
    """
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initialize vault with encryption key.
        
        Args:
            encryption_key: 32-byte Fernet key. If None, generates one.
        """
        if encryption_key is None:
            encryption_key = self._generate_key()
        
        if HAS_FERNET:
            # Ensure key is valid Fernet key (URL-safe base64-encoded 32-byte key)
            if len(encryption_key) != 44:
                # Generate proper Fernet key from provided key
                encryption_key = base64.urlsafe_b64encode(
                    hashlib.sha256(encryption_key).digest()
                )
            self._fernet = Fernet(encryption_key)
        else:
            self._fernet = None
            logger.warning(
                "cryptography package not installed. "
                "Credentials will be stored with basic encoding only."
            )
        
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_log: List[Dict[str, Any]] = []
    
    @classmethod
    def from_env(cls, env_var: str = "RAGLOX_ENCRYPTION_KEY") -> "CredentialVault":
        """
        Create vault from environment variable.
        
        Args:
            env_var: Environment variable containing encryption key
            
        Returns:
            Configured CredentialVault instance
        """
        key = os.environ.get(env_var)
        if key:
            return cls(key.encode())
        return cls()
    
    def _generate_key(self) -> bytes:
        """Generate a new encryption key."""
        if HAS_FERNET:
            return Fernet.generate_key()
        return base64.urlsafe_b64encode(os.urandom(32))
    
    def store(
        self,
        credential_id: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store encrypted credential.
        
        Args:
            credential_id: Unique identifier for the credential
            value: Plaintext credential value
            metadata: Optional metadata (NOT encrypted)
        """
        if self._fernet:
            encrypted_value = self._fernet.encrypt(value.encode())
        else:
            # Basic encoding as fallback
            encrypted_value = base64.b64encode(value.encode())
        
        self._cache[credential_id] = {
            "value": encrypted_value,
            "metadata": metadata or {},
            "stored_at": datetime.utcnow().isoformat()
        }
        
        self._log_access(credential_id, "STORE")
        logger.debug(f"Credential stored: {credential_id[:8]}...")
    
    def retrieve(self, credential_id: str) -> Optional[str]:
        """
        Retrieve and decrypt credential.
        
        Args:
            credential_id: Credential identifier
            
        Returns:
            Decrypted credential value or None if not found
        """
        if credential_id not in self._cache:
            self._log_access(credential_id, "RETRIEVE_NOT_FOUND")
            logger.debug(f"Credential not found: {credential_id[:8]}...")
            return None
        
        try:
            encrypted_value = self._cache[credential_id]["value"]
            
            if self._fernet:
                decrypted = self._fernet.decrypt(encrypted_value).decode()
            else:
                decrypted = base64.b64decode(encrypted_value).decode()
            
            self._log_access(credential_id, "RETRIEVE")
            return decrypted
            
        except (InvalidToken, Exception) as e:
            logger.error(f"Failed to decrypt credential: {credential_id[:8]}...")
            self._log_access(credential_id, "RETRIEVE_FAILED")
            return None
    
    def delete(self, credential_id: str) -> bool:
        """
        Securely delete credential.
        
        Args:
            credential_id: Credential identifier
            
        Returns:
            True if deleted, False if not found
        """
        if credential_id in self._cache:
            # Overwrite with zeros before deleting
            if "value" in self._cache[credential_id]:
                self._cache[credential_id]["value"] = b'\x00' * 64
            del self._cache[credential_id]
            self._log_access(credential_id, "DELETE")
            logger.debug(f"Credential deleted: {credential_id[:8]}...")
            return True
        return False
    
    def exists(self, credential_id: str) -> bool:
        """Check if credential exists."""
        return credential_id in self._cache
    
    def get_metadata(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Get credential metadata without decrypting value."""
        if credential_id in self._cache:
            return self._cache[credential_id].get("metadata", {})
        return None
    
    def list_credentials(self) -> List[str]:
        """List all credential IDs (not values)."""
        return list(self._cache.keys())
    
    def _log_access(self, credential_id: str, action: str) -> None:
        """Log credential access for audit."""
        log_entry = {
            "credential_id": credential_id[:8] + "...",  # Partial ID only
            "action": action,
            "timestamp": datetime.utcnow().isoformat()
        }
        self._access_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-1000:]
    
    def get_access_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get credential access log for audit."""
        return self._access_log[-limit:]
    
    def clear_all(self) -> None:
        """Clear all credentials from cache."""
        for credential_id in list(self._cache.keys()):
            self.delete(credential_id)
        logger.info("All credentials cleared from vault")


def mask_credentials(func):
    """
    Decorator to mask credentials in function logs.
    
    Example:
        @mask_credentials
        async def connect(self, host: str, password: str):
            # password will not appear in logs
            ...
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        masked_kwargs = _mask_sensitive_kwargs(kwargs)
        logger.debug(f"Calling {func.__name__}", extra={"kwargs": masked_kwargs})
        return await func(*args, **kwargs)
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        masked_kwargs = _mask_sensitive_kwargs(kwargs)
        logger.debug(f"Calling {func.__name__}", extra={"kwargs": masked_kwargs})
        return func(*args, **kwargs)
    
    # Return appropriate wrapper based on function type
    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    return sync_wrapper


def _mask_sensitive_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Mask sensitive keyword arguments."""
    sensitive_keys = {
        'password', 'secret', 'key', 'token', 'credential',
        'api_key', 'apikey', 'auth', 'authorization', 'bearer',
        'private_key', 'access_key', 'secret_key'
    }
    
    masked = {}
    for k, v in kwargs.items():
        key_lower = k.lower()
        if any(s in key_lower for s in sensitive_keys):
            masked[k] = '***MASKED***'
        else:
            masked[k] = v
    
    return masked


def sanitize_log_message(message: str) -> str:
    """
    Remove credentials from log messages.
    
    Args:
        message: Log message that may contain credentials
        
    Returns:
        Sanitized message with credentials masked
    
    Example:
        msg = "Connecting with password=secret123"
        safe_msg = sanitize_log_message(msg)
        # Returns: "Connecting with password=***"
    """
    patterns = [
        # Key-value patterns
        (r'password["\']?\s*[:=]\s*["\']?[^\s"\']+', 'password=***'),
        (r'secret["\']?\s*[:=]\s*["\']?[^\s"\']+', 'secret=***'),
        (r'api_key["\']?\s*[:=]\s*["\']?[^\s"\']+', 'api_key=***'),
        (r'token["\']?\s*[:=]\s*["\']?[^\s"\']+', 'token=***'),
        (r'key["\']?\s*[:=]\s*["\']?[^\s"\']{16,}', 'key=***'),
        
        # Bearer tokens
        (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'Bearer ***'),
        
        # Basic auth
        (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic ***'),
        
        # Connection strings
        (r'://[^:]+:[^@]+@', '://***:***@'),
        
        # AWS keys
        (r'AKIA[A-Z0-9]{16}', 'AKIA***'),
        (r'aws_secret_access_key["\']?\s*[:=]\s*["\']?[^\s"\']+', 'aws_secret_access_key=***'),
        
        # Private keys
        (r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----', '***PRIVATE_KEY***'),
    ]
    
    result = message
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    
    return result


# Global vault instance (lazy initialization)
_global_vault: Optional[CredentialVault] = None


def get_vault() -> CredentialVault:
    """Get or create global vault instance."""
    global _global_vault
    if _global_vault is None:
        _global_vault = CredentialVault.from_env()
    return _global_vault
