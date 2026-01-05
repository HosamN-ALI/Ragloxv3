# ═══════════════════════════════════════════════════════════════
# SSH Key Manager
# Manages SSH keys for authentication
# ═══════════════════════════════════════════════════════════════

import logging
import os
from pathlib import Path
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("raglox.infrastructure.ssh.keys")


class SSHKeyManager:
    """
    Manages SSH key generation, storage, and validation.
    
    Features:
    - RSA and Ed25519 key generation
    - Key validation
    - Public key extraction
    - Key format conversion
    """
    
    @staticmethod
    def generate_rsa_key_pair(
        key_size: int = 4096,
        passphrase: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (2048, 3072, 4096)
            passphrase: Optional passphrase to encrypt private key
            
        Returns:
            Tuple of (private_key_pem, public_key_openssh)
        """
        logger.info(f"Generating RSA key pair ({key_size} bits)")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key
        encryption_algorithm = serialization.NoEncryption()
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(
                passphrase.encode('utf-8')
            )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')
        
        # Serialize public key (OpenSSH format)
        public_key = private_key.public_key()
        public_openssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        logger.info("RSA key pair generated successfully")
        return private_pem, public_openssh
    
    @staticmethod
    def generate_ed25519_key_pair(
        passphrase: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate Ed25519 key pair (modern, faster, more secure).
        
        Args:
            passphrase: Optional passphrase to encrypt private key
            
        Returns:
            Tuple of (private_key_pem, public_key_openssh)
        """
        logger.info("Generating Ed25519 key pair")
        
        # Generate private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # Serialize private key
        encryption_algorithm = serialization.NoEncryption()
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(
                passphrase.encode('utf-8')
            )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=encryption_algorithm
        ).decode('utf-8')
        
        # Serialize public key
        public_key = private_key.public_key()
        public_openssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        logger.info("Ed25519 key pair generated successfully")
        return private_pem, public_openssh
    
    @staticmethod
    def extract_public_key_from_private(
        private_key_content: str,
        passphrase: Optional[str] = None
    ) -> str:
        """
        Extract public key from private key.
        
        Args:
            private_key_content: Private key PEM content
            passphrase: Passphrase if key is encrypted
            
        Returns:
            Public key in OpenSSH format
        """
        try:
            password = passphrase.encode('utf-8') if passphrase else None
            
            # Load private key
            private_key = serialization.load_ssh_private_key(
                private_key_content.encode('utf-8'),
                password=password,
                backend=default_backend()
            )
            
            # Extract public key
            public_key = private_key.public_key()
            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')
            
            return public_openssh
            
        except Exception as e:
            logger.error(f"Failed to extract public key: {e}")
            raise ValueError(f"Invalid private key or passphrase: {e}")
    
    @staticmethod
    def validate_private_key(
        private_key_content: str,
        passphrase: Optional[str] = None
    ) -> bool:
        """
        Validate private key format and passphrase.
        
        Args:
            private_key_content: Private key content
            passphrase: Passphrase if key is encrypted
            
        Returns:
            True if valid
        """
        try:
            password = passphrase.encode('utf-8') if passphrase else None
            serialization.load_ssh_private_key(
                private_key_content.encode('utf-8'),
                password=password,
                backend=default_backend()
            )
            return True
        except Exception as e:
            logger.warning(f"Invalid private key: {e}")
            return False
    
    @staticmethod
    def save_key_to_file(
        key_content: str,
        file_path: str,
        permissions: int = 0o600
    ):
        """
        Save key to file with proper permissions.
        
        Args:
            key_content: Key content
            file_path: Path to save file
            permissions: File permissions (default: 0o600 for private keys)
        """
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write key
        path.write_text(key_content)
        
        # Set permissions
        os.chmod(file_path, permissions)
        
        logger.info(f"Key saved to {file_path} with permissions {oct(permissions)}")
    
    @staticmethod
    def load_key_from_file(file_path: str) -> str:
        """Load key from file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {file_path}")
        
        return path.read_text()
    
    @staticmethod
    def format_public_key_for_authorized_keys(
        public_key_openssh: str,
        comment: Optional[str] = None
    ) -> str:
        """
        Format public key for ~/.ssh/authorized_keys
        
        Args:
            public_key_openssh: Public key in OpenSSH format
            comment: Optional comment (e.g., email or identifier)
            
        Returns:
            Formatted key line
        """
        if comment:
            return f"{public_key_openssh.strip()} {comment}\n"
        return f"{public_key_openssh.strip()}\n"
    
    @staticmethod
    def generate_key_pair_for_agent(
        agent_id: str,
        key_type: str = "ed25519",
        passphrase: Optional[str] = None,
        save_to_disk: bool = False,
        keys_directory: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate key pair for an agent.
        
        Args:
            agent_id: Agent identifier
            key_type: 'rsa' or 'ed25519'
            passphrase: Optional passphrase
            save_to_disk: Save keys to disk
            keys_directory: Directory to save keys
            
        Returns:
            Tuple of (private_key, public_key)
        """
        logger.info(f"Generating {key_type} key pair for agent {agent_id}")
        
        # Generate keys
        if key_type.lower() == "rsa":
            private_key, public_key = SSHKeyManager.generate_rsa_key_pair(
                passphrase=passphrase
            )
        elif key_type.lower() == "ed25519":
            private_key, public_key = SSHKeyManager.generate_ed25519_key_pair(
                passphrase=passphrase
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Save to disk if requested
        if save_to_disk:
            if not keys_directory:
                keys_directory = os.path.expanduser("~/.raglox/ssh_keys")
            
            private_key_path = os.path.join(keys_directory, f"{agent_id}_id_{key_type}")
            public_key_path = f"{private_key_path}.pub"
            
            SSHKeyManager.save_key_to_file(
                private_key,
                private_key_path,
                permissions=0o600
            )
            SSHKeyManager.save_key_to_file(
                public_key,
                public_key_path,
                permissions=0o644
            )
            
            logger.info(f"Keys saved: {private_key_path}")
        
        return private_key, public_key
