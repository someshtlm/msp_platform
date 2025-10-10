from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import logging

logger = logging.getLogger(__name__)


class EncryptionManager:
    def __init__(self, master_key: str = None):
        """Initialize with master key from environment"""
        if not master_key:
            master_key = os.getenv('ENCRYPTION_KEY')  # Changed from MASTER_ENCRYPTION_KEY

        if not master_key:
            raise ValueError("ENCRYPTION_KEY not found in environment")

        self.master_key = master_key.encode()

    def _derive_key(self, salt: bytes = None) -> Fernet:
        """Derive encryption key from master key"""
        if salt is None:
            salt = b'stable_salt_12345678'  # Use consistent salt for same data

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key))
        return Fernet(key)

    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt a single field"""
        if not plaintext:
            return plaintext

        try:
            f = self._derive_key()
            encrypted_bytes = f.encrypt(plaintext.encode())
            return base64.urlsafe_b64encode(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_field(self, encrypted_text: str) -> str:
        """Decrypt a single field"""
        if not encrypted_text:
            return encrypted_text

        try:
            f = self._derive_key()
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted_bytes = f.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def encrypt_credentials(self, credentials: dict) -> dict:
        """Encrypt all sensitive fields in credentials dict"""
        sensitive_fields = [
            'ninjaone_client_secret',
            'autotask_secret',
            'connectsecure_client_secret_b64'
        ]

        encrypted_creds = credentials.copy()

        for field in sensitive_fields:
            if field in encrypted_creds and encrypted_creds[field]:
                encrypted_creds[field] = self.encrypt_field(encrypted_creds[field])

        return encrypted_creds

    def decrypt_credentials(self, encrypted_credentials: dict) -> dict:
        """Decrypt all sensitive fields in credentials dict"""
        sensitive_fields = [
            'ninjaone_client_secret',
            'autotask_secret',
            'connectsecure_client_secret_b64'
        ]

        decrypted_creds = encrypted_credentials.copy()

        for field in sensitive_fields:
            if field in decrypted_creds and decrypted_creds[field]:
                decrypted_creds[field] = self.decrypt_field(decrypted_creds[field])

        return decrypted_creds

    def encrypt_integration_credentials(self, credentials: dict) -> dict:
        """
        Encrypt entire credentials dict for integration_credentials table.
        Returns JSONB format: {"encrypted": "base64_encrypted_blob"}

        Args:
            credentials: Dict containing autotask, ninjaone, connectsecure credentials

        Returns:
            Dict with encrypted blob: {"encrypted": "..."}
        """
        import json
        try:
            # Convert credentials dict to JSON string
            credentials_json = json.dumps(credentials)

            # Encrypt the entire JSON string
            f = self._derive_key()
            encrypted_bytes = f.encrypt(credentials_json.encode())
            encrypted_blob = base64.urlsafe_b64encode(encrypted_bytes).decode()

            # Return in JSONB wrapper format
            return {"encrypted": encrypted_blob}
        except Exception as e:
            logger.error(f"Failed to encrypt integration credentials: {e}")
            raise

    def decrypt_integration_credentials(self, encrypted_data: dict) -> dict:
        """
        Decrypt credentials from integration_credentials table.
        Expects JSONB format: {"encrypted": "base64_encrypted_blob"}

        Args:
            encrypted_data: Dict containing {"encrypted": "blob"}

        Returns:
            Decrypted credentials dict with autotask, ninjaone, connectsecure
        """
        import json
        try:
            # Extract encrypted blob from wrapper
            if "encrypted" not in encrypted_data:
                raise ValueError("Invalid encrypted data format - missing 'encrypted' key")

            encrypted_blob = encrypted_data["encrypted"]

            # Decrypt the blob
            f = self._derive_key()
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_blob.encode())
            decrypted_bytes = f.decrypt(encrypted_bytes)
            decrypted_json = decrypted_bytes.decode()

            # Parse JSON back to dict
            credentials = json.loads(decrypted_json)
            return credentials
        except Exception as e:
            logger.error(f"Failed to decrypt integration credentials: {e}")
            raise