import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class CryptoManager:
    def __init__(self):
        self._fernet = None
        self._initialize_encryption()

    def _initialize_encryption(self):
        """Initialize the encryption key from environment variable"""
        encryption_key = os.getenv("ENCRYPTION_KEY")

        if not encryption_key:
            raise ValueError("ENCRYPTION_KEY must be set in environment variables")

        # If the key is a password, derive a proper Fernet key from it
        if len(encryption_key) != 44:  # Fernet keys are 44 characters when base64 encoded
            # Derive key from password using PBKDF2
            salt = b'stable_salt_for_consistency'  # Use a consistent salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
        else:
            # Use the key directly if it's already properly formatted
            key = encryption_key.encode()

        self._fernet = Fernet(key)

    def encrypt_secret(self, secret: str) -> str:
        """
        Encrypt a client secret

        Args:
            secret: The plaintext secret to encrypt

        Returns:
            Base64 encoded encrypted secret
        """
        try:
            encrypted_bytes = self._fernet.encrypt(secret.encode())
            return base64.urlsafe_b64encode(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Error encrypting secret: {str(e)}")
            raise ValueError("Failed to encrypt secret")

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """
        Decrypt a client secret

        Args:
            encrypted_secret: The base64 encoded encrypted secret

        Returns:
            Decrypted plaintext secret
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_secret.encode())
            decrypted_bytes = self._fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Error decrypting secret: {str(e)}")
            raise ValueError("Failed to decrypt secret")


# Global instance
crypto_manager = CryptoManager()


def encrypt_client_secret(secret: str) -> str:
    """Convenience function to encrypt a client secret"""
    return crypto_manager.encrypt_secret(secret)


def decrypt_client_secret(encrypted_secret: str) -> str:
    """Convenience function to decrypt a client secret"""
    return crypto_manager.decrypt_secret(encrypted_secret)