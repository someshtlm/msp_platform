"""
Configuration module with Supabase integration
"""
import os
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
        self._credentials = None
        self._encryption_manager = None
        self._supabase_manager = None

    @property
    def encryption_manager(self):
        if self._encryption_manager is None:
            # Add path resolution for local running
            import sys
            current_dir = os.path.dirname(os.path.abspath(__file__))
            security_system_root = os.path.join(current_dir, '..')
            if security_system_root not in sys.path:
                sys.path.insert(0, security_system_root)

            from src.services.encryption_manager import EncryptionManager
            self._encryption_manager = EncryptionManager()
        return self._encryption_manager

    @property
    def supabase_manager(self):
        if self._supabase_manager is None:
            # Smart imports - try absolute first (for msp_endpoints), fallback to relative (for standalone)
            try:
                from security_reporting_system.config.supabase_client import SupabaseCredentialManager
            except ImportError:
                from config.supabase_client import SupabaseCredentialManager
            self._supabase_manager = SupabaseCredentialManager()
        return self._supabase_manager

    def load_credentials(self, credential_id: str = None) -> Dict[str, Any]:
        """Load and decrypt credentials from Supabase"""
        if self._credentials is None:
            # Use default credential ID if none provided
            credential_id = credential_id or os.getenv('DEFAULT_CREDENTIAL_ID', '4ffdf31a-9ea7-4962-a8ff-4ef440c793f3')

            # Load from Supabase
            encrypted_creds = self.supabase_manager.get_credentials_by_id(credential_id)

            if encrypted_creds:
                # Decrypt the credentials
                self._credentials = self.encryption_manager.decrypt_credentials(encrypted_creds)
                logger.info("Credentials loaded from Supabase")
            else:
                # No credentials found
                raise ValueError(f"No credentials found in Supabase for ID: {credential_id}")

        return self._credentials

    def save_credentials(self, credentials: Dict[str, Any], user_id: str = None) -> bool:
        """Encrypt and save credentials to Supabase"""
        user_id = user_id or os.getenv('DEFAULT_USER_ID', 'system_user')

        # Encrypt sensitive fields
        encrypted_creds = self.encryption_manager.encrypt_credentials(credentials)

        # Save to Supabase
        return self.supabase_manager.save_credentials(encrypted_creds, user_id)

# Global config manager instance
config_manager = ConfigManager()



# Lazy loading function - only loads when called
def get_config():
    return config_manager.load_credentials()


# Keep existing constants that don't require credentials
DEFAULT_TIMEOUT = 30
TOKEN_BUFFER_SECONDS = 300
DEFAULT_PAGE_SIZE = 1000
MAX_PAGES = 10