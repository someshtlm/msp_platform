"""
Supabase client for credential management
"""
import os
import logging
from supabase import create_client, Client
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SupabaseCredentialManager:
    def __init__(self):
        self.supabase_url = os.getenv('SUPABASE_URL')
        self.supabase_key = os.getenv('SUPABASE_KEY')

        if not self.supabase_url or not self.supabase_key:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment")

        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)

    def get_credentials_by_account_id(self, account_id: int) -> Optional[Dict[str, Any]]:
        """
        NEW: Get integration credentials by account_id from integration_credentials table.
        Returns decrypted credentials ready to use.

        Args:
            account_id: Account ID (integer)

        Returns:
            Dict with decrypted autotask, ninjaone, connectsecure credentials
        """
        try:
            from src.services.encryption_manager import EncryptionManager

            # Fetch encrypted credentials from integration_credentials table
            response = self.supabase.table('integration_credentials')\
                .select('*')\
                .eq('account_id', account_id)\
                .eq('is_active', True)\
                .limit(1)\
                .execute()

            if not response.data or len(response.data) == 0:
                logger.error(f"No credentials found for account_id: {account_id}")
                return None

            encrypted_record = response.data[0]

            # Decrypt the credentials
            encryption_manager = EncryptionManager()
            credentials = encryption_manager.decrypt_integration_credentials(
                encrypted_record['credentials']
            )

            logger.info(f"Successfully retrieved and decrypted credentials for account_id: {account_id}")
            return credentials

        except Exception as e:
            logger.error(f"Failed to fetch/decrypt credentials for account_id {account_id}: {e}")
            return None

    def get_organization_by_id(self, org_id: int) -> Optional[Dict[str, Any]]:
        """
        NEW: Get organization-specific platform IDs using organization_integrations table.
        Uses get_org_integrations() RPC function to fetch platform IDs.

        Args:
            org_id: Organization ID (integer)

        Returns:
            Dict with ninjaone_org_id, autotask_id, connectsecure_id, account_id, organization_name
        """
        try:
            # Query organization_integrations table directly to avoid RPC function overloading conflict
            integrations_response = self.supabase.table('organization_integrations')\
                .select('organization_id, integration_id, integrations!inner(integration_key), platform_organization_id')\
                .eq('organization_id', org_id)\
                .execute()

            logger.info(f"=== INTEGRATIONS QUERY RESPONSE FOR ORG {org_id}: {integrations_response.data} ===")

            if not integrations_response.data or len(integrations_response.data) == 0:
                logger.error(f"No integrations found for org_id: {org_id}")
                return None

            # Get organization basic info
            org_response = self.supabase.table('organizations')\
                .select('id, account_id, organization_name')\
                .eq('id', org_id)\
                .limit(1)\
                .execute()

            if not org_response.data or len(org_response.data) == 0:
                logger.error(f"No organization found for org_id: {org_id}")
                return None

            org_basic_info = org_response.data[0]

            # Build org_data with platform IDs from integrations
            org_data = {
                'id': org_basic_info['id'],
                'account_id': org_basic_info['account_id'],
                'organization_name': org_basic_info['organization_name'],
                'name': org_basic_info['organization_name'],  # Backward compatibility
            }

            # Map integration_key to expected field names
            platform_mapping = {
                'ninjaone': 'ninjaone_org_id',
                'autotask': 'autotask_id',
                'connectsecure': 'connectsecure_id',
                'bitdefender': 'bitdefender_company_id'
            }

            # Extract platform IDs from table query response
            for integration in integrations_response.data:
                # Response format: {organization_id, integration_id, integrations: {integration_key}, platform_organization_id}
                integration_key = integration.get('integrations', {}).get('integration_key')
                platform_id = integration.get('platform_organization_id')

                logger.info(f"=== PROCESSING INTEGRATION: key={integration_key}, platform_id={platform_id} ===")

                if integration_key in platform_mapping:
                    field_name = platform_mapping[integration_key]
                    org_data[field_name] = platform_id
                    logger.info(f"=== MAPPED {integration_key} -> {field_name} = {platform_id} ===")

                    # Also add connectsecure_id variant for backward compatibility
                    if integration_key == 'connectsecure':
                        org_data['connect_secure_id'] = platform_id

            logger.info(f"=== FINAL ORG_DATA KEYS: {list(org_data.keys())} ===")
            logger.info(f"=== BITDEFENDER_COMPANY_ID IN ORG_DATA: {org_data.get('bitdefender_company_id')} ===")

            logger.info(f"Successfully retrieved organization data for org_id: {org_id} - {org_data.get('organization_name')}")
            logger.info(f"  Platform IDs: NinjaOne={org_data.get('ninjaone_org_id')}, Autotask={org_data.get('autotask_id')}, ConnectSecure={org_data.get('connectsecure_id')}, Bitdefender={org_data.get('bitdefender_company_id')}")

            return org_data

        except Exception as e:
            logger.error(f"Failed to fetch organization for org_id {org_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def get_credentials_by_id(self, credential_id: str = None) -> Optional[Dict[str, Any]]:
        """
        DEPRECATED: Get credentials by UUID from old user_credentials table.
        Use get_credentials_by_account_id() instead.
        """
        logger.warning("get_credentials_by_id() is DEPRECATED. Use get_credentials_by_account_id() instead.")
        try:
            if credential_id:
                # Get specific record by UUID - FIXED for newer Supabase client
                response = self.supabase.table('user_credentials').select("*").eq('id', credential_id).execute()
            else:
                # Get most recent record - FIXED for newer Supabase client
                response = self.supabase.table('user_credentials').select("*").order('created_at', desc=True).limit(1).execute()

            if response.data and len(response.data) > 0:
                return response.data[0]
            return None

        except Exception as e:
            logger.error(f"Failed to fetch credentials from Supabase: {e}")
            return None

    def save_credentials(self, credentials: Dict[str, Any], user_id: str) -> bool:
        """Save encrypted credentials to Supabase"""
        try:
            data = {
                **credentials,
                'created_by': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }

            response = self.supabase.table('user_credentials').insert(data).execute()
            return len(response.data) > 0

        except Exception as e:
            logger.error(f"Failed to save credentials to Supabase: {e}")
            return False