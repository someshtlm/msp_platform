import os
import logging
from typing import Optional, Dict
from supabase import create_client, Client
from crypto_utils import decrypt_client_secret

logger = logging.getLogger(__name__)

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


async def get_organization_credentials(org_id: int) -> Optional[Dict[str, str]]:
    """
    Retrieve and decrypt M365 credentials for an organization.

    Args:
        org_id: Organization ID (from organizations.id)

    Returns:
        Dictionary with decrypted tenant_id, client_id, and client_secret, or None if not found
    """
    try:
        # Query m365_credentials table
        response = supabase.table('m365_credentials')\
            .select('tenant_id, client_id, client_secret, credential_status')\
            .eq('organization_id', org_id)\
            .limit(1)\
            .execute()

        if not response.data:
            logger.error(f"No M365 credentials found for org_id: {org_id}")
            return None

        creds = response.data[0]

        # Check credential status
        if creds.get('credential_status') != 'Active':
            logger.error(f"M365 credentials inactive for org_id: {org_id}")
            return None

        # Decrypt all three fields
        try:
            decrypted_tenant_id = decrypt_client_secret(creds['tenant_id'])
            decrypted_client_id = decrypt_client_secret(creds['client_id'])
            decrypted_client_secret = decrypt_client_secret(creds['client_secret'])

            return {
                'tenant_id': decrypted_tenant_id,
                'client_id': decrypted_client_id,
                'client_secret': decrypted_client_secret
            }
        except ValueError as e:
            logger.error(f"Failed to decrypt credentials for org_id {org_id}: {str(e)}")
            return None

    except Exception as e:
        logger.error(f"Error retrieving credentials for org_id {org_id}: {e}")
        return None


# Legacy function - DEPRECATED - Use get_organization_credentials instead
async def get_tenant_credentials(client_id: str) -> Optional[Dict[str, str]]:
    """
    DEPRECATED: This function uses the old organization_mapping table.
    Use get_organization_credentials(org_id) instead.

    Fetch tenant credentials from Supabase based on client_id
    The client_secret is automatically decrypted before returning.

    Args:
        client_id: The client ID to look up

    Returns:
        Dictionary with tenant_id and decrypted client_secret, or None if not found
    """
    logger.warning("get_tenant_credentials() is DEPRECATED. Use get_organization_credentials(org_id) instead.")
    return None


async def get_credentials_by_ninjaone_id(ninjaone_org_id: str) -> Optional[Dict[str, str]]:
    """
    Fetch M365 credentials from Supabase based on ninjaone_org_id.
    First resolves ninjaone_org_id to organization_id, then fetches credentials.

    Args:
        ninjaone_org_id: The NinjaOne organization ID to look up

    Returns:
        Dictionary with decrypted tenant_id, client_id, and client_secret, or None if not found
    """
    try:
        # First, find the organization_id from organizations table using ninjaone_org_id
        org_response = supabase.table('organizations')\
            .select('id')\
            .eq('ninjaone_org_id', ninjaone_org_id)\
            .limit(1)\
            .execute()

        if not org_response.data:
            logger.warning(f"No organization found for ninjaone_org_id: {ninjaone_org_id}")
            return None

        org_id = org_response.data[0]['id']

        # Now fetch credentials using organization_id
        return await get_organization_credentials(org_id)

    except Exception as e:
        logger.error(f"Error fetching credentials for ninjaone_org_id {ninjaone_org_id}: {str(e)}")
        return None


# Legacy function - DEPRECATED
async def get_tenant_credentials_by_ninjaone_id(ninjaone_org_id: str) -> Optional[Dict[str, str]]:
    """
    DEPRECATED: Use get_credentials_by_ninjaone_id instead.
    """
    logger.warning("get_tenant_credentials_by_ninjaone_id() is DEPRECATED. Use get_credentials_by_ninjaone_id() instead.")
    return await get_credentials_by_ninjaone_id(ninjaone_org_id)


async def get_credentials_by_client_id(client_id: str) -> Optional[Dict[str, str]]:
    """
    Fetch M365 credentials from Supabase by matching decrypted client_id.
    This provides backward compatibility for old endpoints that use client_id.

    Args:
        client_id: The decrypted client_id to match (UUID format)

    Returns:
        Dictionary with decrypted tenant_id, client_id, and client_secret, or None if not found
    """
    try:
        from crypto_utils import encrypt_client_secret

        # Encrypt the provided client_id to match against database
        encrypted_client_id = encrypt_client_secret(client_id)

        # Query m365_credentials table by encrypted client_id
        response = supabase.table('m365_credentials')\
            .select('organization_id, tenant_id, client_id, client_secret, credential_status')\
            .eq('client_id', encrypted_client_id)\
            .limit(1)\
            .execute()

        if not response.data:
            logger.error(f"No M365 credentials found for client_id: {client_id}")
            return None

        creds = response.data[0]

        # Check credential status
        if creds.get('credential_status') != 'Active':
            logger.error(f"M365 credentials inactive for client_id: {client_id}")
            return None

        # Decrypt all three fields
        try:
            decrypted_tenant_id = decrypt_client_secret(creds['tenant_id'])
            decrypted_client_id = decrypt_client_secret(creds['client_id'])
            decrypted_client_secret = decrypt_client_secret(creds['client_secret'])

            return {
                'tenant_id': decrypted_tenant_id,
                'client_id': decrypted_client_id,
                'client_secret': decrypted_client_secret
            }
        except ValueError as e:
            logger.error(f"Failed to decrypt credentials for client_id {client_id}: {str(e)}")
            return None

    except Exception as e:
        logger.error(f"Error retrieving credentials by client_id {client_id}: {e}")
        return None


async def get_credentials_by_identifier(identifier: str, identifier_type: str) -> Optional[Dict[str, str]]:
    """
    Universal function to fetch M365 credentials by org_id, ninjaone_org_id, or client_id

    Args:
        identifier: The identifier value (org_id, ninjaone_org_id, or client_id)
        identifier_type: Either "org_id", "ninjaone_org_id", or "client_id"

    Returns:
        Dictionary with decrypted tenant_id, client_id, and client_secret, or None if not found
    """
    if identifier_type == "org_id":
        return await get_organization_credentials(int(identifier))
    elif identifier_type == "ninjaone_org_id":
        return await get_credentials_by_ninjaone_id(identifier)
    elif identifier_type == "client_id":
        return await get_credentials_by_client_id(identifier)
    else:
        logger.error(f"Invalid identifier_type: {identifier_type}")
        return None