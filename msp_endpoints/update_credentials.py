import os
import asyncio
import logging
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables FIRST before importing crypto_utils
load_dotenv()

from supabase import create_client, Client
from crypto_utils import encrypt_client_secret

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Supabase client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


async def update_organization_credentials(
    organization_name: str,
    client_id: str,
    tenant_id: str,
    client_secret: str
):
    """
    Update organization credentials by organization name.
    The client_secret will be automatically encrypted before storage.

    Args:
        organization_name: Name of the organization to update
        client_id: Microsoft Application (Client) ID
        tenant_id: Microsoft Directory (Tenant) ID
        client_secret: Microsoft Client Secret (will be encrypted)
    """
    try:
        logger.info(f"Updating credentials for organization: {organization_name}")

        # First, check if organization exists
        existing_org = supabase.table("organization_mapping").select("ninjaone_org_id, organization_name").eq("organization_name", organization_name).execute()

        if not existing_org.data:
            logger.error(f"Organization '{organization_name}' not found")
            return False

        ninjaone_org_id = existing_org.data[0]["ninjaone_org_id"]
        logger.info(f"Found organization with ninjaone_org_id: {ninjaone_org_id}")

        # Encrypt the client_secret
        try:
            encrypted_secret = encrypt_client_secret(client_secret)
            logger.info("Client secret encrypted successfully")
        except Exception as e:
            logger.error(f"Failed to encrypt client_secret: {str(e)}")
            return False

        # Prepare update data
        update_data = {
            "client_id": client_id,
            "tenant_id": tenant_id,
            "client_secret": encrypted_secret,
            "updated_at": datetime.now().isoformat()
        }

        # Update the record
        result = supabase.table("organization_mapping").update(update_data).eq("ninjaone_org_id", ninjaone_org_id).execute()

        if result.data:
            logger.info(f"Successfully updated credentials for {organization_name}")
            logger.info(f"Updated fields: client_id, tenant_id, client_secret (encrypted)")
            return True
        else:
            logger.error("Update operation failed - no data returned")
            return False

    except Exception as e:
        logger.error(f"Error updating organization credentials: {str(e)}")
        return False


async def update_by_ninjaone_org_id(
    ninjaone_org_id: str,
    client_id: str,
    tenant_id: str,
    client_secret: str
):
    """
    Update organization credentials by ninjaone_org_id.
    The client_secret will be automatically encrypted before storage.

    Args:
        ninjaone_org_id: NinjaOne Organization ID
        client_id: Microsoft Application (Client) ID
        tenant_id: Microsoft Directory (Tenant) ID
        client_secret: Microsoft Client Secret (will be encrypted)
    """
    try:
        logger.info(f"Updating credentials for ninjaone_org_id: {ninjaone_org_id}")

        # First, check if organization exists
        existing_org = supabase.table("organization_mapping").select("ninjaone_org_id, organization_name").eq("ninjaone_org_id", ninjaone_org_id).execute()

        if not existing_org.data:
            logger.error(f"Organization with ninjaone_org_id '{ninjaone_org_id}' not found")
            return False

        org_name = existing_org.data[0]["organization_name"]
        logger.info(f"Found organization '{org_name}' with ninjaone_org_id: {ninjaone_org_id}")

        # Encrypt the client_secret
        try:
            encrypted_secret = encrypt_client_secret(client_secret)
            logger.info("Client secret encrypted successfully")
        except Exception as e:
            logger.error(f"Failed to encrypt client_secret: {str(e)}")
            return False

        # Prepare update data
        update_data = {
            "client_id": client_id,
            "tenant_id": tenant_id,
            "client_secret": encrypted_secret,
            "updated_at": datetime.now().isoformat()
        }

        # Update the record
        result = supabase.table("organization_mapping").update(update_data).eq("ninjaone_org_id", ninjaone_org_id).execute()

        if result.data:
            logger.info(f"Successfully updated credentials for {org_name}")
            logger.info(f"Updated fields: client_id, tenant_id, client_secret (encrypted)")
            return True
        else:
            logger.error("Update operation failed - no data returned")
            return False

    except Exception as e:
        logger.error(f"Error updating organization credentials: {str(e)}")
        return False


async def list_organizations():
    """List all organizations to help identify which one to update"""
    try:
        result = supabase.table("organization_mapping").select("ninjaone_org_id, organization_name, client_id, domain, status").execute()

        if result.data:
            print("\n=== Available Organizations ===")
            for org in result.data:
                print(f"Name: {org.get('organization_name')}")
                print(f"NinjaOne Org ID: {org.get('ninjaone_org_id')}")
                print(f"Current Client ID: {org.get('client_id')}")
                print(f"Domain: {org.get('domain')}")
                print(f"Status: {org.get('status')}")
                print("-" * 40)
        else:
            print("No organizations found")

    except Exception as e:
        logger.error(f"Error listing organizations: {str(e)}")


async def main():
    """
    Main function - Update this with your specific values
    """

    # First, list available organizations
    await list_organizations()


    # success = await update_organization_credentials(
    #     organization_name="Your Organization Name",
    #     client_id="your-client-id-here",
    #     tenant_id="your-tenant-id-here",
    #     client_secret="your-client-secret-here"
    # )



    print("\nUncomment and modify the example above with your actual values to update credentials.")


if __name__ == "__main__":
    asyncio.run(main())