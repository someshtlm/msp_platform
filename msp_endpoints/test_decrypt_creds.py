import asyncio
from dotenv import load_dotenv
load_dotenv()

from supabase_services import get_organization_credentials

async def test():
    # Replace with your organization_id
    org_id = 69

    print(f"Testing credential retrieval for org_id: {org_id}")
    creds = await get_organization_credentials(org_id)

    if creds:
        print("✅ Credentials retrieved successfully!")
        print(f"   Tenant ID:{creds['tenant_id']}")
        print(f"   Client ID:{creds['client_id']}")
        print(f"   Client Secret:{creds['client_secret']}")
    else:
        print("❌ Failed to retrieve credentials")

asyncio.run(test())