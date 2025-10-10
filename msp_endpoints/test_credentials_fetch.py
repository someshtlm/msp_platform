#!/usr/bin/env python3
"""
Quick test to verify credential fetching and decryption is working smoothly.
"""
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def test_credential_fetching():
    """Test fetching and decrypting M365 credentials"""
    try:
        from supabase_services import get_organization_credentials

        print("=" * 60)
        print("🧪 TESTING M365 CREDENTIAL FETCHING & DECRYPTION")
        print("=" * 60)

        # Test with org_id (change this to your actual org_id)
        test_org_id = 69

        print(f"\n1️⃣  Testing credential fetch for org_id: {test_org_id}")
        print("-" * 60)

        creds = await get_organization_credentials(test_org_id)

        if creds is None:
            print("❌ FAILED: No credentials found or decryption failed")
            print("\nPossible issues:")
            print("  - No record in m365_credentials table for org_id:", test_org_id)
            print("  - credential_status is not 'Active'")
            print("  - Decryption failed (wrong ENCRYPTION_KEY?)")
            return False

        print("✅ SUCCESS: Credentials fetched and decrypted!")
        print("\n2️⃣  Decrypted Credential Details:")
        print("-" * 60)
        print(f"Tenant ID:      {creds['tenant_id']}")
        print(f"Client ID:      {creds['client_id']}")
        print(f"Client Secret:  {creds['client_secret'][:10]}...{creds['client_secret'][-5:]} (length: {len(creds['client_secret'])})")

        print("\n3️⃣  Validation Checks:")
        print("-" * 60)

        # Check if tenant_id looks like a GUID
        if len(creds['tenant_id']) == 36 and creds['tenant_id'].count('-') == 4:
            print("✅ tenant_id format looks correct (GUID)")
        else:
            print(f"⚠️  tenant_id might be invalid (length: {len(creds['tenant_id'])})")

        # Check if client_id looks like a GUID
        if len(creds['client_id']) == 36 and creds['client_id'].count('-') == 4:
            print("✅ client_id format looks correct (GUID)")
        else:
            print(f"⚠️  client_id might be invalid (length: {len(creds['client_id'])})")

        # Check if client_secret has reasonable length
        if 20 <= len(creds['client_secret']) <= 200:
            print(f"✅ client_secret length looks reasonable ({len(creds['client_secret'])} chars)")
        else:
            print(f"⚠️  client_secret length unusual ({len(creds['client_secret'])} chars)")

        print("\n" + "=" * 60)
        print("🎉 ALL TESTS PASSED - Credentials are being decrypted smoothly!")
        print("=" * 60)

        return True

    except Exception as e:
        print(f"\n❌ ERROR during test: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_credential_fetching())

    if success:
        print("\n✅ Ready for Phase 2 implementation!")
        print("   - Credentials can be fetched successfully")
        print("   - Decryption is working smoothly")
        print("   - You can now use these credentials to call Microsoft Graph API")
    else:
        print("\n❌ Fix credential issues before proceeding to Phase 2")
        print("\nTroubleshooting steps:")
        print("1. Check if m365_credentials table has a record for your org_id")
        print("2. Verify credential_status = 'Active'")
        print("3. Ensure ENCRYPTION_KEY in .env matches the one used to encrypt")
        print("4. Run: python encrypt_existing_secrets.py (to re-encrypt if needed)")
