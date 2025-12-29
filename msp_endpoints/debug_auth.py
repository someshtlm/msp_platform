#!/usr/bin/env python3
"""
Debug script to test authentication flow
"""
import asyncio
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def test_auth():
    """Test the authentication flow step by step"""
    client_id = ""

    print("=== Testing Authentication Flow ===")
    print(f"Testing with client_id: {client_id}")

    # Test 1: Check environment variables
    print("\n1. Checking environment variables...")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    encryption_key = os.getenv("ENCRYPTION_KEY")

    print(f"   SUPABASE_URL: {'✓ Set' if supabase_url else '✗ Missing'}")
    print(f"   SUPABASE_KEY: {'✓ Set' if supabase_key else '✗ Missing'}")
    print(f"   ENCRYPTION_KEY: {'✓ Set' if encryption_key else '✗ Missing'}")

    if not all([supabase_url, supabase_key, encryption_key]):
        print("Missing required environment variables!")
        return

    # Test 2: Test Supabase connection
    print("\n2. Testing Supabase connection...")
    try:
        from supabase_services import supabase
        response = supabase.table('organization_mapping').select('*').limit(1).execute()
        print(f"   ✓ Supabase connection successful")
        print(f"   ✓ Found {len(response.data)} records in test query")
    except Exception as e:
        print(f" Supabase connection failed: {e}")
        return

    # Test 3: Check if client_id exists in database
    print(f"\n3. Checking if client_id exists in database...")
    try:
        response = supabase.table('organization_mapping').select('*').eq('client_id', client_id).execute()
        if response.data and len(response.data) > 0:
            print(f"Found record for client_id: {client_id}")
            record = response.data[0]
            print(f" Record has fields: {list(record.keys())}")
            print(f" tenant_id: {record.get('tenant_id', 'Missing')}")
            print(f" client_secret: {'Present' if record.get('client_secret') else 'Missing'}")
        else:
            print(f"  No record found for client_id: {client_id}")
            print(" Checking all client_ids in database...")
            all_records = supabase.table('organization_mapping').select('client_id').execute()
            if all_records.data:
                print(f"Found these client_ids:")
                for rec in all_records.data[:5]:  # Show first 5
                    print(f"      - {rec.get('client_id')}")
                if len(all_records.data) > 5:
                    print(f"      ... and {len(all_records.data) - 5} more")
            else:
                print(" No records found in organization_mapping table!")
            return
    except Exception as e:
        print(f" Database query failed: {e}")
        return

    # Test 4: Test decryption
    print(f"\n4. Testing decryption...")
    try:
        from crypto_utils import decrypt_client_secret
        encrypted_secret = record.get('client_secret')
        if encrypted_secret:
            decrypted = decrypt_client_secret(encrypted_secret)
            print(f"  Decryption successful")
            print(f" Decrypted length: {len(decrypted)} characters")
        else:
            print(f" No client_secret found in record")
            return
    except Exception as e:
        print(f"  Decryption failed: {e}")
        return

    # Test 5: Test full authentication flow
    print(f"\n5. Testing full authentication flow...")
    try:
        from supabase_services import get_tenant_credentials
        credentials = await get_tenant_credentials(client_id)
        if credentials:
            print(f" get_tenant_credentials() successful")
            print(f" Returned keys: {list(credentials.keys())}")
        else:
            print(f" get_tenant_credentials() returned None")
            return
    except Exception as e:
        print(f" get_tenant_credentials() failed: {e}")
        return

    # Test 6: Test token acquisition (without actually calling Microsoft)
    print(f"\n6. Testing token setup (without Microsoft call)...")
    try:
        from msal import ConfidentialClientApplication
        tenant_id = credentials['tenant_id']
        client_secret = credentials['client_secret']

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        msal_app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )
        print(f"MSAL app created successfully")
        print(f"Authority: {authority}")
    except Exception as e:
        print(f" MSAL setup failed: {e}")
        return

    print(f"\n All tests passed! Authentication should work.")

if __name__ == "__main__":
    asyncio.run(test_auth())




