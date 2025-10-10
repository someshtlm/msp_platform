#!/usr/bin/env python3
"""
Test script to FETCH and DECRYPT integration_credentials from database
"""
import os
import sys
import json
from dotenv import load_dotenv

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

from src.services.encryption_manager import EncryptionManager
from supabase import create_client

def test_decryption():
    """Test fetching and decrypting integration credentials from database"""

    print("=" * 60)
    print("Integration Credentials Decryption Test")
    print("=" * 60)

    # Step 1: Initialize encryption manager
    print("\n[1/4] Initializing encryption manager...")
    try:
        encryption_manager = EncryptionManager()
        print("✅ Encryption manager initialized")
    except Exception as e:
        print(f"❌ Failed to initialize encryption manager: {e}")
        return

    # Step 2: Connect to Supabase
    print("\n[2/4] Connecting to Supabase...")
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')

    if not supabase_url or not supabase_key:
        print("❌ SUPABASE_URL or SUPABASE_KEY not found in environment")
        print("   Please update your .env file")
        return

    try:
        supabase = create_client(supabase_url, supabase_key)
        print("✅ Connected to Supabase")
    except Exception as e:
        print(f"❌ Failed to connect to Supabase: {e}")
        return

    # Step 3: Fetch encrypted credentials from database
    print("\n[3/4] Fetching encrypted credentials from database...")

    account_id_input = input("\nEnter account_id to test (or press Enter to fetch latest): ").strip()

    try:
        if account_id_input:
            account_id = int(account_id_input)
            print(f"\nFetching credentials for account_id: {account_id}...")
            response = supabase.table('integration_credentials')\
                .select('*')\
                .eq('account_id', account_id)\
                .eq('is_active', True)\
                .limit(1)\
                .execute()
        else:
            print("\nFetching latest credentials...")
            response = supabase.table('integration_credentials')\
                .select('*')\
                .eq('is_active', True)\
                .order('created_at', desc=True)\
                .limit(1)\
                .execute()

        if not response.data or len(response.data) == 0:
            print("❌ No credentials found in database")
            print("   Make sure you've run the encryption script first")
            return

        record = response.data[0]
        print("✅ Found credentials in database!")
        print(f"   Record ID: {record['id']}")
        print(f"   Account ID: {record['account_id']}")
        print(f"   Created at: {record.get('created_at', 'N/A')}")
        print(f"   Is Active: {record.get('is_active', 'N/A')}")

        encrypted_credentials = record['credentials']

        # Check if it has the correct format
        if not isinstance(encrypted_credentials, dict) or 'encrypted' not in encrypted_credentials:
            print("❌ Invalid credentials format in database")
            print(f"   Expected: {{'encrypted': '...'}}")
            print(f"   Got: {type(encrypted_credentials)}")
            return

        print(f"\n   Encrypted blob length: {len(encrypted_credentials['encrypted'])} characters")
        print(f"   First 50 chars: {encrypted_credentials['encrypted'][:50]}...")

    except ValueError:
        print("❌ Invalid account_id - must be a number")
        return
    except Exception as e:
        print(f"❌ Failed to fetch from database: {e}")
        import traceback
        traceback.print_exc()
        return

    # Step 4: Decrypt the credentials
    print("\n[4/4] Decrypting credentials...")
    try:
        decrypted_credentials = encryption_manager.decrypt_integration_credentials(encrypted_credentials)
        print("✅ Decryption successful!")

        # Display decrypted structure (without showing full secrets)
        print("\n📋 Decrypted Credentials Structure:")
        print("=" * 60)

        if 'autotask' in decrypted_credentials:
            print("\n🎫 Autotask:")
            autotask = decrypted_credentials['autotask']
            print(f"   ✓ autotask_base_url: {autotask.get('autotask_base_url', 'N/A')}")
            print(f"   ✓ autotask_username: {autotask.get('autotask_username', 'N/A')}")
            print(f"   ✓ autotask_integration_code: {autotask.get('autotask_integration_code', 'N/A')[:10]}...")
            print(f"   ✓ autotask_secret: {'*' * 20} (hidden)")

        if 'ninjaone' in decrypted_credentials:
            print("\n🥷 NinjaOne:")
            ninjaone = decrypted_credentials['ninjaone']
            print(f"   ✓ ninjaone_instance_url: {ninjaone.get('ninjaone_instance_url', 'N/A')}")
            print(f"   ✓ ninjaone_client_id: {ninjaone.get('ninjaone_client_id', 'N/A')[:10]}...")
            print(f"   ✓ ninjaone_scopes: {ninjaone.get('ninjaone_scopes', 'N/A')}")
            print(f"   ✓ ninjaone_client_secret: {'*' * 20} (hidden)")

        if 'connectsecure' in decrypted_credentials:
            print("\n🔒 ConnectSecure:")
            cs = decrypted_credentials['connectsecure']
            print(f"   ✓ connectsecure_base_url: {cs.get('connectsecure_base_url', 'N/A')}")
            print(f"   ✓ connectsecure_tenant_name: {cs.get('connectsecure_tenant_name', 'N/A')}")
            print(f"   ✓ connectsecure_client_id: {cs.get('connectsecure_client_id', 'N/A')[:15]}...")
            print(f"   ✓ connectsecure_client_secret_b64: {'*' * 20} (hidden)")

        print("\n" + "=" * 60)

        # Ask if user wants to see full JSON
        show_full = input("\n🔍 Show full decrypted JSON? (yes/no): ").strip().lower()
        if show_full in ['yes', 'y']:
            print("\n📄 Full Decrypted JSON:")
            print("=" * 60)
            print(json.dumps(decrypted_credentials, indent=2))
            print("=" * 60)

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return

    print("\n" + "=" * 60)
    print("✅ DECRYPTION TEST PASSED!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Credentials are properly encrypted and stored")
    print("2. Decryption is working correctly")
    print("3. Ready to integrate into the security_reporting_system")

if __name__ == "__main__":
    test_decryption()
