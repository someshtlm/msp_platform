#!/usr/bin/env python3
"""
Simple Credential Decryption Script
====================================
Decrypts credentials from integration_credentials table using account_id
"""

import sys
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config.supabase_client import SupabaseCredentialManager
from src.services.encryption_manager import EncryptionManager

def decrypt_credentials_by_account_id(account_id: int):
    """Decrypt credentials for a specific account_id."""

    print(f" Fetching credentials for account_id: {account_id}")

    # Initialize managers
    encryption_manager = EncryptionManager()

    # Get Supabase client
    from config.supabase_client import SupabaseCredentialManager
    supabase_manager = SupabaseCredentialManager()

    # Fetch encrypted credentials from integration_credentials table
    response = supabase_manager.supabase.table('integration_credentials')\
        .select('*')\
        .eq('account_id', account_id)\
        .eq('is_active', True)\
        .execute()

    if not response.data or len(response.data) == 0:
        print(f" No credentials found for account_id: {account_id}")
        return None

    record = response.data[0]
    print(f" Found credentials record")
    print(f"   Record ID: {record.get('id')}")
    print(f"   Account ID: {record.get('account_id')}")

    try:
        # The 'credentials' column contains JSONB encrypted data
        encrypted_credentials_jsonb = record.get('credentials')

        if not encrypted_credentials_jsonb:
            print(f" No credentials data in the record")
            return None

        print(f"    Encrypted credentials found (JSONB)")
        print(f"   Platforms in credentials: {list(encrypted_credentials_jsonb.keys())}")

        # Decrypt the credentials JSONB
        decrypted = encryption_manager.decrypt_integration_credentials(encrypted_credentials_jsonb)

        print(f"   ✅ Decryption successful!")
        print(f"   Decrypted platforms: {list(decrypted.keys())}")

        return decrypted

    except Exception as e:
        print(f"    Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    # Get account_id from command line or use default
    if len(sys.argv) > 1:
        account_id = int(sys.argv[1])
    else:
        # Default account_id for testing
        account_id = 4  # CHANGE THIS TO YOUR ACCOUNT_ID

    print("=" * 60)
    print(" CREDENTIAL DECRYPTION TOOL")
    print("=" * 60)

    results = decrypt_credentials_by_account_id(account_id)

    if results:
        print("\n" + "=" * 60)
        print("DECRYPTED CREDENTIALS (RAW JSON):")
        print("=" * 60)

        # 🔥 NEW: Print ENTIRE decrypted JSON object exactly as saved
        print(json.dumps(results, indent=4, ensure_ascii=False))

        print("\n" + "=" * 60)
        print(" Decryption complete!")
        print("=" * 60)
    else:
        print("\n No credentials decrypted")
