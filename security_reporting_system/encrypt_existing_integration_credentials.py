#!/usr/bin/env python3
"""
Script to encrypt existing PLAIN TEXT credentials in integration_credentials table
This will UPDATE existing rows with encrypted versions
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

def encrypt_existing_credentials():
    """Encrypt plain text credentials already in the database"""

    print("=" * 60)
    print("Encrypt Existing Integration Credentials")
    print("=" * 60)

    # Step 1: Initialize encryption manager
    print("\n[1/5] Initializing encryption manager...")
    try:
        encryption_manager = EncryptionManager()
        print("✅ Encryption manager initialized")
    except Exception as e:
        print(f"❌ Failed to initialize encryption manager: {e}")
        return

    # Step 2: Connect to Supabase
    print("\n[2/5] Connecting to Supabase...")
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')

    if not supabase_url or not supabase_key:
        print("❌ SUPABASE_URL or SUPABASE_KEY not found in environment")
        return

    try:
        supabase = create_client(supabase_url, supabase_key)
        print("✅ Connected to Supabase")
    except Exception as e:
        print(f"❌ Failed to connect to Supabase: {e}")
        return

    # Step 3: Fetch all plain text credentials
    print("\n[3/5] Fetching credentials from database...")

    account_id_input = input("\nEnter account_id to encrypt (or 'all' for all records): ").strip()

    try:
        if account_id_input.lower() == 'all':
            print("\nFetching ALL credentials...")
            response = supabase.table('integration_credentials')\
                .select('*')\
                .execute()
        else:
            account_id = int(account_id_input)
            print(f"\nFetching credentials for account_id: {account_id}...")
            response = supabase.table('integration_credentials')\
                .select('*')\
                .eq('account_id', account_id)\
                .execute()

        if not response.data or len(response.data) == 0:
            print("❌ No credentials found in database")
            return

        records = response.data
        print(f"✅ Found {len(records)} record(s) to process")

        # Show what will be encrypted
        print("\n📋 Records to encrypt:")
        for i, record in enumerate(records, 1):
            print(f"\n{i}. Record ID: {record['id']} | Account ID: {record['account_id']}")

            creds = record['credentials']

            # Check if already encrypted
            if isinstance(creds, dict) and 'encrypted' in creds:
                print("   ⚠️  Already encrypted - WILL SKIP")
                continue

            # Show what's inside (plain text)
            if isinstance(creds, dict):
                has_autotask = 'autotask' in creds
                has_ninjaone = 'ninjaone' in creds
                has_cs = 'connectsecure' in creds
                print(f"   ✓ Autotask: {'YES' if has_autotask else 'NO'}")
                print(f"   ✓ NinjaOne: {'YES' if has_ninjaone else 'NO'}")
                print(f"   ✓ ConnectSecure: {'YES' if has_cs else 'NO'}")
                print("   Status: PLAIN TEXT - needs encryption")

    except ValueError:
        print("❌ Invalid account_id - must be a number or 'all'")
        return
    except Exception as e:
        print(f"❌ Failed to fetch from database: {e}")
        return

    # Step 4: Confirm before encrypting
    print("\n" + "=" * 60)
    confirm = input("🔐 Encrypt these credentials? (yes/no): ").strip().lower()

    if confirm not in ['yes', 'y']:
        print("❌ Operation cancelled")
        return

    # Step 5: Encrypt and update each record
    print("\n[4/5] Encrypting and updating records...")

    encrypted_count = 0
    skipped_count = 0
    failed_count = 0

    for i, record in enumerate(records, 1):
        record_id = record['id']
        account_id = record['account_id']
        credentials = record['credentials']

        print(f"\n[{i}/{len(records)}] Processing Record ID {record_id} (Account {account_id})...")

        try:
            # Skip if already encrypted
            if isinstance(credentials, dict) and 'encrypted' in credentials:
                print("   ⏭️  Already encrypted - skipping")
                skipped_count += 1
                continue

            # Encrypt the plain text credentials
            print("   🔐 Encrypting...")
            encrypted_data = encryption_manager.encrypt_integration_credentials(credentials)

            print(f"   ✅ Encrypted successfully ({len(encrypted_data['encrypted'])} chars)")

            # Update in database
            print("   💾 Updating database...")
            update_response = supabase.table('integration_credentials')\
                .update({'credentials': encrypted_data})\
                .eq('id', record_id)\
                .execute()

            if update_response.data:
                print("   ✅ Database updated!")
                encrypted_count += 1
            else:
                print("   ❌ Failed to update database")
                failed_count += 1

        except Exception as e:
            print(f"   ❌ Error: {e}")
            failed_count += 1
            continue

    # Step 6: Summary
    print("\n" + "=" * 60)
    print("📊 ENCRYPTION SUMMARY")
    print("=" * 60)
    print(f"✅ Successfully encrypted: {encrypted_count} record(s)")
    print(f"⏭️  Skipped (already encrypted): {skipped_count} record(s)")
    print(f"❌ Failed: {failed_count} record(s)")
    print("=" * 60)

    if encrypted_count > 0:
        print("\n✅ Encryption complete!")
        print("\nNext steps:")
        print("1. Run test_integration_decryption.py to verify")
        print("2. Delete any duplicate rows if needed")
        print("3. Proceed with code integration")

if __name__ == "__main__":
    encrypt_existing_credentials()
