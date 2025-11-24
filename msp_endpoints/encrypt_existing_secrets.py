#!/usr/bin/env python3
"""
Script to encrypt existing plain text credentials in m365_credentials table.
Encrypts: tenant_id, client_id, client_secret
"""
import asyncio
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def encrypt_existing_secrets():
    """Encrypt all plain text credentials (tenant_id, client_id, client_secret) in m365_credentials table"""
    try:
        from supabase_services import supabase
        from crypto_utils import encrypt_client_secret

        print("=== Encrypting Existing M365 Credentials ===")
        print("This script will encrypt: tenant_id, client_id, client_secret")

        # Get all records from m365_credentials
        print("\n1. Fetching all records from m365_credentials table...")
        response = supabase.table('m365_credentials').select('*').execute()

        if not response.data:
            print("No records found in m365_credentials table!")
            return

        print(f"Found {len(response.data)} total records")

        # Filter records that have credentials to encrypt
        records_to_encrypt = []
        for record in response.data:
            # Check if record has the required fields
            has_tenant_id = record.get('tenant_id') and record.get('tenant_id').strip()
            has_client_id = record.get('client_id') and record.get('client_id').strip()
            has_client_secret = record.get('client_secret') and record.get('client_secret').strip()

            if has_tenant_id or has_client_id or has_client_secret:
                records_to_encrypt.append(record)

        print(f"Found {len(records_to_encrypt)} records with credentials to encrypt")

        if len(records_to_encrypt) == 0:
            print("No records have credentials to encrypt!")
            return

        # Show records that will be updated
        print("\nRecords that will be encrypted:")
        for i, record in enumerate(records_to_encrypt, 1):
            org_id = record.get('organization_id', 'Unknown')
            tenant_preview = record.get('tenant_id', '')[:10] + "..." if len(record.get('tenant_id', '')) > 10 else record.get('tenant_id', '')
            client_preview = record.get('client_id', '')[:10] + "..." if len(record.get('client_id', '')) > 10 else record.get('client_id', '')
            secret_preview = record.get('client_secret', '')[:10] + "..." if len(record.get('client_secret', '')) > 10 else record.get('client_secret', '')
            print(f"  {i}. Organization ID: {org_id}")
            print(f"     tenant_id: {tenant_preview}")
            print(f"     client_id: {client_preview}")
            print(f"     client_secret: {secret_preview}")

        # Confirm before proceeding
        print("\n" + "="*50)
        proceed = input("Do you want to encrypt these credentials? (yes/no): ").strip().lower()

        if proceed not in ['yes', 'y']:
            print("Operation cancelled.")
            return

        print("\n2. Starting encryption process...")

        # Process each record
        updated_count = 0
        failed_count = 0

        for i, record in enumerate(records_to_encrypt, 1):
            try:
                org_id = record.get('organization_id', f"Record {i}")
                record_id = record.get('id')
                tenant_id = record.get('tenant_id', '')
                client_id = record.get('client_id', '')
                client_secret = record.get('client_secret', '')

                print(f"\nProcessing {i}/{len(records_to_encrypt)}: Organization ID {org_id}")

                # Prepare update data
                update_data = {}

                # Encrypt tenant_id if present
                if tenant_id and tenant_id.strip():
                    # Check if already encrypted (basic check - encrypted values are longer)
                    if len(tenant_id) > 100 and '=' in tenant_id[-10:]:
                        print(f"  ⚠️  tenant_id appears already encrypted (length: {len(tenant_id)})")
                    else:
                        print(f"  🔐 Encrypting tenant_id (current length: {len(tenant_id)})...")
                        encrypted_tenant_id = encrypt_client_secret(tenant_id)
                        update_data['tenant_id'] = encrypted_tenant_id
                        print(f"  ✓ tenant_id encrypted successfully (new length: {len(encrypted_tenant_id)})")

                # Encrypt client_id if present
                if client_id and client_id.strip():
                    # Check if already encrypted
                    if len(client_id) > 100 and '=' in client_id[-10:]:
                        print(f"  ⚠️  client_id appears already encrypted (length: {len(client_id)})")
                    else:
                        print(f"  🔐 Encrypting client_id (current length: {len(client_id)})...")
                        encrypted_client_id = encrypt_client_secret(client_id)
                        update_data['client_id'] = encrypted_client_id
                        print(f"  ✓ client_id encrypted successfully (new length: {len(encrypted_client_id)})")

                # Encrypt client_secret if present
                if client_secret and client_secret.strip():
                    # Check if already encrypted
                    if len(client_secret) > 100 and '=' in client_secret[-10:]:
                        print(f"  ⚠️  client_secret appears already encrypted (length: {len(client_secret)})")
                    else:
                        print(f"  🔐 Encrypting client_secret (current length: {len(client_secret)})...")
                        encrypted_client_secret = encrypt_client_secret(client_secret)
                        update_data['client_secret'] = encrypted_client_secret
                        print(f"  ✓ client_secret encrypted successfully (new length: {len(encrypted_client_secret)})")

                # Update in database if there's anything to update
                if update_data:
                    print(f"  💾 Updating database with {len(update_data)} encrypted field(s)...")

                    if record_id:
                        update_response = supabase.table('m365_credentials').update(
                            update_data
                        ).eq('id', record_id).execute()

                        if update_response.data:
                            print(f"  ✅ Successfully updated in database")
                            updated_count += 1
                        else:
                            print(f"  ❌ Failed to update in database")
                            failed_count += 1
                    else:
                        print(f"  ❌ No ID found for record")
                        failed_count += 1
                else:
                    print(f"  ⏭️  No new fields to encrypt (all already encrypted)")

            except Exception as e:
                print(f"  ❌ Error processing record: {str(e)}")
                failed_count += 1
                continue

        print("\n" + "="*50)
        print("🎉 ENCRYPTION COMPLETE!")
        print(f"✅ Successfully encrypted: {updated_count} records")
        if failed_count > 0:
            print(f"❌ Failed to encrypt: {failed_count} records")

        print("\n3. Verifying encryption...")

        # Verify one record
        if updated_count > 0:
            test_record = records_to_encrypt[0]
            test_org_id = test_record.get('organization_id')

            if test_org_id:
                print(f"Testing decryption for: Organization ID {test_org_id}")

                # Test decryption by fetching the record again
                verify_response = supabase.table('m365_credentials')\
                    .select('*')\
                    .eq('organization_id', test_org_id)\
                    .limit(1)\
                    .execute()

                if verify_response.data:
                    from crypto_utils import decrypt_client_secret
                    encrypted_record = verify_response.data[0]

                    try:
                        # Try to decrypt each field
                        if encrypted_record.get('tenant_id'):
                            decrypted_tenant = decrypt_client_secret(encrypted_record['tenant_id'])
                            print(f"✅ tenant_id decryption PASSED (length: {len(decrypted_tenant)})")

                        if encrypted_record.get('client_id'):
                            decrypted_client = decrypt_client_secret(encrypted_record['client_id'])
                            print(f"✅ client_id decryption PASSED (length: {len(decrypted_client)})")

                        if encrypted_record.get('client_secret'):
                            decrypted_secret = decrypt_client_secret(encrypted_record['client_secret'])
                            print(f"✅ client_secret decryption PASSED (length: {len(decrypted_secret)})")

                        print("\n✅ ALL DECRYPTION TESTS PASSED!")
                    except Exception as e:
                        print(f"❌ Decryption test FAILED: {str(e)}")
                else:
                    print("❌ Could not fetch record for verification")

        print("\n🚀 Your m365_credentials table is now encrypted!")
        print("\nNext steps:")
        print("1. Update supabase_services.py to use m365_credentials table")
        print("2. Test your endpoints with the new encrypted credentials")

    except Exception as e:
        print(f"❌ Script error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(encrypt_existing_secrets())