# store_credentials.py
import os
import sys
from dotenv import load_dotenv
from supabase import create_client

# Add path resolution for local running
current_dir = os.path.dirname(os.path.abspath(__file__))
security_system_root = os.path.join(current_dir, '..', '..')
if security_system_root not in sys.path:
    sys.path.insert(0, security_system_root)

from src.services.encryption_manager import EncryptionManager

load_dotenv()


def store_encrypted_credentials():
    supabase = create_client(os.getenv('SUPABASE_URL'), os.getenv('SUPABASE_KEY'))
    encryption_manager = EncryptionManager()

    # Your actual credentials - replace with real values
    credentials = {
        'id': '4ffdf31a-9ea7-4962-a8ff-4ef440c793f3',
        'ninjaone_client_id': 'W5fh2GIOnM2csE2G1SwKT-O1AUU',
        'ninjaone_client_secret': 'p9P2FPgM2_O8GPQ51i_RFc7s6GIbnJd3ksGmuu50DOH8jJbHBYWEIw',  # Will be encrypted
        'ninjaone_instance_url': 'https://teamlogicitneaustin.rmmservice.com',
        'ninjaone_scopes': 'monitoring management',
        'autotask_username': 'inputiv@teamlogicit64325.com',
        'autotask_secret': 'k6qbRCe&8nTiM2Qbb^',  # Will be encrypted
        'autotask_integration_code': 'G2S6X7OOTYMGU25GGOJBZXF7BMD',
        'autotask_base_url': 'https://webservices.autotask.net/atservicesrest/v1.0/',
        'connectsecure_tenant_name': 'teamlogicit64325',
        'connectsecure_base_url': 'https://pod104.myconnectsecure.com',
        'connectsecure_client_id': '71e134b9-a751-4979-9465-766a81ab4766',
        'connectsecure_client_secret_b64': str ("Z0FBQUFBQm9OdElYVThPa0hVeXlCU0lWc3JCb0pLb2lHT2NGNDMycDFlZVBuUWhEazRvREpJeDk1S1NYek5yVWJSWmNKbE0w"
    "eS1GdUZEbjBSWnM1UTZtRm1hZHRrdzI0SlplRzRyanJiWUxzUFZVdFBub2ZXZG5ILTd0aDZuYnJQSDZlcmx6bEh0cUlIUEQ4VlV"
    "PdEpTNWlmSlNQd2tMU2xNdTEwaUhDU2lFLVJkZ3YtRWVEeFdjPQ==") ,  # Will be encrypted
        'created_by': 'system_user',
        'created_at': '2024-01-01T00:00:00Z',
        'updated_at': '2024-01-01T00:00:00Z'
    }

    print("Encrypting sensitive fields...")
    encrypted_creds = encryption_manager.encrypt_credentials(credentials)

    print("Storing in database...")
    response = supabase.table('user_credentials').insert(encrypted_creds).execute()

    if response.data:
        print("✅ Credentials stored successfully!")
        return True
    else:
        print("❌ Failed to store credentials")
        return False


if __name__ == "__main__":
    store_encrypted_credentials()