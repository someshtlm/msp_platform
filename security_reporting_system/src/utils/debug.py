import os

from dotenv import load_dotenv
from supabase import create_client

load_dotenv()


def debug_supabase():
    print("=== Supabase Debug ===")

    # Check environment variables
    url = os.getenv('SUPABASE_URL')
    key = os.getenv('SUPABASE_KEY')

    print(f"URL: {url[:20]}..." if url else "URL: Missing")
    print(f"Key: {key[:20]}..." if key else "Key: Missing")

    if not url or not key:
        print("❌ Missing SUPABASE_URL or SUPABASE_KEY in .env file")
        return

    try:
        # Connect to Supabase
        supabase = create_client(url, key)
        print("✅ Connected to Supabase")

        # Check if table exists and get all records
        response = supabase.table('user_credentials').select("id, created_at, created_by").execute()

        if response.data:
            print(f"✅ Found {len(response.data)} credential records:")
            for i, record in enumerate(response.data):
                print(f"  {i + 1}. ID: {record.get('id')}")
                print(f"     Created: {record.get('created_at')}")
                print(f"     By: {record.get('created_by')}")
        else:
            print("❌ No credentials found in database")
            print("You need to create a record first!")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    debug_supabase()