# Step-by-Step Guide: Inserting M365 Credentials into Supabase

This guide walks you through inserting Microsoft 365 credentials into the `m365_credentials` table and encrypting them using the existing encryption script.

---

## Prerequisites

1. ✅ Your Supabase instance is set up with the new schema (from `schema.sql`)
2. ✅ `.env` file contains:
   - `SUPABASE_URL` (new Supabase URL)
   - `SUPABASE_KEY` (new Supabase anon/service key)
   - `ENCRYPTION_KEY` (existing encryption key - same one from before)
3. ✅ You have an `organization` already created in the `organizations` table

---

## Step 1: Create an Organization (if not exists)

First, you need to create an organization in the `organizations` table. Each M365 credential is linked to an organization via `organization_id`.

**Go to Supabase Dashboard → Table Editor → organizations**

Insert a new row:
```sql
INSERT INTO organizations (account_id, organization_name, domain, industry, organization_size, status)
VALUES (
    1,                    -- account_id (get this from 'accounts' table)
    'Acme Corporation',   -- organization_name
    'acme.com',          -- domain
    'Technology',        -- industry
    '50-100',           -- organization_size
    'Active'            -- status
);
```

**Note the `id` that gets generated** - this is your `organization_id` (e.g., `1`, `2`, `3`).

---

## Step 2: Insert Plain Text Credentials into m365_credentials

**Go to Supabase Dashboard → Table Editor → m365_credentials**

Insert a new row with **PLAIN TEXT** credentials (we'll encrypt them in Step 3):

```sql
INSERT INTO m365_credentials (
    organization_id,
    account_id,
    tenant_id,
    client_id,
    client_secret,
    credential_status
)
VALUES (
    1,                                      -- organization_id (from Step 1)
    1,                                      -- account_id (same as organization's account_id)
    'your-azure-tenant-id-here',           -- tenant_id (PLAIN TEXT for now)
    'your-azure-client-id-here',           -- client_id (PLAIN TEXT for now)
    'your-azure-client-secret-here',       -- client_secret (PLAIN TEXT for now)
    'Active'                               -- credential_status
);
```

### Example:
```sql
INSERT INTO m365_credentials (
    organization_id,
    account_id,
    tenant_id,
    client_id,
    client_secret,
    credential_status
)
VALUES (
    1,
    1,
    'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
    'b15b18dc-ffad-43c5-b7ca-3f14626f1e0e',
    'Xyz~8Q~abcd1234efgh5678ijkl9012mnop',
    'Active'
);
```

**Important Notes:**
- Do NOT encrypt the credentials manually
- Insert them as **plain text**
- The encryption script will handle encryption in Step 3

---

## Step 3: Run the Encryption Script

Now run the encryption script to encrypt all three fields (`tenant_id`, `client_id`, `client_secret`).

### Open Terminal/Command Prompt:

```bash
cd C:\Users\TLM\Desktop\msp_platform\msp_endpoints
python encrypt_existing_secrets.py
```

### What the script does:

1. **Fetches all records** from `m365_credentials` table
2. **Displays preview** of records that will be encrypted:
   ```
   Records that will be encrypted:
     1. Organization ID: 1
        tenant_id: a1b2c3d4-e...
        client_id: b15b18dc-f...
        client_secret: Xyz~8Q~abc...
   ```

3. **Asks for confirmation**:
   ```
   Do you want to encrypt these credentials? (yes/no):
   ```
   Type `yes` and press Enter.

4. **Encrypts each field**:
   ```
   Processing 1/1: Organization ID 1
     🔐 Encrypting tenant_id (current length: 36)...
     ✓ tenant_id encrypted successfully (new length: 168)
     🔐 Encrypting client_id (current length: 36)...
     ✓ client_id encrypted successfully (new length: 168)
     🔐 Encrypting client_secret (current length: 32)...
     ✓ client_secret encrypted successfully (new length: 160)
     💾 Updating database with 3 encrypted field(s)...
     ✅ Successfully updated in database
   ```

5. **Verifies encryption** by testing decryption:
   ```
   3. Verifying encryption...
   Testing decryption for: Organization ID 1
   ✅ tenant_id decryption PASSED (length: 36)
   ✅ client_id decryption PASSED (length: 36)
   ✅ client_secret decryption PASSED (length: 32)

   ✅ ALL DECRYPTION TESTS PASSED!
   ```

6. **Done!**
   ```
   🚀 Your m365_credentials table is now encrypted!
   ```

---

## Step 4: Verify Encrypted Data in Supabase

**Go to Supabase Dashboard → Table Editor → m365_credentials**

You should now see:
- `tenant_id`: Long encrypted string (e.g., `Z0FBQUFBQm5uOXRR...` - ~168 chars)
- `client_id`: Long encrypted string (e.g., `Z0FBQUFBQm5uOXRR...` - ~168 chars)
- `client_secret`: Long encrypted string (e.g., `Z0FBQUFBQm5uOXRR...` - ~160 chars)

✅ Your credentials are now securely encrypted!

---

## Step 5: Test Credential Retrieval

You can test if the credentials are being decrypted correctly by using the updated `supabase_services.py`:

### Create a test script (`test_credentials.py`):

```python
import asyncio
from dotenv import load_dotenv
load_dotenv()

from supabase_services import get_organization_credentials

async def test():
    # Replace with your organization_id
    org_id = 1

    print(f"Testing credential retrieval for org_id: {org_id}")
    creds = await get_organization_credentials(org_id)

    if creds:
        print("✅ Credentials retrieved successfully!")
        print(f"   Tenant ID: {creds['tenant_id']}")
        print(f"   Client ID: {creds['client_id']}")
        print(f"   Client Secret: {creds['client_secret'][:10]}... (length: {len(creds['client_secret'])})")
    else:
        print("❌ Failed to retrieve credentials")

asyncio.run(test())
```

Run it:
```bash
python test_credentials.py
```

Expected output:
```
Testing credential retrieval for org_id: 1
✅ Credentials retrieved successfully!
   Tenant ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
   Client ID: b15b18dc-ffad-43c5-b7ca-3f14626f1e0e
   Client Secret: Xyz~8Q~abc... (length: 32)
```

---

## Step 6: Insert Multiple Organizations (Optional)

If you have multiple organizations, repeat Steps 1-3 for each:

1. Insert organization in `organizations` table → Get `organization_id`
2. Insert plain text credentials in `m365_credentials` table
3. Run `python encrypt_existing_secrets.py` again

The script will **only encrypt new plain text credentials** and **skip already encrypted ones**.

---

## Summary of What Changed

### ✅ Updated Files:
1. **`encrypt_existing_secrets.py`**
   - Now works with `m365_credentials` table (not `organization_mapping`)
   - Encrypts all 3 fields: `tenant_id`, `client_id`, `client_secret`
   - Detects already encrypted fields and skips them

2. **`supabase_services.py`**
   - New function: `get_organization_credentials(org_id)` - retrieves and decrypts credentials
   - New function: `get_credentials_by_ninjaone_id(ninjaone_org_id)` - resolves ninjaone_org_id → org_id
   - Deprecated old functions that used `organization_mapping` table

### ✅ Database Schema (from `schema.sql`):
- **`m365_credentials` table** stores encrypted credentials
- **`organizations` table** links organizations to accounts
- Each organization has ONE set of M365 credentials (UNIQUE constraint on `organization_id`)

---

## Troubleshooting

### Error: "No M365 credentials found for org_id: X"
- Check that you inserted the credentials with the correct `organization_id`
- Verify the organization exists in `organizations` table

### Error: "Failed to decrypt credentials"
- Ensure `ENCRYPTION_KEY` in `.env` is the **same key** used to encrypt
- Check that the credentials were encrypted using `encrypt_existing_secrets.py`

### Error: "M365 credentials inactive for org_id: X"
- Update the `credential_status` column to `'Active'` in Supabase

---

## Next Steps

After inserting and encrypting credentials:
1. ✅ Test cache READ endpoints (Phase 1)
2. ✅ Implement cache WRITE endpoints (Phase 2)
3. ✅ Test Microsoft Graph API authentication with encrypted credentials

---

**Questions?** Refer to:
- `CACHE_TEST_GUIDE_UPDATED.md` - Complete cache implementation guide
- `schema.sql` - Database schema reference
- `supabase_services.py` - Credential retrieval functions
