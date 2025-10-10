# Complete Cache Implementation Guide - Phase 1 & Phase 2

This comprehensive guide covers the full Supabase caching implementation for M365 data, including READ operations (Phase 1) and WRITE operations (Phase 2).

---

# 🏗️ Architecture Overview

## Database Hierarchy
```
auth.users (Supabase Auth)
    ↓ auth_user_id (UUID)
platform_users (id, account_id, auth_user_id, email, role)
    ↓ account_id
accounts (id, account_name, subdomain, status)
    ↓ account_id
organizations (id, account_id, organization_name, domain)
    ↓ organization_id
m365_credentials (tenant_id, client_id, client_secret [ENCRYPTED])
    ↓ Use these credentials to authenticate with Microsoft Graph API
m365_*_snapshots (cache tables with organization_id FK)
```

## Key Tables

### **m365_credentials** (Lines 70-84)
Stores encrypted Microsoft 365 credentials per organization:
- `organization_id` (int, FK to organizations, UNIQUE)
- `account_id` (int, FK to accounts)
- `tenant_id` (varchar) - Azure AD tenant ID
- `client_id` (varchar, UNIQUE) - Azure App Registration ID
- `client_secret` (text, **ENCRYPTED**) - Application secret
- `credential_status` (varchar) - "Active"/"Inactive"
- `last_token_refresh` (timestamp)

### **integration_credentials** (Lines 44-56)
Stores credentials for NinjaOne, Autotask, ConnectSecure:
- `account_id` (int, FK to accounts)
- `integration_name` (varchar) - "ninjaone", "autotask", "connectsecure"
- `credentials` (jsonb, **ENCRYPTED**) - Contains API keys, tokens
- `is_active` (boolean)

### **organizations** (Lines 267-284)
Links organizations to accounts and external systems:
- `id` (serial PK) - **This is the org_id/clientId used in APIs**
- `account_id` (int, FK to accounts)
- `organization_name` (varchar)
- `ninjaone_org_id`, `connect_secure_id`, `autotask_id` (varchar)

---

# 📖 Phase 1: READ from Cache (COMPLETED)

## Overview
Phase 1 fetches data from Supabase cache tables and transforms it to match the exact frontend JSON format.

## Cache TTL Configuration
- **M365 Data Endpoints:** 1 week (10080 minutes)
- **Clients Endpoint:** 2 weeks (20160 minutes)
- Configurable via `ttl_minutes` parameter in `is_cache_valid()`

## Parameter Changes (UPDATED)
All endpoints now use **`clientId`** (not `organization_id`) as query parameter:
- **Required parameter** (no default value)
- Frontend sends: `clientId` = `organizations.id` (org_id)
- Backend extracts: `org_id = clientId`

**Exception:** `/api/test-cache-read-clients` uses `u_id` parameter (see below)

---

## 🗄️ Database Tables & Response Mapping

### 1. **m365_compliance_snapshots** → `/api/GetAllComplianceStatus`

**Table Columns:**
- `organization_id` (int, FK)
- `status` (varchar) - "Compliant", "Partially Compliant", "Not Compliant"
- `score_percentage` (int) - 0-100
- `total_policies` (int)
- `policies_data` (jsonb) - `{"policies": [{...}, {...}]}`
- `breakdown` (jsonb) - `{"compliant": {...}, "partially_compliant": {...}, ...}`
- `title` (varchar)
- `checked_at` (timestamp)

**Cache Function:** `get_cached_compliance(organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-compliance?clientId=1
```

**Parsing Logic:**
```python
# Extract nested policies array
policies_data = cache_entry.get('policies_data', {})
policies_array = policies_data.get('policies', [])  # Extract from {"policies": [...]}

# Use breakdown as-is
breakdown_data = cache_entry.get('breakdown', {})

# Format percentage
score_percentage_str = f"{cache_entry['score_percentage']}%"
```

---

### 2. **m365_mfa_snapshots** → `/api/GetMFAComplianceReport`

**Table Columns:**
- `organization_id` (int, FK)
- `percentage` (numeric) - 56.4
- `status` (varchar)
- `total_users`, `mfa_enabled`, `mfa_disabled` (int)
- `mfa_registered`, `conditional_access`, `security_defaults`, `per_user_mfa` (int)
- `recommendation`, `description` (text)
- `measurement_date` (timestamp)

**Cache Function:** `get_cached_mfa(organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-mfa?clientId=1
```

**Parsing Logic:**
```python
# Format percentage with proper decimals
percentage_value = float(cache_entry['percentage'])
percentage_str = f"{percentage_value}%" if percentage_value == int(percentage_value) else f"{percentage_value:.1f}%"

# IMPORTANT: Wrap response in array
frontend_json = [{...}]  # Array with single object
```

---

### 3. **m365_license_snapshots** → `/api/GetLicenseSummary`

**Table Columns:**
- `organization_id` (int, FK)
- `total_users`, `others_count`, `standard_count`, `premium_count`, `basic_count` (int)
- `license_details` (jsonb) - `{"licenseDetails": [{...}, {...}]}`
- `snapshot_date` (timestamp)

**Cache Function:** `get_cached_licenses(organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-licenses?clientId=1
```

**Parsing Logic:**
```python
# Extract nested licenseDetails array
license_data = cache_entry.get('license_details', {})
license_details_array = license_data.get('licenseDetails', [])

# Return as object (NOT array)
frontend_json = {
    "totalUsers": cache_entry['total_users'],
    "licenseDistribution": {...},
    "licenseDetails": license_details_array
}
```

---

### 4. **m365_secure_score_history** → `/api/GetMicrosoftSecureScore`

**Table Columns:**
- `organization_id` (int, FK)
- `current_score`, `max_score`, `percentage` (numeric)
- `active_user_count`, `licensed_user_count` (int)
- `top_improvement_actions` (jsonb) - `[{...}, {...}]`
- `all_improvement_actions` (jsonb) - `[{...}, {...}]`
- `completed_actions` (jsonb) - `[{...}, {...}]`
- `score_data` (jsonb) - Contains `createdDateTime`
- `created_at` (timestamp)

**Cache Function:** `get_cached_secure_score(organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-secure-score?clientId=1
```

**Parsing Logic:**
```python
# Extract createdDateTime from score_data JSONB
score_data_jsonb = cache_entry.get('score_data', {})
created_date_time = score_data_jsonb.get('createdDateTime', cache_entry['created_at'])

# Use JSONB arrays as-is
frontend_json = {
    "scoreData": {
        "createdDateTime": created_date_time
        # Note: azureTenantId removed - not in Supabase table
    },
    "topImprovementActions": cache_entry.get('top_improvement_actions', []),
    "allImprovementActions": cache_entry.get('all_improvement_actions', []),
    "completedActions": cache_entry.get('completed_actions', [])
}
```

---

### 5. **m365_users** → `/api/ListUsers`

**Table Columns:**
- `id` (int, PK)
- `organization_id` (int, FK)
- `user_id` (varchar, UNIQUE) - Graph API user ID (UUID)
- `display_name`, `email`, `department`, `role`, `status` (varchar)
- `mfa_enabled` (boolean)
- `last_synced` (timestamp)

**Cache Function:** `get_cached_users_list(organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-users-list?clientId=1
```

**Parsing Logic:**
```python
# Get ALL users for organization
users_response = supabase.table('m365_users')\
    .select('*')\
    .eq('organization_id', organization_id)\
    .execute()

# Transform to frontend format
frontend_json = {"users": [...]}
```

---

### 6. **m365_users + m365_user_details + m365_user_devices** → `/api/UserDetails/{user_id}`

**Table Relationships:**
- `m365_users.user_id` (Graph API UUID) → `m365_user_details.user_id` (1-to-1, FK)
- `m365_users.user_id` (Graph API UUID) → `m365_user_devices.user_id` (1-to-many, FK)

**IMPORTANT:** JOINs use `user['user_id']` (Graph API UUID), NOT `user['id']` (internal PK)

**Cache Function:** `get_cached_user_details(user_id, organization_id)`

**Test Endpoint:**
```http
GET /api/test-cache-read-user-details/{user_id}?clientId=1
```

**Parsing Logic:**
```python
# Query user by Graph API user_id
user = supabase.table('m365_users')\
    .select('*')\
    .eq('user_id', user_id)\
    .eq('organization_id', organization_id)\
    .execute()

# JOIN using Graph API user_id (NOT internal id)
user_details = supabase.table('m365_user_details')\
    .select('*')\
    .eq('user_id', user['user_id'])\  # ✅ CORRECT: Use Graph API UUID
    .execute()

devices = supabase.table('m365_user_devices')\
    .select('*')\
    .eq('user_id', user['user_id'])\  # ✅ CORRECT: Use Graph API UUID
    .execute()

# All count fields use `or 0` to convert null to 0
"archived_items_count": user_details.get('mailbox_archived_items_count') or 0
```

---

### 7. **organizations** → `/api/GetClients` (NEW APPROACH)

**Table Columns:**
- `id` (serial PK) - **This is the org_id/clientId**
- `account_id` (int, FK)
- `organization_name` (varchar)
- `domain`, `industry`, `organization_size` (varchar)
- `status` (varchar) - "Active"/"Inactive"
- `ninjaone_org_id`, `connect_secure_id`, `autotask_id` (varchar)
- `created_at`, `updated_at` (timestamp)

**Cache Function:** `get_cached_clients()` - **UPDATED FOR PHASE 2**

**Test Endpoint (Phase 2):**
```http
GET /api/test-cache-read-clients?u_id={auth_user_id}
```

**NEW Flow:**
1. Frontend sends `u_id` (from `auth.users.id` / `platform_users.auth_user_id`)
2. SQL function or query: `u_id` → `account_id`
3. Query organizations: `WHERE account_id = X`
4. Return ALL organizations for that account

**Response Format:**
```json
{
  "status_code": 200,
  "data": {
    "success": true,
    "clients": [
      {
        "ninjaone_org_id": null,
        "organization_name": "Acme Corp",
        "domain": {"url": "acme.com", "text": "Visit Website"},
        "org_id": 2,
        "created": {
          "created_date": "09/16/2025",
          "updated_date": "09/16/2025"
        },
        "status": "Active",
        "industry": "Technology",
        "organization_size": "50-100"
      }
    ],
    "count": 3
  }
}
```

---

### 8. **Test All Caches (Comprehensive)**

**Test Endpoint:**
```http
GET /api/test-cache-read-all?clientId=1
```

Returns status of all cache types at once for testing.

---

# ✍️ Phase 2: WRITE to Cache (IMPLEMENTATION PLAN)

## Overview
Phase 2 fetches fresh data from Microsoft Graph API and writes it to Supabase cache tables.

---

## 🔐 Authentication & Credential Management

### Step 1: Retrieve Organization Credentials

**Function:** `get_organization_credentials(org_id: int)`

```python
async def get_organization_credentials(org_id: int) -> Optional[Dict[str, str]]:
    """
    Retrieve and decrypt M365 credentials for an organization.

    Args:
        org_id: Organization ID (clientId from frontend)

    Returns:
        {
            "tenant_id": "...",
            "client_id": "...",
            "client_secret": "..." (decrypted)
        }
    """
    try:
        # Query m365_credentials table
        response = supabase.table('m365_credentials')\
            .select('tenant_id, client_id, client_secret, credential_status')\
            .eq('organization_id', org_id)\
            .limit(1)\
            .execute()

        if not response.data:
            logger.error(f"No M365 credentials found for org_id: {org_id}")
            return None

        creds = response.data[0]

        # Check credential status
        if creds['credential_status'] != 'Active':
            logger.error(f"M365 credentials inactive for org_id: {org_id}")
            return None

        # Decrypt client_secret using ENCRYPTION_KEY
        decrypted_secret = decrypt_credential(creds['client_secret'])

        return {
            "tenant_id": creds['tenant_id'],
            "client_id": creds['client_id'],
            "client_secret": decrypted_secret
        }

    except Exception as e:
        logger.error(f"Error retrieving credentials for org_id {org_id}: {e}")
        return None
```

---

### Step 2: Encryption/Decryption Functions

**Required:** You will provide encryption/decryption functions.

**Expected Interface:**
```python
def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt credential using ENCRYPTION_KEY from .env

    Args:
        plaintext: Plain text credential

    Returns:
        Encrypted string (Base64/Fernet/AES)
    """
    pass

def decrypt_credential(ciphertext: str) -> str:
    """
    Decrypt credential using ENCRYPTION_KEY from .env

    Args:
        ciphertext: Encrypted credential from database

    Returns:
        Decrypted plain text credential
    """
    pass
```

---

### Step 3: Generate Microsoft Graph API Token

**Function:** `get_graph_api_token(tenant_id: str, client_id: str, client_secret: str)`

```python
import requests

async def get_graph_api_token(tenant_id: str, client_id: str, client_secret: str) -> Optional[str]:
    """
    Generate OAuth2 access token for Microsoft Graph API.

    Args:
        tenant_id: Azure AD tenant ID
        client_id: Azure App Registration ID
        client_secret: Decrypted application secret

    Returns:
        Access token string or None if failed
    """
    try:
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials"
        }

        response = requests.post(token_url, data=token_data, timeout=30)
        response.raise_for_status()

        token_response = response.json()
        access_token = token_response.get("access_token")

        if not access_token:
            logger.error(f"No access token in response for tenant: {tenant_id}")
            return None

        # Update last_token_refresh in m365_credentials table
        supabase.table('m365_credentials')\
            .update({"last_token_refresh": datetime.now().isoformat()})\
            .eq('tenant_id', tenant_id)\
            .execute()

        logger.info(f"✅ Generated Graph API token for tenant: {tenant_id}")
        return access_token

    except Exception as e:
        logger.error(f"❌ Error generating token for tenant {tenant_id}: {e}")
        return None
```

---

## 📝 WRITE Functions Implementation

### 1. Write Compliance to Cache

**Function:** `write_compliance_to_cache(org_id: int)`

```python
async def write_compliance_to_cache(org_id: int) -> bool:
    """
    Fetch compliance data from Graph API and save to m365_compliance_snapshots.

    Flow:
        1. Get org credentials → Generate token
        2. Call Graph API /api/GetAllComplianceStatus equivalent
        3. Transform response → Supabase format
        4. UPSERT to m365_compliance_snapshots

    Args:
        org_id: Organization ID (clientId)

    Returns:
        True if successful, False otherwise
    """
    try:
        logger.info(f"📝 Writing compliance cache for org_id: {org_id}")

        # Step 1: Get credentials and token
        creds = await get_organization_credentials(org_id)
        if not creds:
            return False

        token = await get_graph_api_token(
            creds['tenant_id'],
            creds['client_id'],
            creds['client_secret']
        )
        if not token:
            return False

        # Step 2: Call Graph API (or internal endpoint)
        # TODO: Implement Graph API call logic
        # graph_response = await call_compliance_endpoint(token, org_id)

        # Step 3: Transform to Supabase format
        # Frontend JSON → Database columns
        compliance_data = {
            "organization_id": org_id,
            "status": graph_response['compliance_summary']['status'],
            "score_percentage": int(graph_response['compliance_summary']['score_percentage'].replace('%', '')),
            "total_policies": graph_response['compliance_summary']['total_policies'],
            "policies_data": {"policies": graph_response['policies']},  # Wrap in nested structure
            "breakdown": graph_response['compliance_summary']['breakdown'],
            "title": graph_response['compliance_summary']['title'],
            "checked_at": datetime.now().isoformat()
        }

        # Step 4: UPSERT to database
        # Check if record exists
        existing = supabase.table('m365_compliance_snapshots')\
            .select('id')\
            .eq('organization_id', org_id)\
            .limit(1)\
            .execute()

        if existing.data:
            # UPDATE existing record
            supabase.table('m365_compliance_snapshots')\
                .update(compliance_data)\
                .eq('organization_id', org_id)\
                .execute()
            logger.info(f"✅ Updated compliance cache for org_id: {org_id}")
        else:
            # INSERT new record
            supabase.table('m365_compliance_snapshots')\
                .insert(compliance_data)\
                .execute()
            logger.info(f"✅ Inserted compliance cache for org_id: {org_id}")

        return True

    except Exception as e:
        logger.error(f"❌ Error writing compliance cache for org_id {org_id}: {e}")
        return False
```

---

### 2. Write MFA to Cache

**Function:** `write_mfa_to_cache(org_id: int)`

```python
async def write_mfa_to_cache(org_id: int) -> bool:
    """
    Fetch MFA data from Graph API and save to m365_mfa_snapshots.

    Transform:
        Frontend: [{"percentage": "56.4%", ...}]
        Database: {"percentage": 56.4, ...}
    """
    try:
        # Similar flow to compliance
        creds = await get_organization_credentials(org_id)
        token = await get_graph_api_token(...)

        # Call Graph API
        # graph_response = await call_mfa_endpoint(token, org_id)

        # Transform (extract from array, remove % from percentage)
        mfa_data = graph_response[0]  # Unwrap array

        mfa_db_data = {
            "organization_id": org_id,
            "percentage": float(mfa_data['percentage'].replace('%', '')),
            "status": mfa_data['status'],
            "total_users": mfa_data['total_users'],
            "mfa_enabled": mfa_data['mfa_enabled'],
            "mfa_disabled": mfa_data['mfa_disabled'],
            "mfa_registered": mfa_data['enabled_by_method']['mfa_registered'],
            "conditional_access": mfa_data['enabled_by_method']['conditional_access'],
            "security_defaults": mfa_data['enabled_by_method']['security_defaults'],
            "per_user_mfa": mfa_data['enabled_by_method']['per_user_mfa'],
            "recommendation": mfa_data['recommendation'],
            "description": mfa_data['details']['description'],
            "measurement_date": datetime.now().isoformat()
        }

        # UPSERT
        existing = supabase.table('m365_mfa_snapshots')\
            .select('id')\
            .eq('organization_id', org_id)\
            .execute()

        if existing.data:
            supabase.table('m365_mfa_snapshots')\
                .update(mfa_db_data)\
                .eq('organization_id', org_id)\
                .execute()
        else:
            supabase.table('m365_mfa_snapshots')\
                .insert(mfa_db_data)\
                .execute()

        logger.info(f"✅ Written MFA cache for org_id: {org_id}")
        return True

    except Exception as e:
        logger.error(f"❌ Error writing MFA cache: {e}")
        return False
```

---

### 3. Write Licenses to Cache

**Function:** `write_licenses_to_cache(org_id: int)`

```python
async def write_licenses_to_cache(org_id: int) -> bool:
    """
    Fetch license data from Graph API and save to m365_license_snapshots.

    Transform:
        Frontend: {"licenseDetails": [...]}
        Database: {"license_details": {"licenseDetails": [...]}}
    """
    try:
        creds = await get_organization_credentials(org_id)
        token = await get_graph_api_token(...)

        # Call Graph API
        # graph_response = await call_licenses_endpoint(token, org_id)

        license_db_data = {
            "organization_id": org_id,
            "total_users": graph_response['totalUsers'],
            "others_count": graph_response['licenseDistribution']['Others'],
            "standard_count": graph_response['licenseDistribution']['Standard'],
            "premium_count": graph_response['licenseDistribution']['Premium'],
            "basic_count": graph_response['licenseDistribution']['Basic'],
            "license_details": {"licenseDetails": graph_response['licenseDetails']},  # Wrap nested
            "snapshot_date": datetime.now().isoformat()
        }

        # UPSERT
        existing = supabase.table('m365_license_snapshots')\
            .select('id')\
            .eq('organization_id', org_id)\
            .execute()

        if existing.data:
            supabase.table('m365_license_snapshots')\
                .update(license_db_data)\
                .eq('organization_id', org_id)\
                .execute()
        else:
            supabase.table('m365_license_snapshots')\
                .insert(license_db_data)\
                .execute()

        logger.info(f"✅ Written license cache for org_id: {org_id}")
        return True

    except Exception as e:
        logger.error(f"❌ Error writing license cache: {e}")
        return False
```

---

### 4. Write Secure Score to Cache

**Function:** `write_secure_score_to_cache(org_id: int)`

```python
async def write_secure_score_to_cache(org_id: int) -> bool:
    """
    Fetch secure score from Graph API and save to m365_secure_score_history.

    Transform:
        - Extract createdDateTime and wrap in score_data JSONB
        - Store improvement action arrays as-is
    """
    try:
        creds = await get_organization_credentials(org_id)
        token = await get_graph_api_token(...)

        # Call Graph API
        # graph_response = await call_secure_score_endpoint(token, org_id)

        score_db_data = {
            "organization_id": org_id,
            "current_score": graph_response['scoreData']['currentScore'],
            "max_score": graph_response['scoreData']['maxScore'],
            "percentage": float(graph_response['scoreData']['percentage'].replace('%', '')),
            "active_user_count": graph_response['scoreData']['activeUserCount'],
            "licensed_user_count": graph_response['scoreData']['licensedUserCount'],
            "score_data": {
                "createdDateTime": graph_response['scoreData']['createdDateTime']
            },
            "top_improvement_actions": graph_response['topImprovementActions'],
            "all_improvement_actions": graph_response['allImprovementActions'],
            "completed_actions": graph_response['completedActions'],
            "created_at": datetime.now().isoformat()
        }

        # UPSERT
        existing = supabase.table('m365_secure_score_history')\
            .select('id')\
            .eq('organization_id', org_id)\
            .execute()

        if existing.data:
            supabase.table('m365_secure_score_history')\
                .update(score_db_data)\
                .eq('organization_id', org_id)\
                .execute()
        else:
            supabase.table('m365_secure_score_history')\
                .insert(score_db_data)\
                .execute()

        logger.info(f"✅ Written secure score cache for org_id: {org_id}")
        return True

    except Exception as e:
        logger.error(f"❌ Error writing secure score cache: {e}")
        return False
```

---

### 5. Write Users to Cache

**Function:** `write_users_to_cache(org_id: int)`

```python
async def write_users_to_cache(org_id: int) -> bool:
    """
    Fetch users list from Graph API and save to m365_users.

    Process:
        - Delete existing users for this org (or use UPSERT on user_id)
        - Insert all users
    """
    try:
        creds = await get_organization_credentials(org_id)
        token = await get_graph_api_token(...)

        # Call Graph API
        # graph_response = await call_users_list_endpoint(token, org_id)

        users_list = graph_response['users']

        # Option 1: Delete existing users and re-insert (simpler)
        supabase.table('m365_users')\
            .delete()\
            .eq('organization_id', org_id)\
            .execute()

        # Insert all users
        users_to_insert = []
        for user in users_list:
            users_to_insert.append({
                "organization_id": org_id,
                "user_id": user['UserId'],
                "display_name": user['Name'],
                "email": user['Email'],
                "department": user['Department'],
                "role": user['Role'],
                "status": user['Status'],
                "mfa_enabled": user['MFA'],
                "last_synced": datetime.now().isoformat()
            })

        # Batch insert
        if users_to_insert:
            supabase.table('m365_users')\
                .insert(users_to_insert)\
                .execute()

        logger.info(f"✅ Written {len(users_to_insert)} users to cache for org_id: {org_id}")
        return True

    except Exception as e:
        logger.error(f"❌ Error writing users cache: {e}")
        return False
```

---

### 6. Write User Details to Cache

**Function:** `write_user_details_to_cache(user_id: str, org_id: int)`

```python
async def write_user_details_to_cache(user_id: str, org_id: int) -> bool:
    """
    Fetch single user's details from Graph API and save to m365_user_details + m365_user_devices.

    Process:
        - Call Graph API /api/UserDetails/{user_id}
        - Split response into user_details and devices
        - UPSERT to both tables
    """
    try:
        creds = await get_organization_credentials(org_id)
        token = await get_graph_api_token(...)

        # Call Graph API
        # graph_response = await call_user_details_endpoint(token, user_id, org_id)

        # Transform user_details
        user_details_data = {
            "user_id": user_id,  # Graph API UUID (FK to m365_users.user_id)
            "licenses": graph_response['licenses'],
            "mailbox_size_mb": graph_response['mailbox']['size_in_mb'],
            "mailbox_quota_mb": graph_response['mailbox']['quota_in_mb'],
            "mailbox_usage_percentage": graph_response['mailbox']['usage_percentage'],
            "mailbox_items_count": graph_response['mailbox']['items_count'],
            "mailbox_archived_items_count": graph_response['mailbox']['archived_items_count'],
            "onedrive_size_mb": graph_response['one_drive']['size_in_mb'],
            "onedrive_quota_mb": graph_response['one_drive']['quota_in_mb'],
            "onedrive_usage_percentage": graph_response['one_drive']['usage_percentage'],
            "onedrive_files_count": graph_response['one_drive']['files_count'],
            "teams_calls_minutes_last_30_days": graph_response['activity']['teams_calls_minutes_last_30_days'],
            "teams_meetings_count_last_30_days": graph_response['activity']['teams_meetings_count_last_30_days'],
            "teams_messages_count_last_30_days": graph_response['activity']['teams_messages_count_last_30_days'],
            "email_sent_count_last_30_days": graph_response['activity']['email_sent_count_last_30_days'],
            "documents_edited_last_30_days": graph_response['activity']['documents_edited_last_30_days'],
            "risk_level": graph_response['security']['risk_level'],
            "sign_in_attempts_last_30_days": graph_response['security']['sign_in_attempts_last_30_days'],
            "blocked_sign_in_attempts": graph_response['security']['blocked_sign_in_attempts'],
            "authentication_methods": graph_response['security']['authentication_methods'],
            "last_password_change": graph_response['security']['last_password_change'],
            "last_sign_in": graph_response['security']['last_sign_in'],
            "groups": graph_response['groups'],
            "last_updated": datetime.now().isoformat()
        }

        # UPSERT user_details
        existing_details = supabase.table('m365_user_details')\
            .select('id')\
            .eq('user_id', user_id)\
            .execute()

        if existing_details.data:
            supabase.table('m365_user_details')\
                .update(user_details_data)\
                .eq('user_id', user_id)\
                .execute()
        else:
            supabase.table('m365_user_details')\
                .insert(user_details_data)\
                .execute()

        # Delete existing devices and re-insert
        supabase.table('m365_user_devices')\
            .delete()\
            .eq('user_id', user_id)\
            .execute()

        # Insert devices
        devices_to_insert = []
        for device in graph_response['devices']['device_list']:
            devices_to_insert.append({
                "user_id": user_id,  # Graph API UUID (FK)
                "device_id": device['device_id'],
                "device_name": device['device_name'],
                "device_type": device['device_type'],
                "last_synced": datetime.now().isoformat()
            })

        if devices_to_insert:
            supabase.table('m365_user_devices')\
                .insert(devices_to_insert)\
                .execute()

        logger.info(f"✅ Written user details for user_id: {user_id}, devices: {len(devices_to_insert)}")
        return True

    except Exception as e:
        logger.error(f"❌ Error writing user details: {e}")
        return False
```

---

### 7. Write All Caches (Batch Operation)

**Function:** `write_all_caches_to_cache(org_id: int)`

```python
async def write_all_caches_to_cache(org_id: int) -> Dict[str, bool]:
    """
    Write all cache types at once for an organization.

    Returns:
        {
            "compliance": True,
            "mfa": True,
            "licenses": False,  # If failed
            ...
        }
    """
    results = {}

    results['compliance'] = await write_compliance_to_cache(org_id)
    results['mfa'] = await write_mfa_to_cache(org_id)
    results['licenses'] = await write_licenses_to_cache(org_id)
    results['secure_score'] = await write_secure_score_to_cache(org_id)
    results['users'] = await write_users_to_cache(org_id)

    # Optional: Write user details for each user (expensive operation)
    # users = supabase.table('m365_users').select('user_id').eq('organization_id', org_id).execute()
    # for user in users.data:
    #     await write_user_details_to_cache(user['user_id'], org_id)

    return results
```

---

## 🧪 Phase 2 Test Endpoints

Create test endpoints to trigger WRITE operations:

### 1. Test Write Compliance
```http
POST /api/test-cache-write-compliance?clientId=1
```

**Endpoint Implementation:**
```python
@router.post("/test-cache-write-compliance", response_model=GraphApiResponse, summary="[TEST] Write Compliance to Cache")
async def test_cache_write_compliance(clientId: int = Query(..., description="Client ID (org_id)")):
    """
    TEST ENDPOINT: Fetch compliance from Graph API and write to m365_compliance_snapshots.
    """
    try:
        org_id = clientId
        logger.info(f"🧪 TEST: Writing compliance cache for org_id: {org_id}")

        success = await write_compliance_to_cache(org_id)

        if not success:
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to write compliance cache for org_id: {org_id}"
            )

        return GraphApiResponse(
            status_code=200,
            data={"message": "Compliance cache written successfully", "org_id": org_id},
            error=None
        )

    except Exception as e:
        logger.error(f"❌ TEST ERROR: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Test failed: {str(e)}"
        )
```

### 2. Test Write MFA
```http
POST /api/test-cache-write-mfa?clientId=1
```

### 3. Test Write Licenses
```http
POST /api/test-cache-write-licenses?clientId=1
```

### 4. Test Write Secure Score
```http
POST /api/test-cache-write-secure-score?clientId=1
```

### 5. Test Write Users
```http
POST /api/test-cache-write-users?clientId=1
```

### 6. Test Write User Details
```http
POST /api/test-cache-write-user-details/{user_id}?clientId=1
```

### 7. Test Write All Caches
```http
POST /api/test-cache-write-all?clientId=1
```

**Returns:**
```json
{
  "status_code": 200,
  "data": {
    "org_id": 1,
    "results": {
      "compliance": true,
      "mfa": true,
      "licenses": true,
      "secure_score": true,
      "users": true
    },
    "total_success": 5,
    "total_failed": 0
  }
}
```

---

## 🔄 Complete Flow Diagram

```
┌─────────────────┐
│   Frontend      │
│  (React/Vue)    │
└────────┬────────┘
         │
         │ 1. GET /api/test-cache-read-clients?u_id={auth_user_id}
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Backend: get_cached_clients()                          │
│  - Resolve u_id → account_id (SQL function/query)       │
│  - Query: organizations WHERE account_id = X            │
│  - Return ALL organizations for account                 │
└────────┬────────────────────────────────────────────────┘
         │
         │ Response: [{"org_id": 1, ...}, {"org_id": 2, ...}]
         │
         ▼
┌─────────────────┐
│   Frontend      │
│  Selects org_id │
└────────┬────────┘
         │
         │ 2. GET /api/test-cache-read-compliance?clientId=1
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Backend: get_cached_compliance(org_id)                 │
│  - Query: m365_compliance_snapshots WHERE org_id = 1    │
│  - Check TTL validity                                   │
│  - Transform DB → Frontend JSON                         │
└────────┬────────────────────────────────────────────────┘
         │
         │ If cache MISS or expired:
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Backend: write_compliance_to_cache(org_id)             │
│  Step 1: Get credentials from m365_credentials          │
│  Step 2: Decrypt client_secret                          │
│  Step 3: Generate Graph API token                       │
│  Step 4: Call Microsoft Graph API                       │
│  Step 5: Transform API Response → DB format             │
│  Step 6: UPSERT to m365_compliance_snapshots            │
└────────┬────────────────────────────────────────────────┘
         │
         │ Cache now populated
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  Backend: get_cached_compliance(org_id) [retry]         │
│  - Return fresh data to frontend                        │
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Phase 2 Implementation Checklist

### Step 1: Encryption/Decryption
- [ ] Get encryption/decryption functions from user
- [ ] Test encryption with sample credentials
- [ ] Implement `decrypt_credential(ciphertext)` function

### Step 2: Credential Retrieval
- [ ] Implement `get_organization_credentials(org_id)`
- [ ] Test with real organization data
- [ ] Handle missing/inactive credentials

### Step 3: Graph API Authentication
- [ ] Implement `get_graph_api_token(tenant_id, client_id, client_secret)`
- [ ] Test token generation with real credentials
- [ ] Handle token refresh and expiration

### Step 4: Graph API Endpoints
- [ ] Determine how to call Graph API endpoints
  - Option A: Call internal `/api/GetAllComplianceStatus` endpoints
  - Option B: Call Microsoft Graph API directly
- [ ] Implement API calls for each data type

### Step 5: WRITE Functions
- [ ] Implement `write_compliance_to_cache(org_id)`
- [ ] Implement `write_mfa_to_cache(org_id)`
- [ ] Implement `write_licenses_to_cache(org_id)`
- [ ] Implement `write_secure_score_to_cache(org_id)`
- [ ] Implement `write_users_to_cache(org_id)`
- [ ] Implement `write_user_details_to_cache(user_id, org_id)`
- [ ] Implement `write_all_caches_to_cache(org_id)`

### Step 6: Test Endpoints
- [ ] Create POST `/api/test-cache-write-compliance`
- [ ] Create POST `/api/test-cache-write-mfa`
- [ ] Create POST `/api/test-cache-write-licenses`
- [ ] Create POST `/api/test-cache-write-secure-score`
- [ ] Create POST `/api/test-cache-write-users`
- [ ] Create POST `/api/test-cache-write-user-details/{user_id}`
- [ ] Create POST `/api/test-cache-write-all`

### Step 7: Testing & Validation
- [ ] Test WRITE → READ cycle for each endpoint
- [ ] Verify data integrity (API response matches cache)
- [ ] Test UPSERT logic (update existing records)
- [ ] Test error handling (invalid credentials, API failures)
- [ ] Monitor API call logs in `api_call_logs` table

### Step 8: Integration Credentials (Future)
- [ ] Implement retrieval for NinjaOne credentials
- [ ] Implement retrieval for Autotask credentials
- [ ] Implement retrieval for ConnectSecure credentials
- [ ] Link external IDs via `organization_integration_mappings`

---

## 🔒 Security Considerations

### Credential Storage
- ✅ `client_secret` stored **ENCRYPTED** in `m365_credentials.client_secret`
- ✅ Integration credentials stored **ENCRYPTED** in `integration_credentials.credentials` JSONB
- ✅ `ENCRYPTION_KEY` stored in `.env` (never committed to git)

### Access Control
- ✅ Frontend sends `u_id` (authenticated user)
- ✅ Backend resolves `u_id` → `account_id` → organizations
- ✅ Users can only access organizations belonging to their account
- ✅ No direct access to `client_secret` without decryption

### Token Management
- ✅ Access tokens never stored permanently
- ✅ Tokens generated on-demand for API calls
- ✅ `last_token_refresh` timestamp tracked
- ✅ Failed auth attempts logged in `api_call_logs`

---

## 📊 Database Schema Changes (Phase 2 Updates)

### Updated: `get_cached_clients()` Function
- **OLD:** Returns ALL organizations (no filtering)
- **NEW:** Accepts `u_id` parameter, returns organizations for user's account

### Updated: `/api/test-cache-read-clients` Endpoint
- **OLD:** No parameters
- **NEW:** `?u_id={auth_user_id}` parameter (required)

### New: SQL Function (Optional)
```sql
CREATE OR REPLACE FUNCTION get_account_id_from_user_id(p_auth_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_account_id INTEGER;
BEGIN
    SELECT account_id INTO v_account_id
    FROM platform_users
    WHERE auth_user_id = p_auth_user_id
    LIMIT 1;

    RETURN v_account_id;
END;
$$ LANGUAGE plpgsql;
```

**Usage in Python:**
```python
# Option 1: SQL function
result = supabase.rpc('get_account_id_from_user_id', {'p_auth_user_id': u_id}).execute()
account_id = result.data

# Option 2: Direct query (simpler)
user = supabase.table('platform_users').select('account_id').eq('auth_user_id', u_id).execute()
account_id = user.data[0]['account_id']
```

---

## ⚠️ Error Handling

### Common Errors

**1. Credentials Not Found**
```json
{
  "status_code": 404,
  "error": "No M365 credentials found for org_id: 1"
}
```

**2. Token Generation Failed**
```json
{
  "status_code": 401,
  "error": "Failed to generate Graph API token for tenant: {tenant_id}"
}
```

**3. Graph API Call Failed**
```json
{
  "status_code": 502,
  "error": "Graph API request failed: {error_message}"
}
```

**4. Database Write Failed**
```json
{
  "status_code": 500,
  "error": "Failed to write compliance cache: {error_message}"
}
```

---

## 🚀 Testing Phase 2

### Step 1: Populate Credentials
Manually insert test credentials into `m365_credentials`:
```sql
INSERT INTO m365_credentials (organization_id, account_id, tenant_id, client_id, client_secret)
VALUES (1, 1, 'your-tenant-id', 'your-client-id', encrypt('your-client-secret'));
```

### Step 2: Test Token Generation
```bash
curl -X POST "http://localhost:8000/api/test-token-generation?clientId=1"
```

### Step 3: Test Individual WRITE
```bash
curl -X POST "http://localhost:8000/api/test-cache-write-compliance?clientId=1"
```

### Step 4: Verify Cache
```bash
curl "http://localhost:8000/api/test-cache-read-compliance?clientId=1"
```

### Step 5: Test Complete Cycle
```bash
# 1. Write all caches
curl -X POST "http://localhost:8000/api/test-cache-write-all?clientId=1"

# 2. Read all caches
curl "http://localhost:8000/api/test-cache-read-all?clientId=1"
```

---

## ✅ Success Criteria

### Phase 2 Complete When:
1. ✅ Credentials retrieved and decrypted successfully
2. ✅ Graph API tokens generated without errors
3. ✅ All WRITE functions successfully save data to cache tables
4. ✅ WRITE → READ cycle produces identical data
5. ✅ UPSERT logic works (updates existing records)
6. ✅ Error handling catches invalid credentials, API failures
7. ✅ API call logs populated in `api_call_logs` table
8. ✅ `/api/test-cache-read-clients?u_id=X` returns correct organizations for user

---

## 📝 Next Steps After Phase 2

### Phase 3: Production Integration
1. Replace test endpoints with production endpoints
2. Add background job scheduler for automatic cache refresh
3. Implement cache invalidation strategy
4. Add monitoring and alerting for cache freshness
5. Optimize query performance with database indexes

### Phase 4: Additional Integrations
1. NinjaOne credential retrieval and API calls
2. Autotask credential retrieval and API calls
3. ConnectSecure credential retrieval and API calls
4. Link external IDs via `organization_integration_mappings`

---

## 📞 Contact & Questions

For questions about:
- **Encryption/Decryption:** User will provide functions
- **Graph API Endpoints:** Determine if calling internal APIs or Microsoft directly
- **Credential Format:** Confirm encryption method (Fernet/AES/Base64)
- **SQL Functions:** Optional optimization for `u_id` → `account_id` resolution

---

**Last Updated:** Phase 2 Implementation Plan Added
**Status:** Phase 1 Complete ✅ | Phase 2 Ready for Implementation 🚧
