"""
Cache services for reading M365 data from Supabase cache tables.
Transforms database columns to frontend JSON format matching original endpoints EXACTLY.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from supabase_services import supabase

logger = logging.getLogger(__name__)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def is_cache_valid(checked_at_str: str, ttl_minutes: int = 30) -> bool:
    """
    Check if cached data is still valid based on TTL (Time-To-Live).

    Args:
        checked_at_str: ISO 8601 datetime string from database (e.g., "2025-01-15T10:30:00Z")
        ttl_minutes: Cache validity period in minutes (default: 30)

    Returns:
        True if cache is still valid, False if expired
    """
    try:
        # Parse the ISO datetime string
        checked_at = datetime.fromisoformat(checked_at_str.replace('Z', '+00:00'))
        now = datetime.now(checked_at.tzinfo)  # Use same timezone

        # Calculate expiration time
        expiration_time = checked_at + timedelta(minutes=ttl_minutes)

        is_valid = now < expiration_time

        if is_valid:
            logger.info(f"✅ Cache valid - expires in {(expiration_time - now).total_seconds() / 60:.1f} minutes")
        else:
            logger.warning(f"⏰ Cache expired - {(now - expiration_time).total_seconds() / 60:.1f} minutes ago")

        return is_valid

    except Exception as e:
        logger.error(f"Error checking cache validity: {e}")
        return False


# ============================================================================
# COMPLIANCE CACHE FUNCTIONS
# ============================================================================

async def get_cached_compliance(organization_id: int) -> Optional[Dict[str, Any]]:
    """
    Read compliance data from m365_compliance_snapshots table.

    Database Schema:
        - organization_id (int)
        - status (varchar) - "Compliant", "Partially Compliant", "Not Compliant"
        - score_percentage (int) - 0-100
        - total_policies (int)
        - policies_data (jsonb) - {"policies": [{...}, {...}]}
        - breakdown (jsonb) - {"compliant": {...}, "partially_compliant": {...}, ...}
        - title (varchar) - "Microsoft 365 Compliance Status"
        - checked_at (timestamp)

    Returns:
        JSON matching /api/GetAllComplianceStatus response format
    """
    try:
        logger.info(f"📖 Reading compliance cache for organization_id: {organization_id}")

        # Query latest compliance snapshot
        response = supabase.table('m365_compliance_snapshots')\
            .select('*')\
            .eq('organization_id', organization_id)\
            .order('checked_at', desc=True)\
            .limit(1)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No compliance cache found for organization_id: {organization_id}")
            return None

        cache_entry = response.data[0]

        # Check if cache is still valid (1 week TTL for testing)
        if not is_cache_valid(cache_entry['checked_at'], ttl_minutes=100800):
            logger.warning(f"⏰ Compliance cache expired for organization_id: {organization_id}")
            return None

        # Extract breakdown from JSONB
        breakdown_data = cache_entry.get('breakdown', {})

        # Extract policies from JSONB (stored as {"policies": [...]})
        policies_data = cache_entry.get('policies_data', {})
        policies_array = policies_data.get('policies', [])

        # Build frontend JSON exactly matching /api/GetAllComplianceStatus
        frontend_json = {
            "compliance_summary": {
                "title": cache_entry.get('title', 'Microsoft 365 Compliance Status'),
                "status": cache_entry['status'],
                "score_percentage": f"{cache_entry['score_percentage']}%",
                "total_policies": cache_entry['total_policies'],
                "breakdown": breakdown_data  # Already in correct format from JSONB
            },
            "policies": policies_array  # Extract from nested structure
        }

        logger.info(f"✅ Compliance cache retrieved - Status: {cache_entry['status']}, Score: {cache_entry['score_percentage']}%")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving compliance cache for organization_id {organization_id}: {e}")
        return None


# ============================================================================
# MFA CACHE FUNCTIONS
# ============================================================================

async def get_cached_mfa(organization_id: int) -> Optional[List[Dict[str, Any]]]:
    """
    Read MFA data from m365_mfa_snapshots table.

    Database Schema:
        - organization_id (int)
        - percentage (numeric) - 56.4
        - status (varchar)
        - total_users (int)
        - mfa_enabled (int)
        - mfa_disabled (int)
        - mfa_registered (int)
        - conditional_access (int)
        - security_defaults (int)
        - per_user_mfa (int)
        - recommendation (text)
        - description (text)
        - measurement_date (timestamp)

    Returns:
        JSON array matching /api/GetMFAComplianceReport response format
    """
    try:
        logger.info(f"📖 Reading MFA cache for organization_id: {organization_id}")

        # Query latest MFA snapshot
        response = supabase.table('m365_mfa_snapshots')\
            .select('*')\
            .eq('organization_id', organization_id)\
            .order('measurement_date', desc=True)\
            .limit(1)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No MFA cache found for organization_id: {organization_id}")
            return None

        cache_entry = response.data[0]

        # Check if cache is still valid (1 week TTL for testing)
        if not is_cache_valid(cache_entry['measurement_date'], ttl_minutes=100800):
            logger.warning(f"⏰ MFA cache expired for organization_id: {organization_id}")
            return None

        # Format percentage as string with % symbol
        percentage_value = float(cache_entry['percentage'])
        percentage_str = f"{percentage_value}%" if percentage_value == int(percentage_value) else f"{percentage_value:.1f}%"

        # Build frontend JSON exactly matching /api/GetMFAComplianceReport
        frontend_json = [{
            "percentage": percentage_str,
            "status": cache_entry['status'],
            "target": "100%",  # Always 100%
            "total_users": cache_entry['total_users'],
            "mfa_enabled": cache_entry['mfa_enabled'],
            "mfa_disabled": cache_entry['mfa_disabled'],
            "enabled_by_method": {
                "mfa_registered": cache_entry['mfa_registered'],
                "conditional_access": cache_entry['conditional_access'],
                "security_defaults": cache_entry['security_defaults'],
                "per_user_mfa": cache_entry['per_user_mfa']
            },
            "recommendation": cache_entry['recommendation'],
            "details": {
                "description": cache_entry['description'],
                "measurement_date": cache_entry['measurement_date']
            }
        }]

        logger.info(f"✅ MFA cache retrieved - Status: {cache_entry['status']}, Percentage: {percentage_str}")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving MFA cache for organization_id {organization_id}: {e}")
        return None


# ============================================================================
# LICENSE CACHE FUNCTIONS
# ============================================================================

async def get_cached_licenses(organization_id: int) -> Optional[Dict[str, Any]]:
    """
    Read license data from m365_license_snapshots table.

    Database Schema:
        - organization_id (int)
        - total_users (int)
        - others_count (int)
        - standard_count (int)
        - premium_count (int)
        - basic_count (int)
        - license_details (jsonb) - {"licenseDetails": [{...}, {...}]}
        - snapshot_date (timestamp)

    Returns:
        JSON matching /api/GetLicenseSummary response format
    """
    try:
        logger.info(f"📖 Reading license cache for organization_id: {organization_id}")

        # Query latest license snapshot
        response = supabase.table('m365_license_snapshots')\
            .select('*')\
            .eq('organization_id', organization_id)\
            .order('snapshot_date', desc=True)\
            .limit(1)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No license cache found for organization_id: {organization_id}")
            return None

        cache_entry = response.data[0]

        # Check if cache is still valid (1 week TTL for testing)
        if not is_cache_valid(cache_entry['snapshot_date'], ttl_minutes=100800):
            logger.warning(f"⏰ License cache expired for organization_id: {organization_id}")
            return None

        # Extract license details from JSONB (stored as {"licenseDetails": [...]})
        license_data = cache_entry.get('license_details', {})
        license_details_array = license_data.get('licenseDetails', [])

        # Build frontend JSON exactly matching /api/GetLicenseSummary
        frontend_json = {
            "totalUsers": cache_entry['total_users'],
            "licenseDistribution": {
                "Others": cache_entry['others_count'],
                "Standard": cache_entry['standard_count'],
                "Premium": cache_entry['premium_count'],
                "Basic": cache_entry['basic_count']
            },
            "licenseDetails": license_details_array  # Extract from nested structure
        }

        logger.info(f"✅ License cache retrieved - Total Users: {cache_entry['total_users']}, Licenses: {len(license_details_array)}")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving license cache for organization_id {organization_id}: {e}")
        return None


# ============================================================================
# SECURE SCORE CACHE FUNCTIONS
# ============================================================================

async def get_cached_secure_score(organization_id: int) -> Optional[Dict[str, Any]]:
    """
    Read secure score data from m365_secure_score_history table.

    Database Schema:
        - organization_id (int)
        - current_score (numeric)
        - max_score (numeric)
        - percentage (numeric)
        - active_user_count (int)
        - licensed_user_count (int)
        - top_improvement_actions (jsonb) - [{...}, {...}]
        - all_improvement_actions (jsonb) - [{...}, {...}]
        - completed_actions (jsonb) - [{...}, {...}]
        - score_data (jsonb) - Contains createdDateTime and azureTenantId
        - created_at (timestamp)

    Returns:
        JSON matching /api/GetMicrosoftSecureScore response format
    """
    try:
        logger.info(f"📖 Reading secure score cache for organization_id: {organization_id}")

        # Query latest secure score snapshot
        response = supabase.table('m365_secure_score_history')\
            .select('*')\
            .eq('organization_id', organization_id)\
            .order('created_at', desc=True)\
            .limit(1)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No secure score cache found for organization_id: {organization_id}")
            return None

        cache_entry = response.data[0]

        # Check if cache is still valid (1 week TTL for testing)
        if not is_cache_valid(cache_entry['created_at'], ttl_minutes=100800):
            logger.warning(f"⏰ Secure score cache expired for organization_id: {organization_id}")
            return None

        # Format percentage as string
        percentage_value = float(cache_entry['percentage'])
        percentage_str = f"{int(percentage_value)}%" if percentage_value == int(percentage_value) else f"{percentage_value:.0f}%"

        # Get score_data JSONB (contains createdDateTime)
        score_data_jsonb = cache_entry.get('score_data', {})
        created_date_time = score_data_jsonb.get('createdDateTime', cache_entry['created_at'])

        # Build frontend JSON exactly matching /api/GetMicrosoftSecureScore
        frontend_json = {
            "scoreData": {
                "currentScore": int(cache_entry['current_score']),
                "maxScore": int(cache_entry['max_score']),
                "percentage": percentage_str,
                "activeUserCount": cache_entry['active_user_count'],
                "licensedUserCount": cache_entry['licensed_user_count'],
                "createdDateTime": created_date_time
                # Note: azureTenantId removed as per user request (not in Supabase table)
            },
            "topImprovementActions": cache_entry.get('top_improvement_actions', []),
            "allImprovementActions": cache_entry.get('all_improvement_actions', []),
            "completedActions": cache_entry.get('completed_actions', [])
        }

        logger.info(f"✅ Secure score cache retrieved - Score: {cache_entry['current_score']}/{cache_entry['max_score']} ({percentage_str})")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving secure score cache for organization_id {organization_id}: {e}")
        return None


# ============================================================================
# USER LIST CACHE FUNCTIONS
# ============================================================================

async def get_cached_users_list(organization_id: int) -> Optional[Dict[str, Any]]:
    """
    Read ALL users for an organization from m365_users table.

    Database Schema (m365_users):
        - id (int, PK)
        - organization_id (int, FK)
        - user_id (varchar, UNIQUE) - Graph API user ID
        - display_name (varchar)
        - email (varchar)
        - department (varchar)
        - role (varchar)
        - status (varchar)
        - mfa_enabled (boolean)
        - user_principal_name (varchar)
        - last_synced (timestamp)

    Returns:
        JSON matching /api/ListUsers response format
    """
    try:
        logger.info(f"📖 Reading users list cache for organization_id: {organization_id}")

        # Query all users for this organization
        response = supabase.table('m365_users')\
            .select('*')\
            .eq('organization_id', organization_id)\
            .order('last_synced', desc=True)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No users found for organization_id: {organization_id}")
            return None

        # Check if cache is still valid (using first user's timestamp) (1 week TTL for testing)
        first_user = response.data[0]
        if not is_cache_valid(first_user['last_synced'], ttl_minutes=100800):
            logger.warning(f"⏰ Users cache expired for organization_id: {organization_id}")
            return None

        # Transform each user to frontend format
        users_array = []
        for user in response.data:
            users_array.append({
                "UserId": user['user_id'],
                "Name": user['display_name'],
                "Email": user['email'],
                "Department": user['department'],
                "Role": user['role'],
                "Status": user['status'],
                "MFA": user['mfa_enabled']
            })

        # Build frontend JSON exactly matching /api/ListUsers
        frontend_json = {
            "users": users_array
        }

        logger.info(f"✅ Users list cache retrieved - {len(users_array)} users found")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving users list cache for organization_id {organization_id}: {e}")
        return None


# ============================================================================
# USER DETAILS CACHE FUNCTIONS (Single User)
# ============================================================================

async def get_cached_clients(u_id: str) -> Optional[Dict[str, Any]]:
    """
    Read clients/organizations from organizations table filtered by user's account.

    Flow:
        1. Get account_id from u_id using SQL function
        2. Query organizations WHERE account_id = X
        3. Return organizations for that account only

    Database Schema (organizations table):
        - id (serial, PK) - This is the org_id
        - account_id (int, FK)
        - platform_user_id (int, FK)
        - organization_name (varchar)
        - domain (varchar)
        - industry (varchar)
        - organization_size (varchar)
        - status (varchar) - default 'Active'
        - created_at (timestamp)
        - updated_at (timestamp)

    Args:
        u_id: User UUID from auth.users.id / platform_users.auth_user_id

    Returns:
        JSON matching /api/GetClients response format
    """
    try:
        logger.info(f"📖 Reading clients/organizations for u_id: {u_id}")

        # Step 1: Get account_id from u_id using SQL function
        account_response = supabase.rpc('get_account_id_from_uid', {'user_uid': u_id}).execute()

        if not account_response.data:
            logger.warning(f"❌ No account found for u_id: {u_id}")
            return None

        account_id = account_response.data
        logger.info(f"✅ Resolved u_id to account_id: {account_id}")

        # Step 2: Query organizations filtered by account_id
        response = supabase.table('organizations')\
            .select('*')\
            .eq('account_id', account_id)\
            .order('created_at', desc=True)\
            .execute()

        if not response.data or len(response.data) == 0:
            logger.warning(f"❌ No organizations found for account_id: {account_id}")
            return None

        # Check if cache is still valid (2 weeks TTL - using first organization's timestamp)
        first_org = response.data[0]
        if not is_cache_valid(first_org['created_at'], ttl_minutes=201600):
            logger.warning(f"⏰ Organizations cache expired")
            return None

        # Transform each organization to frontend format
        clients_array = []
        for org in response.data:
            # Format dates as MM/DD/YYYY
            created_date = org['created_at']
            updated_date = org['updated_at']

            # Parse and format dates
            try:
                from datetime import datetime
                created_dt = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                updated_dt = datetime.fromisoformat(updated_date.replace('Z', '+00:00'))

                created_formatted = created_dt.strftime("%m/%d/%Y")
                updated_formatted = updated_dt.strftime("%m/%d/%Y")
            except:
                created_formatted = "N/A"
                updated_formatted = "N/A"

            clients_array.append({
                "ninjaone_org_id": None,  # Temporary: null for now
                "organization_name": org['organization_name'],
                "domain": {
                    "url": org.get('domain'),
                    "text": "Visit Website"  # Always "Visit Website"
                },
                "org_id": org['id'],  # The serial primary key from organizations table
                "created": {
                    "created_date": created_formatted,
                    "updated_date": updated_formatted
                },
                "status": org.get('status', 'Active'),
                "industry": org.get('industry'),
                "organization_size": org.get('organization_size')
            })

        # Build frontend JSON exactly matching /api/GetClients
        frontend_json = {
            "success": True,
            "clients": clients_array,
            "count": len(clients_array)
        }

        logger.info(f"✅ Clients cache retrieved - {len(clients_array)} organizations found for account_id: {account_id}")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving clients cache: {e}")
        return None


async def get_cached_user_details(user_id: str, organization_id: int) -> Optional[Dict[str, Any]]:
    """
    Read ONE user's complete details from m365_users + m365_user_details + m365_user_devices.

    Database Schema (3 tables):
        m365_users: Basic user info
        m365_user_details: Mailbox, OneDrive, activity, security details
        m365_user_devices: User's devices

    Returns:
        JSON matching /api/UserDetails/{user_id} response format
    """
    try:
        logger.info(f"📖 Reading user details cache for user_id: {user_id}")

        # Query user from m365_users table
        user_response = supabase.table('m365_users')\
            .select('*')\
            .eq('user_id', user_id)\
            .eq('organization_id', organization_id)\
            .limit(1)\
            .execute()

        if not user_response.data or len(user_response.data) == 0:
            logger.warning(f"❌ No user found for user_id: {user_id}")
            return None

        user = user_response.data[0]

        # Check if cache is still valid (1 week TTL for testing)
        if not is_cache_valid(user['last_synced'], ttl_minutes=100800):
            logger.warning(f"⏰ User cache expired for user_id: {user_id}")
            return None

        # Query user details from m365_user_details table (using Graph API user_id, NOT internal id)
        details_response = supabase.table('m365_user_details')\
            .select('*')\
            .eq('user_id', user['user_id'])\
            .limit(1)\
            .execute()

        user_details = details_response.data[0] if details_response.data else {}

        # Query user devices from m365_user_devices table (using Graph API user_id, NOT internal id)
        devices_response = supabase.table('m365_user_devices')\
            .select('*')\
            .eq('user_id', user['user_id'])\
            .execute()

        devices_data = devices_response.data if devices_response.data else []

        # Transform devices to frontend format
        device_list = []
        for device in devices_data:
            device_list.append({
                "device_id": device['device_id'],
                "device_name": device['device_name'],
                "device_type": device['device_type']
            })

        # Build frontend JSON exactly matching /api/UserDetails/{user_id}
        frontend_json = {
            "UserId": user['user_id'],
            "Name": user['display_name'],
            "Email": user['email'],
            "Department": user_details.get('department') or "Not Available",
            "Role": user['role'],
            "Status": user['status'],
            "MFA": user['mfa_enabled'],
            "last_sign_in": user_details.get('last_sign_in') or "Not Available",
            "mfa_methods": user_details.get('authentication_methods', []),
            "licenses": user_details.get('licenses', []),
            "mailbox": {
                "size_in_mb": user_details.get('mailbox_size_mb') or 0,
                "quota_in_mb": user_details.get('mailbox_quota_mb') or 50000,
                "usage_percentage": user_details.get('mailbox_usage_percentage') or 0,
                "items_count": user_details.get('mailbox_items_count') or 0,
                "archived_items_count": user_details.get('mailbox_archived_items_count') or 0
            },
            "one_drive": {
                "size_in_mb": user_details.get('onedrive_size_mb') or 0,
                "quota_in_mb": user_details.get('onedrive_quota_mb') or 0,
                "usage_percentage": user_details.get('onedrive_usage_percentage') or 0,
                "files_count": user_details.get('onedrive_files_count') or 0
            },
            "activity": {
                "teams_calls_minutes_last_30_days": user_details.get('teams_calls_minutes_last_30_days') or 0,
                "teams_meetings_count_last_30_days": user_details.get('teams_meetings_count_last_30_days') or 0,
                "teams_messages_count_last_30_days": user_details.get('teams_messages_count_last_30_days') or 0,
                "email_sent_count_last_30_days": user_details.get('email_sent_count_last_30_days') or 0,
                "documents_edited_last_30_days": user_details.get('documents_edited_last_30_days') or 0
            },
            "security": {
                "risk_level": user_details.get('risk_level') or 'low',
                "sign_in_attempts_last_30_days": user_details.get('sign_in_attempts_last_30_days') or 0,
                "blocked_sign_in_attempts": user_details.get('blocked_sign_in_attempts') or 0,
                "authentication_methods": user_details.get('authentication_methods', []),
                "last_password_change": user_details.get('last_password_change') or "Not Available",
                "mfa_enabled": user['mfa_enabled'],
                "last_sign_in": user_details.get('last_sign_in') or "Not Available"
            },
            "groups": user_details.get('groups', []),
            "devices": {
                "total_devices": len(device_list),
                "device_list": device_list
            }
        }

        logger.info(f"✅ User details cache retrieved - User: {user['display_name']}, Devices: {len(device_list)}")
        return frontend_json

    except Exception as e:
        logger.error(f"❌ Error retrieving user details cache for user_id {user_id}: {e}")
        return None
