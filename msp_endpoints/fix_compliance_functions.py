#!/usr/bin/env python3
"""
Script to fix the compliance functions that were broken during optimization.
This script will add back the necessary token acquisition logic to individual endpoints.
"""

# Function template to add to each individual endpoint
FUNCTION_PREFIX = '''    try:
        # Extract identifier and type from credentials
        identifier, identifier_type = credentials

        # Get client_id
        if identifier_type == "ninjaone_org_id":
            from supabase_services import supabase
            response = supabase.table('organization_mapping').select('client_id').eq('ninjaone_org_id', identifier).execute()
            if not response.data or len(response.data) == 0:
                raise Exception(f"No client_id found for ninjaone_org_id: {identifier}")
            client_id = response.data[0]['client_id']
        else:
            client_id = identifier

        # Get token for this individual endpoint
        token = await get_access_token_by_identifier(identifier, identifier_type)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        # Original function logic continues below...
'''

# Functions that need to be fixed
FUNCTIONS_TO_FIX = [
    "list_sharepoint_external_resharing_status",
    "list_unified_auditing_status",
    "list_high_risk_users_signin_policies",
    "list_risky_signin_policies",
    "list_shared_mailbox_signin_status",
    "list_guest_user_access_permissions",
    "list_sharepoint_site_creation_status",
    "list_weak_authenticator_status",
    "list_global_admins",
    "check_password_expiration_policy",
    "list_spf_policy_status",
    "check_teams_external_access",
    "list_risky_country_locations",
    "list_connected_apps_user_consents"
]

print("Functions that need token acquisition logic added:")
for func in FUNCTIONS_TO_FIX:
    print(f"- {func}")

print(f"\nTotal functions to fix: {len(FUNCTIONS_TO_FIX)}")
print("\nFunction prefix to add:")
print(FUNCTION_PREFIX)