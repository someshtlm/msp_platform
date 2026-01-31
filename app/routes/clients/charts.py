"""
Integration Platform Charts Endpoints
======================================
Endpoints for managing integration platforms and their available charts
"""

import logging
from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime
from app.schemas.api import GraphApiResponse
from app.core.database.supabase_services import supabase
from app.schemas.api import SavePlatformCredentialsRequest

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/PlatformList", response_model=GraphApiResponse, summary="Get All Integration Platforms with User Credentials")
async def get_platform_list(u_id: str):
    """
    Get list of all integration platforms with their available charts and pre-filled credential values for a specific user.

    Query Parameters:
    - u_id: User UUID from auth.users

    Returns a list of platforms with their details including:
    - platform_id: Unique identifier
    - name: Display name of the platform
    - description: Platform description
    - enabled: Whether the platform is active
    - integrationFields: Required fields for integration WITH pre-filled values
    - chartlist: List of available charts for this platform


    """
    try:
        logger.info(f"Fetching integration platforms with credentials for u_id: {u_id}")

        # ================================================================
        # Step 1: Get account_id from u_id
        # ================================================================
        try:
            account_response = supabase.rpc('get_account_id_from_uid', {'user_uid': u_id}).execute()

            if not account_response.data:
                logger.warning(f"User not found for u_id: {u_id}")
                return GraphApiResponse(
                    status_code=404,
                    data=[],
                    error="User not found"
                )

            account_id = account_response.data
            logger.info(f"Found account_id: {account_id} for u_id: {u_id}")

        except Exception as e:
            logger.error(f"Error fetching account_id from u_id: {str(e)}")
            return GraphApiResponse(
                status_code=500,
                data=[],
                error=f"Failed to retrieve account information: {str(e)}"
            )

        # ================================================================
        # Step 2: Fetch and decrypt credentials for this account
        # ================================================================
        decrypted_credentials = {}
        try:
            creds_response = supabase.table('integration_credentials')\
                .select('credentials')\
                .eq('account_id', account_id)\
                .limit(1)\
                .execute()

            if creds_response.data and len(creds_response.data) > 0:
                encrypted_blob = creds_response.data[0]['credentials']

                # Decrypt credentials
                from app.services.encryption.manager import EncryptionManager
                encryption_manager = EncryptionManager()
                decrypted_credentials = encryption_manager.decrypt_integration_credentials(encrypted_blob)
                logger.info(f"Successfully decrypted credentials for account {account_id}")
                logger.info(f"Found credentials for platforms: {list(decrypted_credentials.keys())}")
            else:
                logger.info(f"No credentials found for account {account_id}, will return empty values")

        except Exception as e:
            logger.warning(f"Error fetching/decrypting credentials: {str(e)}, will return empty values")
            decrypted_credentials = {}

        # ================================================================
        # Step 3: Query integrations table - get all platforms
        # ================================================================
        response = supabase.table('integrations')\
            .select('id, integration_key, integration_display_name, description, integration_fields, is_active')\
            .order('id')\
            .execute()

        if not response.data:
            logger.warning("No integration platforms found in database")
            return GraphApiResponse(
                status_code=200,
                data=[],
                error=None
            )

        # ================================================================
        # Step 4: Fetch all available charts for all platforms
        # ================================================================
        charts_response = supabase.table('platform_available_charts')\
            .select('id, integration_id, chart_key, chart_display_name, chart_description')\
            .order('integration_id, id')\
            .execute()

        # Group charts by integration_id for efficient lookup
        charts_by_platform = {}
        if charts_response.data:
            for chart in charts_response.data:
                integration_id = chart.get('integration_id')
                if integration_id not in charts_by_platform:
                    charts_by_platform[integration_id] = []

                charts_by_platform[integration_id].append({
                    "chart_id": chart.get('id'),
                    "chart_key": chart.get('chart_key'),
                    "chart_display_name": chart.get('chart_display_name'),
                    "chart_description": chart.get('chart_description', '')
                })

        # ================================================================
        # Step 5: Fetch user's selected charts for this account
        # ================================================================
        selected_charts_by_platform = {}
        try:
            # Get all chart_ids selected by this account
            selected_charts_response = supabase.table('account_selected_charts')\
                .select('chart_id')\
                .eq('account_id', account_id)\
                .execute()

            if selected_charts_response.data:
                # Get chart_ids list
                selected_chart_ids = [item['chart_id'] for item in selected_charts_response.data]

                # Fetch full chart details for selected charts
                selected_chart_details = supabase.table('platform_available_charts')\
                    .select('id, integration_id, chart_key, chart_display_name, chart_description')\
                    .in_('id', selected_chart_ids)\
                    .execute()

                # Group selected charts by platform (integration_id)
                if selected_chart_details.data:
                    for chart in selected_chart_details.data:
                        integration_id = chart.get('integration_id')
                        if integration_id not in selected_charts_by_platform:
                            selected_charts_by_platform[integration_id] = []

                        selected_charts_by_platform[integration_id].append({
                            "chart_id": chart.get('id'),
                            "chart_key": chart.get('chart_key'),
                            "chart_display_name": chart.get('chart_display_name'),
                            "chart_description": chart.get('chart_description', '')
                        })

                logger.info(f"Found {len(selected_chart_ids)} selected charts for account {account_id}")
            else:
                logger.info(f"No selected charts found for account {account_id}")

        except Exception as e:
            logger.warning(f"Error fetching selected charts: {str(e)}, will return empty arrays")
            selected_charts_by_platform = {}

        # ================================================================
        # Step 6: Transform records and add credential values + selected charts
        # ================================================================
        platforms = []
        for record in response.data:
            platform_id = record.get('id')
            integration_key = record.get('integration_key')
            integration_fields = record.get('integration_fields', [])

            # Get credentials for this platform (if they exist)
            platform_credentials = decrypted_credentials.get(integration_key, {})

            # Add "value" field to each integration field
            fields_with_values = []
            for field in integration_fields:
                field_name = field.get('name')
                field_value = platform_credentials.get(field_name, "")  # Empty string if not found

                # Create new field dict with value
                field_with_value = {
                    "name": field.get('name'),
                    "type": field.get('type'),
                    "label": field.get('label'),
                    "required": field.get('required', False),
                    "field_info": field.get('field_info', ''),
                    "value": field_value
                }
                fields_with_values.append(field_with_value)

            platform = {
                "platform_id": platform_id,
                "name": record.get('integration_display_name'),
                "description": record.get('description', ''),
                "enabled": record.get('is_active', False),
                "integrationFields": fields_with_values,
                "chartlist": charts_by_platform.get(platform_id, []),
                "account_selected_charts": selected_charts_by_platform.get(platform_id, [])
            }
            platforms.append(platform)

        logger.info(f"Successfully retrieved {len(platforms)} integration platforms with credentials for account {account_id}")

        return GraphApiResponse(
            status_code=200,
            data=platforms,
            error=None
        )

    except Exception as e:
        logger.error(f"Error fetching integration platforms: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data=[],
            error=f"Failed to fetch integration platforms: {str(e)}"
        )


@router.post("/SavePlatformCredentials", response_model=GraphApiResponse, summary="Save Platform Credentials and Chart Selections")
async def save_platform_credentials(request: SavePlatformCredentialsRequest):
    """
    Save credentials and selected charts for a single platform.

    This endpoint:
    1. Validates user UUID and gets account_id
    2. Validates platform_id exists
    3. Validates charts belong to the platform
    4. Merges credentials with existing ones
    5. Encrypts and saves to integration_credentials table
    6. Inserts chart selections into account_selected_charts table

    """
    try:
        logger.info(f"SavePlatformCredentials called for platform_id: {request.platform_id}")

        # ================================================================
        # Step 1: Get account_id from UUID
        # ================================================================
        try:
            account_response = supabase.rpc('get_account_id_from_uid', {'user_uid': request.uuid}).execute()

            if not account_response.data:
                logger.warning(f"User not found for UUID: {request.uuid}")
                return GraphApiResponse(
                    status_code=404,
                    data={"success": False},
                    error="User not found"
                )

            account_id = account_response.data
            logger.info(f"Found account_id: {account_id} for UUID: {request.uuid}")

        except Exception as e:
            logger.error(f"Error fetching account_id from UUID: {str(e)}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error=f"Failed to retrieve account information: {str(e)}"
            )

        # ================================================================
        # Step 2: Get integration details
        # ================================================================
        try:
            integration_response = supabase.table('integrations')\
                .select('id, integration_key, integration_display_name, integration_fields')\
                .eq('id', request.platform_id)\
                .limit(1)\
                .execute()

            if not integration_response.data or len(integration_response.data) == 0:
                logger.warning(f"Platform not found for platform_id: {request.platform_id}")
                return GraphApiResponse(
                    status_code=404,
                    data={"success": False},
                    error=f"Platform not found: platform_id {request.platform_id}"
                )

            integration = integration_response.data[0]
            integration_key = integration['integration_key']
            integration_display_name = integration['integration_display_name']

            logger.info(f"Processing platform: {integration_key} ({integration_display_name})")

        except Exception as e:
            logger.error(f"Error fetching platform details: {str(e)}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error=f"Failed to fetch platform details: {str(e)}"
            )

        # ================================================================
        # Step 3: Validate charts belong to this platform
        # ================================================================
        chart_ids = [chart['chart_id'] for chart in request.chartlist_selected_by_user]

        if chart_ids:
            try:
                charts_validation_response = supabase.table('platform_available_charts')\
                    .select('id, integration_id')\
                    .in_('id', chart_ids)\
                    .execute()

                if charts_validation_response.data:
                    wrong_platform_charts = []
                    for chart in charts_validation_response.data:
                        if chart['integration_id'] != request.platform_id:
                            wrong_platform_charts.append(chart['id'])

                    if wrong_platform_charts:
                        logger.warning(f"Charts belong to different platform: {wrong_platform_charts}")
                        return GraphApiResponse(
                            status_code=400,
                            data={"success": False},
                            error=f"Charts {', '.join(map(str, wrong_platform_charts))} do not belong to this platform"
                        )

                logger.info(f"✓ Chart validation passed for {integration_key}")

            except Exception as e:
                logger.error(f"Error validating charts: {str(e)}")
                return GraphApiResponse(
                    status_code=500,
                    data={"success": False},
                    error=f"Failed to validate charts: {str(e)}"
                )

        # ================================================================
        # Step 4: Merge with existing credentials and save
        # ================================================================
        try:
            existing_creds_response = supabase.table('integration_credentials')\
                .select('id, credentials')\
                .eq('account_id', account_id)\
                .limit(1)\
                .execute()

            from app.services.encryption.manager import EncryptionManager
            encryption_manager = EncryptionManager()

            if existing_creds_response.data and len(existing_creds_response.data) > 0:
                credential_id = existing_creds_response.data[0]['id']
                encrypted_blob = existing_creds_response.data[0]['credentials']

                existing_credentials = encryption_manager.decrypt_integration_credentials(encrypted_blob)
                logger.info(f"Found existing credentials for account {account_id}, merging...")

                existing_credentials[integration_key] = request.credentials

                new_encrypted_blob = encryption_manager.encrypt_integration_credentials(existing_credentials)

                supabase.table('integration_credentials')\
                    .update({
                        'credentials': new_encrypted_blob,
                        'is_active': True,
                        'updated_at': datetime.now().isoformat()
                    })\
                    .eq('id', credential_id)\
                    .execute()

                logger.info(f"Updated credentials for account {account_id}, credential_id: {credential_id}")

            else:
                new_credentials = {integration_key: request.credentials}

                encrypted_blob = encryption_manager.encrypt_integration_credentials(new_credentials)

                insert_result = supabase.table('integration_credentials')\
                    .insert({
                        'account_id': account_id,
                        'credentials': encrypted_blob,
                        'is_active': True,
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    })\
                    .execute()

                credential_id = insert_result.data[0]['id']
                logger.info(f"Created new credentials for account {account_id}, credential_id: {credential_id}")

        except Exception as e:
            logger.error(f"Error saving credentials: {str(e)}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error=f"Failed to save credentials: {str(e)}"
            )

        # ================================================================
        # Step 5: Update chart selections (Handle both select AND deselect)
        # ================================================================
        charts_saved = 0
        try:
            # STEP 5A: Get ALL available charts for this platform
            all_platform_charts_response = supabase.table('platform_available_charts')\
                .select('id')\
                .eq('integration_id', request.platform_id)\
                .execute()

            all_platform_chart_ids = {chart['id'] for chart in all_platform_charts_response.data} if all_platform_charts_response.data else set()

            logger.info(f"Platform {request.platform_id} has {len(all_platform_chart_ids)} available charts")

            # STEP 5B: Get currently selected charts for this account AND platform
            existing_platform_charts_response = supabase.table('account_selected_charts')\
                .select('chart_id')\
                .eq('account_id', account_id)\
                .in_('chart_id', list(all_platform_chart_ids))\
                .execute()

            existing_chart_ids = {chart['chart_id'] for chart in existing_platform_charts_response.data} if existing_platform_charts_response.data else set()

            logger.info(f"Account {account_id} currently has {len(existing_chart_ids)} selected charts for this platform")

            # STEP 5C: Determine which charts to ADD and which to REMOVE
            new_chart_ids = set(chart_ids) if chart_ids else set()

            charts_to_add = new_chart_ids - existing_chart_ids  # New selections
            charts_to_remove = existing_chart_ids - new_chart_ids  # Deselected charts

            logger.info(f"Charts to ADD: {charts_to_add}")
            logger.info(f"Charts to REMOVE: {charts_to_remove}")

            # STEP 5D: DELETE deselected charts
            if charts_to_remove:
                supabase.table('account_selected_charts')\
                    .delete()\
                    .eq('account_id', account_id)\
                    .in_('chart_id', list(charts_to_remove))\
                    .execute()

                logger.info(f"✓ Deleted {len(charts_to_remove)} deselected charts for account {account_id}")

            # STEP 5E: INSERT newly selected charts
            if charts_to_add:
                charts_to_insert = []
                for chart_id in charts_to_add:
                    charts_to_insert.append({
                        'account_id': account_id,
                        'chart_id': chart_id,
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    })

                supabase.table('account_selected_charts').insert(charts_to_insert).execute()
                logger.info(f"✓ Inserted {len(charts_to_add)} new chart selections for account {account_id}")

            charts_saved = len(new_chart_ids)
            logger.info(f"Chart selections updated: {charts_saved} total charts now selected for platform {request.platform_id}")

        except Exception as e:
            logger.error(f"Error updating chart selections: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error=f"Failed to save chart selections: {str(e)}"
            )

        logger.info(f"✓ SavePlatformCredentials completed successfully for account {account_id}")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "platform_name": integration_display_name,
                "charts_saved": charts_saved,
                "credential_id": credential_id
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Unexpected error in SavePlatformCredentials: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Internal server error: {str(e)}"
        )


# ============================================================================
# SMTP CREDENTIALS ENDPOINTS
# ============================================================================

# @router.get("/GetSMTPCredentials", response_model=GraphApiResponse, summary="Get SMTP Credentials for User")
# async def get_smtp_credentials(u_id: str):
#     """
#     Get SMTP credentials for a user with password masked for security.
#
#     Query Parameters:
#     - u_id: User UUID from auth.users
#
#     Returns credentials in frontend format:
#
#     ```
#     """
#     try:
#         logger.info(f"GetSMTPCredentials called for u_id: {u_id}")
#
#         # ================================================================
#         # Step 1: Get account_id from u_id
#         # ================================================================
#         try:
#             account_response = supabase.rpc('get_account_id_from_uid', {'user_uid': u_id}).execute()
#
#             if not account_response.data:
#                 logger.warning(f"User not found for u_id: {u_id}")
#                 return GraphApiResponse(
#                     status_code=404,
#                     data=None,
#                     error="User not found"
#                 )
#
#             account_id = account_response.data
#             logger.info(f"Found account_id: {account_id} for u_id: {u_id}")
#
#         except Exception as e:
#             logger.error(f"Error fetching account_id from u_id: {str(e)}")
#             return GraphApiResponse(
#                 status_code=500,
#                 data=None,
#                 error=f"Failed to retrieve account information: {str(e)}"
#             )
#
#         # ================================================================
#         # Step 2: Fetch SMTP credentials for this account
#         # ================================================================
#         try:
#             creds_response = supabase.table('account_smtp_credentials')\
#                 .select('smtp_email, app_password, smtp_server, is_active, last_used, created_at, updated_at')\
#                 .eq('account_id', account_id)\
#                 .eq('is_active', True)\
#                 .execute()
#
#             if not creds_response.data or len(creds_response.data) == 0:
#                 logger.info(f"No SMTP credentials found for account {account_id}")
#                 return GraphApiResponse(
#                     status_code=404,
#                     data=None,
#                     error="No SMTP credentials found for this account"
#                 )
#
#             creds = creds_response.data[0]
#             logger.info(f"Found SMTP credentials for account {account_id}")
#
#             # ================================================================
#             # Step 3: Decrypt app_password and return actual values
#             # ================================================================
#             from app.services.encryption.smtp_encryption import SMTPEncryptionService
#
#             encryption_service = SMTPEncryptionService()
#
#             try:
#                 # Decrypt the app_password from database
#                 decrypted_password = encryption_service.decrypt_app_password(creds['app_password'])
#                 logger.info(f"✓ Successfully decrypted app_password for account {account_id}")
#             except Exception as e:
#                 logger.error(f"Failed to decrypt app_password: {e}")
#                 return GraphApiResponse(
#                     status_code=500,
#                     data=None,
#                     error=f"Failed to decrypt credentials: {str(e)}"
#                 )
#
#             return GraphApiResponse(
#                 status_code=200,
#                 data={
#                     "senderEmail": creds['smtp_email'],
#                     "smtpServer": creds['smtp_server'],
#                     "appPassword": decrypted_password,  # ← ACTUAL DECRYPTED VALUE
#                     "isActive": creds['is_active'],
#                     "lastUsed": creds.get('last_used'),
#                     "createdAt": creds['created_at'],
#                     "updatedAt": creds['updated_at']
#                 },
#                 error=None
#             )
#
#         except Exception as e:
#             logger.error(f"Error fetching SMTP credentials: {str(e)}")
#             import traceback
#             logger.error(f"Traceback: {traceback.format_exc()}")
#             return GraphApiResponse(
#                 status_code=500,
#                 data=None,
#                 error=f"Failed to fetch SMTP credentials: {str(e)}"
#             )
#
#     except Exception as e:
#         logger.error(f"Unexpected error in GetSMTPCredentials: {str(e)}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return GraphApiResponse(
#             status_code=500,
#             data=None,
#             error=f"Internal server error: {str(e)}"
#         )
#
#
# @router.post("/SaveSMTPCredentials", response_model=GraphApiResponse, summary="Save SMTP Credentials")
# async def save_smtp_credentials(
#     uuid: str,
#     senderEmail: str,
#     appPassword: str,
#     smtpServer: str
# ):
#     """
#     Save or update SMTP credentials for an account.
#
#     Query Parameters (from frontend):
#     - uuid: User UUID from auth.users
#     - senderEmail: SMTP sender email address (e.g., "pratik@inputiv.com")
#     - appPassword: App password for SMTP (will be encrypted)
#     - smtpServer: SMTP server hostname (e.g., "smtp-mail.outlook.com")
#
#
#     Response:
#
#     """
#     try:
#         logger.info(f"SaveSMTPCredentials called for user: {uuid}")
#
#         # ================================================================
#         # Step 1: Get account_id from UUID
#         # ================================================================
#         try:
#             account_response = supabase.rpc('get_account_id_from_uid', {'user_uid': uuid}).execute()
#
#             if not account_response.data:
#                 logger.warning(f"User not found for UUID: {uuid}")
#                 return GraphApiResponse(
#                     status_code=404,
#                     data={"success": False},
#                     error="User not found"
#                 )
#
#             account_id = account_response.data
#             logger.info(f"Found account_id: {account_id} for UUID: {uuid}")
#
#         except Exception as e:
#             logger.error(f"Error fetching account_id from UUID: {str(e)}")
#             return GraphApiResponse(
#                 status_code=500,
#                 data={"success": False},
#                 error=f"Failed to retrieve account information: {str(e)}"
#             )
#
#         # ================================================================
#         # Step 2: Validate SMTP data
#         # ================================================================
#         from app.services.encryption.smtp_encryption import SMTPEncryptionService
#
#         encryption_service = SMTPEncryptionService()
#
#         smtp_data = {
#             "smtp_email": senderEmail,
#             "app_password": appPassword,
#             "smtp_server": smtpServer
#         }
#
#         try:
#             encryption_service.validate_smtp_data(smtp_data)
#             logger.info(f"✓ SMTP data validation passed")
#         except ValueError as e:
#             logger.warning(f"SMTP data validation failed: {e}")
#             return GraphApiResponse(
#                 status_code=400,
#                 data={"success": False},
#                 error=f"Validation failed: {str(e)}"
#             )
#
#         # ================================================================
#         # Step 3: Encrypt app_password
#         # ================================================================
#         try:
#             encrypted_password = encryption_service.encrypt_app_password(appPassword)
#             logger.info(f"✓ Encrypted app_password (length: {len(encrypted_password)} chars)")
#         except Exception as e:
#             logger.error(f"Failed to encrypt app_password: {e}")
#             return GraphApiResponse(
#                 status_code=500,
#                 data={"success": False},
#                 error=f"Failed to encrypt credentials: {str(e)}"
#             )
#
#         # ================================================================
#         # Step 4: Check if credentials already exist (UPSERT logic)
#         # ================================================================
#         try:
#             existing_response = supabase.table('account_smtp_credentials')\
#                 .select('id')\
#                 .eq('account_id', account_id)\
#                 .execute()
#
#             if existing_response.data and len(existing_response.data) > 0:
#                 # UPDATE existing credentials
#                 credential_id = existing_response.data[0]['id']
#
#                 supabase.table('account_smtp_credentials')\
#                     .update({
#                         'smtp_email': senderEmail,
#                         'app_password': encrypted_password,
#                         'smtp_server': smtpServer,
#                         'is_active': True,
#                         'updated_at': datetime.now().isoformat()
#                     })\
#                     .eq('id', credential_id)\
#                     .execute()
#
#                 logger.info(f"✓ Updated SMTP credentials for account {account_id}, credential_id: {credential_id}")
#                 action = "updated"
#
#             else:
#                 # INSERT new credentials
#                 insert_result = supabase.table('account_smtp_credentials')\
#                     .insert({
#                         'account_id': account_id,
#                         'smtp_email': senderEmail,
#                         'app_password': encrypted_password,
#                         'smtp_server': smtpServer,
#                         'is_active': True,
#                         'created_at': datetime.now().isoformat(),
#                         'updated_at': datetime.now().isoformat()
#                     })\
#                     .execute()
#
#                 credential_id = insert_result.data[0]['id']
#                 logger.info(f"✓ Created new SMTP credentials for account {account_id}, credential_id: {credential_id}")
#                 action = "created"
#
#         except Exception as e:
#             logger.error(f"Error saving SMTP credentials: {str(e)}")
#             import traceback
#             logger.error(f"Traceback: {traceback.format_exc()}")
#             return GraphApiResponse(
#                 status_code=500,
#                 data={"success": False},
#                 error=f"Failed to save SMTP credentials: {str(e)}"
#             )
#
#         # ================================================================
#         # Step 5: Return success response (camelCase)
#         # ================================================================
#         logger.info(f"✓ SaveSMTPCredentials completed successfully for account {account_id}")
#
#         return GraphApiResponse(
#             status_code=200,
#             data={
#                 "success": True,
#                 "action": action,
#                 "senderEmail": senderEmail,
#                 "credentialId": credential_id
#             },
#             error=None
#         )
#
#     except Exception as e:
#         logger.error(f"Unexpected error in SaveSMTPCredentials: {str(e)}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return GraphApiResponse(
#             status_code=500,
#             data={"success": False},
#             error=f"Internal server error: {str(e)}"
#         )
