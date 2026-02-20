# report_endpoint.py

import logging
import os
import io
import base64
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Path, Depends, Query
from fastapi.responses import StreamingResponse
from typing import Optional, Dict, Any
from app.schemas.api import GraphApiResponse
from app.schemas.api import AccountAllocationRequest, SaveIntegrationCredentialsRequest
from dotenv import load_dotenv

load_dotenv()

# Import from the restructured app security reporting system
from app.services.integrations.orchestrator import SecurityAssessmentOrchestrator
from app.utils.frontend_transformer import FrontendTransformer

# Create router for report endpoints
router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/GetAvailableReportMonths", response_model=GraphApiResponse,
            summary="Get Available Report Months")
async def get_available_report_months():
    """
    Returns a list of the last 3 months available for report generation.
    Each month includes the key needed for API calls and human-readable information.

    Returns:
        GraphApiResponse: Contains list of available months with keys and date ranges
    """
    try:
        from app.utils.month_selector import MonthSelector

        month_selector = MonthSelector()
        available_months = month_selector.list_available_months()

        # Format response for API consumption
        months_list = []
        for month in available_months:
            month_key = f"{month['name'].lower()}_{month['year']}"  # "august_2025"
            months_list.append({
                "month_key": month_key,
                "display_name": month['display_name'],     # "August 2025"
                "month_name": month['name'],               # "August"
                "year": month['year'],                     # "2025"
                "month_number": month['month_number']      # "8"
            })

        logger.info(f"Retrieved {len(months_list)} available report months")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "available_months": months_list,
                "count": len(months_list),
                "usage_instructions": {
                    "description": "Use the 'month_key' field when calling the report generation endpoint",
                    "example": "GET /api/GenerateSecurityReportJSON/{user_id}/{org_id}?month=november_2024"
                }
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error retrieving available report months: {e}")
        return GraphApiResponse(
            status_code=500,
            data={
                "success": False,
                "available_months": []
            },
            error=f"Failed to retrieve available months: {str(e)}"
        )

# Add this new endpoint after the existing GenerateSecurityReport endpoint

def get_organization_name(org_id: int) -> str:
    """
    Helper function to fetch organization name from Supabase.

    Args:
        org_id: Organization ID from organizations table

    Returns:
        Organization name string, or "Unknown Organization" if not found
    """
    try:
        from app.core.database.supabase_services import supabase

        response = supabase.table('organizations')\
            .select('organization_name')\
            .eq('id', org_id)\
            .limit(1)\
            .execute()

        if response.data and len(response.data) > 0:
            return response.data[0]['organization_name']
        else:
            logger.warning(f"No organization found for org_id: {org_id}")
            return "Unknown Organization"

    except Exception as e:
        logger.error(f"Error fetching organization name for org_id {org_id}: {e}")
        return "Unknown Organization"


@router.get("/GenerateSecurityReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate Security Assessment Report JSON")
async def generate_security_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None,
                                     description="Report month in 'month_year' format (e.g., 'november_2024', 'december_2024'). If not provided, defaults to previous month.")
):
    """
    Generates a comprehensive security assessment report in JSON format for the specified organization and month.

    NEW STRUCTURE:
    - Uses user_id (UUID) to fetch account_id via Supabase function
    - Uses org_id to identify the organization
    - Supports month selection for historical reports

    Args:
        user_id: User UUID (auth_user_id) from platform_users table
        org_id: Organization ID (organizations.id)
        month: Optional month in 'month_year' format (e.g., 'november_2024'). Defaults to previous month.

    Returns:
        GraphApiResponse: Contains JSON data from frontend transformer

    Example Usage:
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id} (previous month - default)
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id}?month=november_2024
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id}?month=december_2024
    """
    try:
        logger.info(
            f"Generating security report JSON for user_id: {user_id}, org_id: {org_id}, month: {month or 'previous_month'}")

        # DEMO DATA FOR SPECIFIC USER
        demo_user_id = os.getenv("DEMO_USER_ID", "")
        if demo_user_id and user_id == demo_user_id:
            logger.info(f"Returning demo data from dummy.json for user_id: {user_id}")

            # Load demo data from dummy.json file
            dummy_json_path = os.path.join(os.path.dirname(__file__), 'dummy.json')

            try:
                import json
                with open(dummy_json_path, 'r', encoding='utf-8') as f:
                    demo_data = json.load(f)

                # Fetch organization name dynamically based on org_id
                organization_name = get_organization_name(org_id)
                logger.info(f"Fetched organization name: {organization_name} for org_id: {org_id}")

                # Replace placeholders in organization data with actual values
                if "organization" in demo_data:
                    demo_data["organization"]["id"] = str(org_id)
                    demo_data["organization"]["name"] = organization_name

                logger.info(f"Successfully loaded and customized demo data from {dummy_json_path}")

            except FileNotFoundError:
                logger.error(f"dummy.json file not found at {dummy_json_path}")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Demo data file not found"
                )
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in dummy.json: {e}")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error=f"Invalid demo data format: {str(e)}"
                )

            # Return the demo data loaded from dummy.json
            return GraphApiResponse(
                status_code=200,
                data=demo_data,
                error=None
            )



        # Step 1: Get account_id from user_id using Supabase RPC function
        try:
            from app.core.database.supabase_services import supabase

            # Call the Supabase RPC function to get account_id
            result = supabase.rpc('get_account_id_from_uid', {'user_uid': user_id}).execute()

            if not result.data:
                logger.error(f"No account found for user_id: {user_id}")
                return GraphApiResponse(
                    status_code=404,
                    data=None,
                    error=f"User not found or inactive: {user_id}"
                )

            account_id = result.data
            logger.info(f"Resolved user_id {user_id} to account_id: {account_id}")

        except Exception as e:
            logger.error(f"Error fetching account_id for user_id {user_id}: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to resolve user credentials: {str(e)}"
            )

        # Step 2: Get organization details and validate it belongs to the account
        try:
            # Get basic organization info
            org_response = supabase.table('organizations')\
                .select('id, account_id, organization_name, status')\
                .eq('id', org_id)\
                .eq('account_id', account_id)\
                .eq('status', 'Active')\
                .limit(1)\
                .execute()

            if not org_response.data or len(org_response.data) == 0:
                logger.error(f"Organization {org_id} not found or doesn't belong to account {account_id}")
                return GraphApiResponse(
                    status_code=403,
                    data=None,
                    error=f"Organization {org_id} not found or access denied"
                )

            organization = org_response.data[0]
            org_name = organization.get('organization_name')

            # Get platform IDs from organization_integrations table directly (avoid RPC overloading conflict)
            integrations_response = supabase.table('organization_integrations')\
                .select('organization_id, integration_id, integrations!inner(integration_key), platform_organization_id')\
                .eq('organization_id', org_id)\
                .execute()

            # Extract ninjaone_org_id from integrations
            ninjaone_org_id = None
            if integrations_response.data:
                for integration in integrations_response.data:
                    integration_key = integration.get('integrations', {}).get('integration_key')
                    if integration_key == 'ninjaone':
                        ninjaone_org_id = integration.get('platform_organization_id')
                        break

            logger.info(f"Validated organization: {org_name} (ninjaone_org_id: {ninjaone_org_id})")

        except Exception as e:
            logger.error(f"Error fetching organization {org_id}: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to fetch organization details: {str(e)}"
            )

        # Validate month format if provided (should be "november_2024" format)
        if month:
            try:
                from app.utils.month_selector import MonthSelector

                month_selector = MonthSelector()
                # This will validate the format and raise ValueError if invalid
                month_info = month_selector.get_month_by_name(month)
                logger.info(f"Using month: {month} -> {month_info.display_name}")

            except ValueError as e:
                # get_month_by_name raises ValueError with clear error message
                return GraphApiResponse(
                    status_code=400,
                    data=None,
                    error=str(e)
                )
            except Exception as e:
                logger.error(f"Error validating month: {e}")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error=f"Error validating month parameter: {str(e)}"
                )

        # Initialize security assessment orchestrator with NEW credential system (account_id + org_id)
        # No organization sync needed - we already validated org exists and belongs to account
        try:
            logger.info(f"Initializing SecurityAssessmentOrchestrator with account_id={account_id}, org_id={org_id}")
            orchestrator = SecurityAssessmentOrchestrator(account_id=account_id, org_id=org_id)
            logger.info("SecurityAssessmentOrchestrator initialized successfully")
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"Failed to initialize SecurityAssessmentOrchestrator: {e}")
            logger.error(f"Full traceback: {error_details}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to initialize security assessment system: {str(e)} | Details: {error_details[:500]}"
            )

        # Generate the security assessment data
        try:
            logger.info("Attempting to generate security assessment data...")

            # Use the NEW method: collect_all_data_with_org_id() with account_id and org_id
            security_data = await orchestrator.collect_all_data_with_org_id(
                month_name=month  # Pass selected month to orchestrator
            )

            if not security_data:
                logger.error("Security data generation returned empty result")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Security data generation failed - empty result"
                )

            logger.info(f"Security data generation completed successfully")

        except Exception as e:
            logger.error(f"Security data generation failed: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Security data generation failed: {str(e)}"
            )

        try:
            logger.info("Transforming data using FrontendTransformer...")

            # Convert month parameter to "November 2024" format for reporting_period
            reporting_period = None
            if month:
                try:
                    parts = month.split('_')
                    month_name = parts[0].capitalize()  # "november" -> "November"
                    year = parts[1]  # "2024"
                    reporting_period = f"{month_name} {year}"  # "November 2024"
                except:
                    pass  # If parsing fails, reporting_period will be None and use current month

            transformer = FrontendTransformer()
            frontend_json = transformer.transform_to_frontend_json(
                security_data,
                account_id=account_id,
                reporting_period=reporting_period
            )

            if not frontend_json:
                logger.error("Frontend transformation returned empty result")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Frontend transformation failed - empty result"
                )

            logger.info("Frontend transformation completed successfully")

        except Exception as e:
            logger.error(f"Frontend transformation failed: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Frontend transformation failed: {str(e)}"
            )
        # Get organization info for response
        logger.info(f"Successfully generated security report JSON for {org_name}")

        # Return the transformed JSON data
        return GraphApiResponse(
            status_code=200,
            data=frontend_json,  # Return the frontend JSON data directly
            error=None
        )

    except Exception as e:
        logger.error(f"Unexpected error generating security report JSON for user_id={user_id}, org_id={org_id}: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Internal server error: {str(e)}"
        )


@router.get("/GenerateSecurityReportJSONStream/{user_id}/{org_id}",
            summary="Generate Security Report JSON (Streaming)",
            description="Streams report data platform-by-platform as NDJSON to avoid 504 timeouts.")
async def generate_security_report_json_stream(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None,
                                     description="Report month in 'month_year' format (e.g., 'november_2024')")
):
    """
    Streaming version of GenerateSecurityReportJSON.
    Returns NDJSON (newline-delimited JSON) with each platform's data sent as it completes.
    Sends heartbeats every 10 seconds to keep the connection alive and prevent 504 timeouts.

    Each line is a JSON object with a 'type' field:
    - type: "organization"    → organization info (sent first)
    - type: "platform_data"   → a single platform's transformed data
    - type: "heartbeat"       → keep-alive signal (ignore for data)
    - type: "error"           → error for a specific platform
    - type: "complete"        → final signal with execution_info
    """
    import json

    async def stream_generator():
        try:
            # --- Step 1: Validate user_id → get account_id ---
            try:
                from app.core.database.supabase_services import supabase

                result = supabase.rpc('get_account_id_from_uid', {'user_uid': user_id}).execute()

                if not result.data:
                    yield json.dumps({"type": "error", "message": f"User not found: {user_id}", "progress": 0}) + "\n"
                    return

                account_id = result.data
                logger.info(f"[Stream] Resolved user_id {user_id} to account_id: {account_id}")

            except Exception as e:
                yield json.dumps({"type": "error", "message": f"Failed to resolve user: {str(e)}", "progress": 0}) + "\n"
                return

            # --- Step 2: Validate org_id belongs to account ---
            try:
                org_response = supabase.table('organizations')\
                    .select('id, account_id, organization_name, status')\
                    .eq('id', org_id)\
                    .eq('account_id', account_id)\
                    .eq('status', 'Active')\
                    .limit(1)\
                    .execute()

                if not org_response.data or len(org_response.data) == 0:
                    yield json.dumps({"type": "error", "message": f"Organization {org_id} not found or access denied", "progress": 0}) + "\n"
                    return

                org_name = org_response.data[0].get('organization_name')

            except Exception as e:
                yield json.dumps({"type": "error", "message": f"Failed to validate organization: {str(e)}", "progress": 0}) + "\n"
                return

            # --- Step 3: Validate month format ---
            if month:
                try:
                    from app.utils.month_selector import MonthSelector
                    month_selector = MonthSelector()
                    month_info = month_selector.get_month_by_name(month)
                except ValueError as e:
                    yield json.dumps({"type": "error", "message": str(e), "progress": 0}) + "\n"
                    return
                except Exception as e:
                    yield json.dumps({"type": "error", "message": f"Invalid month: {str(e)}", "progress": 0}) + "\n"
                    return

            # --- Step 4: Initialize orchestrator ---
            try:
                orchestrator = SecurityAssessmentOrchestrator(account_id=account_id, org_id=org_id)
                org_info = orchestrator._initialize_processors_with_org_id()
            except Exception as e:
                yield json.dumps({"type": "error", "message": f"Failed to initialize: {str(e)}", "progress": 0}) + "\n"
                return

            # --- Step 5: Send organization info immediately ---
            reporting_period = None
            if month:
                try:
                    parts = month.split('_')
                    month_name_str = parts[0].capitalize()
                    year_str = parts[1]
                    reporting_period = f"{month_name_str} {year_str}"
                except:
                    pass

            transformer = FrontendTransformer()
            execution_info_data = {
                "execution_info": {
                    "organization_id": str(org_id),
                    "organization_name": org_info['organization_name'],
                    "timestamp": datetime.now().isoformat(),
                    "data_sources": []
                }
            }

            org_data = transformer._extract_organization_info(execution_info_data, reporting_period, account_id)

            yield json.dumps({
                "type": "organization",
                "data": {"organization": org_data},
                "progress": 5
            }, default=str) + "\n"

            logger.info(f"[Stream] Sent organization info for {org_name}")

            # --- Step 6: Stream each platform's data ---
            autotask_company_id = org_info.get('autotask_company_id')
            start_time = datetime.now()
            data_sources = []

            async for chunk in orchestrator.stream_data_per_platform(
                company_id=autotask_company_id,
                month_name=month
            ):
                if chunk["type"] == "platform_data":
                    # Transform the raw platform data to frontend format
                    platform_name = chunk["platform"]
                    raw_data = chunk["data"]

                    try:
                        transformed = transformer.transform_single_platform(
                            platform_name, raw_data, account_id
                        )

                        if transformed:
                            yield json.dumps({
                                "type": "platform_data",
                                "platform": platform_name,
                                "data": transformed,
                                "progress": chunk["progress"]
                            }, default=str) + "\n"
                            logger.info(f"[Stream] Sent {platform_name} data")
                        else:
                            yield json.dumps({
                                "type": "error",
                                "platform": platform_name,
                                "message": f"{platform_name}: transformation returned empty data",
                                "progress": chunk["progress"]
                            }, default=str) + "\n"
                            logger.warning(f"[Stream] {platform_name} transform returned empty")

                    except Exception as e:
                        yield json.dumps({
                            "type": "error",
                            "platform": platform_name,
                            "message": f"{platform_name} transform failed: {str(e)}",
                            "progress": chunk["progress"]
                        }, default=str) + "\n"
                        logger.error(f"[Stream] {platform_name} transform error: {e}")

                elif chunk["type"] == "heartbeat":
                    yield json.dumps(chunk, default=str) + "\n"

                elif chunk["type"] == "error":
                    yield json.dumps(chunk, default=str) + "\n"

                elif chunk["type"] == "stream_done":
                    data_sources = chunk.get("data_sources", [])

            # --- Step 7: Send complete signal with execution_info ---
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            yield json.dumps({
                "type": "complete",
                "data": {
                    "execution_info": {
                        "generated_at": start_time.isoformat(),
                        "data_sources_processed": data_sources,
                        "report_type": "Monthly Customer Report",
                        "processing_time_seconds": round(duration, 2),
                        "next_update": (datetime.now() + timedelta(days=30)).isoformat()
                    }
                },
                "progress": 100
            }, default=str) + "\n"

            logger.info(f"[Stream] Report complete in {duration:.1f}s, platforms: {data_sources}")

        except Exception as e:
            logger.error(f"[Stream] Unexpected error: {e}")
            yield json.dumps({"type": "error", "message": f"Unexpected error: {str(e)}", "progress": 0}) + "\n"

    return StreamingResponse(
        stream_generator(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"  # Disable Nginx/proxy buffering
        }
    )


def filter_platform_data(frontend_json: Dict[str, Any], platform_name: str) -> Dict[str, Any]:
    """
    Filter frontend JSON to return only specific platform data.

    Args:
        frontend_json: Full frontend JSON with all platforms
        platform_name: Platform to extract (NinjaOne, Autotask, ConnectSecure)

    Returns:
        Filtered JSON with organization + single platform + execution_info
    """
    filtered = {
        "organization": frontend_json.get("organization", {}),
        "execution_info": frontend_json.get("execution_info", {})
    }

    if platform_name in frontend_json:
        filtered[platform_name] = frontend_json[platform_name]

    return filtered


@router.get("/GenerateNinjaOneReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate NinjaOne-Only Security Report JSON")
async def generate_ninjaone_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None, description="Report month name")
):
    """
    Generate security report JSON containing ONLY NinjaOne platform data.

    Returns structure: {"organization": {...}, "NinjaOne": {...}, "execution_info": {...}}
    Respects account_selected_charts filtering.
    """
    try:
        full_response = await generate_security_report_json_endpoint(user_id, org_id, month)

        if full_response.status_code != 200 or not full_response.data:
            return full_response

        filtered_data = filter_platform_data(full_response.data, "NinjaOne")

        return GraphApiResponse(
            status_code=200,
            data=filtered_data,
            error=None
        )
    except Exception as e:
        logger.error(f"Failed to generate NinjaOne report: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Failed to generate NinjaOne report: {str(e)}"
        )


@router.get("/GenerateAutotaskReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate Autotask-Only Security Report JSON")
async def generate_autotask_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None, description="Report month name")
):
    """
    Generate security report JSON containing ONLY Autotask platform data.

    Returns structure: {"organization": {...}, "Autotask": {...}, "execution_info": {...}}
    Respects account_selected_charts filtering.
    """
    try:
        full_response = await generate_security_report_json_endpoint(user_id, org_id, month)

        if full_response.status_code != 200 or not full_response.data:
            return full_response

        filtered_data = filter_platform_data(full_response.data, "Autotask")

        return GraphApiResponse(
            status_code=200,
            data=filtered_data,
            error=None
        )
    except Exception as e:
        logger.error(f"Failed to generate Autotask report: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Failed to generate Autotask report: {str(e)}"
        )


@router.get("/GenerateConnectSecureReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate ConnectSecure-Only Security Report JSON")
async def generate_connectsecure_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None, description="Report month name")
):
    """
    Generate security report JSON containing ONLY ConnectSecure platform data.

    Returns structure: {"organization": {...}, "ConnectSecure": {...}, "execution_info": {...}}
    Respects account_selected_charts filtering.
    """
    try:
        full_response = await generate_security_report_json_endpoint(user_id, org_id, month)

        if full_response.status_code != 200 or not full_response.data:
            return full_response

        filtered_data = filter_platform_data(full_response.data, "ConnectSecure")

        return GraphApiResponse(
            status_code=200,
            data=filtered_data,
            error=None
        )
    except Exception as e:
        logger.error(f"Failed to generate ConnectSecure report: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Failed to generate ConnectSecure report: {str(e)}"
        )


@router.get("/GenerateBitdefenderReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate Bitdefender-Only Security Report JSON")
async def generate_bitdefender_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None, description="Report month name")
):
    """
    Generate security report JSON containing ONLY Bitdefender platform data.

    Returns structure: {"organization": {...}, "Bitdefender": {...}, "execution_info": {...}}
    Respects account_selected_charts filtering.
    """
    try:
        full_response = await generate_security_report_json_endpoint(user_id, org_id, month)

        if full_response.status_code != 200 or not full_response.data:
            return full_response

        filtered_data = filter_platform_data(full_response.data, "Bitdefender")

        return GraphApiResponse(
            status_code=200,
            data=filtered_data,
            error=None
        )
    except Exception as e:
        logger.error(f"Failed to generate Bitdefender report: {e}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Failed to generate Bitdefender report: {str(e)}"
        )


@router.post("/AccountAllocation", response_model=GraphApiResponse,
             summary="Allocate New Account and Platform User")
async def account_allocation_endpoint(request: AccountAllocationRequest):
    """
    Creates a new account and platform user in the system.

    This endpoint calls the Supabase function `create_account_and_platform_user` to:
    1. Create a new account with the provided company name
    2. Create a platform user linked to the account and auth user
    3. Return the newly created account_id and platform_user_id

    Args:
        request: AccountAllocationRequest containing:
            - companyName: Company name for the new account (2-255 characters)
            - userId: User UUID (auth_user_id) from Supabase Auth
            - userEmail: User email address

    Returns:
        GraphApiResponse containing:
            - success: Boolean indicating success
            - account_id: Newly created account ID
            - platform_user_id: Newly created platform user ID
            - message: Success message

    Error Handling:
        - 400: Invalid request data (validation errors)
        - 409: User already exists (duplicate userId)
        - 500: Server error or database operation failed

    Example Request:
        POST /api/AccountAllocation
        {
            "companyName": "Acme Corp",
            "userId": "670fef07-80ea-45be-b1ab-5c51461218d2",
            "userEmail": "admin@acmecorp.com"
        }

    Example Response:
        {
            "status_code": 200,
            "data": {
                "success": true,
                "account_id": 123,
                "platform_user_id": 456,
                "message": "Account allocated successfully"
            },
            "error": null
        }
    """
    try:
        logger.info(f"Account allocation request received for company: {request.companyName}, user: {request.userId}")

        # Initialize Supabase client
        from app.core.database.supabase_services import supabase

        # Check if user already exists in platform_users table
        try:
            existing_user = supabase.table('platform_users')\
                .select('id, account_id')\
                .eq('auth_user_id', request.userId)\
                .limit(1)\
                .execute()

            if existing_user.data and len(existing_user.data) > 0:
                logger.warning(f"User already exists: {request.userId}")
                return GraphApiResponse(
                    status_code=409,
                    data={
                        "success": False,
                        "message": "This user already exists",
                        "existing_platform_user_id": existing_user.data[0]['id'],
                        "existing_account_id": existing_user.data[0]['account_id']
                    },
                    error="User with this userId already exists in the system"
                )
        except Exception as e:
            logger.error(f"Error checking existing user: {e}")
            # Continue with creation attempt even if check fails

        # Call the Supabase function to create account and platform user
        try:
            result = supabase.rpc(
                'create_account_and_platform_user',
                {
                    'p_company_name': request.companyName,
                    'p_user_id': request.userId,
                    'p_user_email': request.userEmail
                }
            ).execute()

            if not result.data:
                logger.error("Supabase function returned empty result")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Failed to create account: Database function returned empty result"
                )

            # Extract the returned IDs
            account_id = result.data.get('account_id')
            platform_user_id = result.data.get('platform_user_id')

            if not account_id or not platform_user_id:
                logger.error(f"Invalid response from database function: {result.data}")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Failed to create account: Invalid response from database"
                )

            logger.info(f"Account created successfully - account_id: {account_id}, platform_user_id: {platform_user_id}")

            return GraphApiResponse(
                status_code=200,
                data={
                    "success": True,
                    "account_id": account_id,
                    "platform_user_id": platform_user_id,
                    "message": "Account allocated successfully",
                    "company_name": request.companyName,
                    "user_email": request.userEmail
                },
                error=None
            )

        except Exception as e:
            error_message = str(e)
            logger.error(f"Error calling Supabase function: {error_message}")

            # Check for specific database errors
            if "duplicate key" in error_message.lower() or "already exists" in error_message.lower():
                return GraphApiResponse(
                    status_code=409,
                    data=None,
                    error="This user already exists in the system"
                )
            elif "foreign key" in error_message.lower():
                return GraphApiResponse(
                    status_code=400,
                    data=None,
                    error="Invalid user ID: User must exist in Supabase Auth"
                )
            else:
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error=f"Database operation failed: {error_message}"
                )

    except ValueError as ve:
        # Validation errors from Pydantic
        logger.error(f"Validation error: {ve}")
        return GraphApiResponse(
            status_code=400,
            data=None,
            error=f"Invalid request data: {str(ve)}"
        )

    except Exception as e:
        logger.error(f"Unexpected error in account allocation: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Internal server error: {str(e)}"
        )


@router.post("/SaveIntegrationCredentials", response_model=GraphApiResponse,
             summary="Save Integration Credentials and Sync Organizations")
async def save_integration_credentials_endpoint(request: SaveIntegrationCredentialsRequest):
    """
    Save encrypted integration credentials for NinjaOne, Autotask, and/or ConnectSecure platforms,
    test the credentials, fetch organizations, perform fuzzy matching, and save organization mappings.

    Workflow:
    1. Validate request and extract platform credentials
    2. Transform to encryption format and encrypt using EncryptionManager
    3. Save to integration_credentials table (or update if exists)
    4. Test each platform's credentials by attempting API calls
    5. Fetch organization lists from each platform
    6. Perform fuzzy matching to map organizations across platforms
    7. Save/update organization mappings to organizations table
    8. Return detailed response with mappings and confidence scores

    Args:
        request: SaveIntegrationCredentialsRequest containing:
            - companyId: Account ID (account_id in database)
            - companyName: Company name
            - userId: User UUID (auth_user_id)
            - platforms: List of platform configurations (at least one)

    Returns:
        GraphApiResponse containing:
            - success: Boolean indicating success
            - message: Success/error message
            - credential_id: ID of saved integration_credentials record
            - platforms_tested: List of successfully tested platforms
            - organizations_synced: Count of synced organizations
            - organization_mappings: List of mapped organizations with confidence scores

    Error Handling:
        - 400: Invalid request data
        - 403: Account access denied
        - 500: Encryption, database, or API errors

    Example Request:
        POST /api/SaveIntegrationCredentials
        {
            "companyId": 41,
            "companyName": "Crimson Retail",
            "userId": "201d1004-4d25-4466-9d10-1936afd62a78",
            "platforms": [
                {
                    "platform": "ninjaone",
                    "configuration": {
                        "ninjaone_client_id": "xxxx",
                        "ninjaone_client_secret": "yyyy",
                        "ninjaone_instance_url": "https://app.ninjarmm.com"
                    }
                },
                {
                    "platform": "autotask",
                    "configuration": {
                        "autotask_username": "user@example.com",
                        "autotask_secret": "secret",
                        "autotask_integration_code": "code"
                    }
                }
            ]
        }
    """
    try:
        logger.info(f"SaveIntegrationCredentials request received for account_id: {request.companyId}, "
                   f"platforms: {[p.platform for p in request.platforms]}")

        # Initialize Supabase client
        from app.core.database.supabase_services import supabase

        # Step 1: Validate account exists (simple validation)
        try:
            account_response = supabase.table('accounts')\
                .select('id')\
                .eq('id', request.companyId)\
                .limit(1)\
                .execute()

            if not account_response.data or len(account_response.data) == 0:
                logger.error(f"Account {request.companyId} not found")
                return GraphApiResponse(
                    status_code=403,
                    data=None,
                    error=f"Account {request.companyId} not found"
                )

            logger.info(f"Validated account ID: {request.companyId}")

        except Exception as e:
            logger.error(f"Error validating account: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to validate account: {str(e)}"
            )

        # Step 2: Transform payload to encryption format
        # Combine all platform configurations into single credentials dict
        combined_credentials = {}

        for platform_item in request.platforms:
            platform_name = platform_item.platform.lower()
            config = platform_item.configuration

            # Convert Pydantic model to dict if needed
            if hasattr(config, 'dict'):
                config_dict = config.dict(exclude_unset=True, exclude_none=True)
            else:
                config_dict = dict(config)

            # Merge into combined credentials
            combined_credentials.update(config_dict)

        logger.info(f"Combined credentials keys: {list(combined_credentials.keys())}")

        # Step 3: Encrypt credentials using EncryptionManager
        try:
            from app.services.encryption.manager import EncryptionManager

            encryption_manager = EncryptionManager()
            encrypted_blob = encryption_manager.encrypt_integration_credentials(combined_credentials)

            logger.info("Credentials encrypted successfully")

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to encrypt credentials: {str(e)}"
            )

        # Step 4: Save or update integration_credentials record
        try:
            # Check if credentials already exist for this account
            existing_creds = supabase.table('integration_credentials')\
                .select('id')\
                .eq('account_id', request.companyId)\
                .limit(1)\
                .execute()

            if existing_creds.data and len(existing_creds.data) > 0:
                # Update existing
                credential_id = existing_creds.data[0]['id']
                update_result = supabase.table('integration_credentials')\
                    .update({
                        'credentials': encrypted_blob,
                        'is_active': True,
                        'updated_at': datetime.now().isoformat()
                    })\
                    .eq('id', credential_id)\
                    .execute()

                logger.info(f"Updated existing credentials (ID: {credential_id})")

            else:
                # Insert new
                insert_result = supabase.table('integration_credentials')\
                    .insert({
                        'account_id': request.companyId,
                        'credentials': encrypted_blob,
                        'is_active': True,
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    })\
                    .execute()

                credential_id = insert_result.data[0]['id']
                logger.info(f"Inserted new credentials (ID: {credential_id})")

        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to save credentials to database: {str(e)}"
            )

        # Step 5: Test credentials and fetch organizations from each platform
        import asyncio
        import httpx

        platforms_tested = []
        platforms_failed = []
        ninjaone_orgs = []
        autotask_companies = []
        connectsecure_companies = []

        # Test each platform
        for platform_item in request.platforms:
            platform_name = platform_item.platform.lower()

            try:
                if platform_name == 'ninjaone':
                    # Test NinjaOne credentials
                    config = platform_item.configuration
                    if hasattr(config, 'dict'):
                        config_dict = config.dict(exclude_unset=True, exclude_none=True)
                    else:
                        config_dict = dict(config)

                    token_url = f"{config_dict.get('ninjaone_instance_url')}/oauth/token"

                    async with httpx.AsyncClient() as client:
                        token_response = await client.post(token_url, data={
                            'grant_type': 'client_credentials',
                            'client_id': config_dict.get('ninjaone_client_id'),
                            'client_secret': config_dict.get('ninjaone_client_secret'),
                            'scope': config_dict.get('ninjaone_scopes', 'monitoring management')
                        }, timeout=30.0)
                        token_response.raise_for_status()
                        token = token_response.json()['access_token']

                        # Fetch organizations
                        headers = {
                            'Authorization': f'Bearer {token}',
                            'Accept': 'application/json'
                        }
                        org_response = await client.get(
                            f"{config_dict.get('ninjaone_instance_url')}/v2/organizations",
                            headers=headers,
                            timeout=30.0
                        )
                        org_response.raise_for_status()
                        ninjaone_orgs = org_response.json()

                        platforms_tested.append('ninjaone')
                        logger.info(f"✓ NinjaOne tested successfully - {len(ninjaone_orgs)} organizations fetched")

                elif platform_name == 'autotask':
                    # Test Autotask credentials
                    config = platform_item.configuration
                    if hasattr(config, 'dict'):
                        config_dict = config.dict(exclude_unset=True, exclude_none=True)
                    else:
                        config_dict = dict(config)

                    # Get zone URL first
                    zone_info_url = f"https://webservices.autotask.net/atservicesrest/v1.0/zoneInformation?user={config_dict.get('autotask_username')}"

                    async with httpx.AsyncClient(timeout=30.0) as client:
                        zone_response = await client.get(zone_info_url)
                        zone_response.raise_for_status()
                        zone_data = zone_response.json()
                        zone_url = zone_data.get('url').rstrip('/') + '/'

                        # Fetch companies
                        headers = {
                            "UserName": config_dict.get('autotask_username'),
                            "Secret": config_dict.get('autotask_secret'),
                            "APIIntegrationcode": config_dict.get('autotask_integration_code'),
                            "Content-Type": "application/json"
                        }

                        query_data = {
                            "MaxRecords": 500,
                            "filter": [{"field": "isActive", "op": "eq", "value": True}]
                        }

                        company_response = await client.post(
                            f"{zone_url}v1.0/Companies/query",
                            headers=headers,
                            json=query_data,
                            timeout=30.0
                        )
                        company_response.raise_for_status()
                        company_data = company_response.json()
                        autotask_companies = company_data.get('items', [])

                        platforms_tested.append('autotask')
                        logger.info(f"✓ Autotask tested successfully - {len(autotask_companies)} companies fetched")

                elif platform_name == 'connectsecure':
                    # Test ConnectSecure credentials
                    config = platform_item.configuration
                    if hasattr(config, 'dict'):
                        config_dict = config.dict(exclude_unset=True, exclude_none=True)
                    else:
                        config_dict = dict(config)

                    auth_url = f"{config_dict.get('connectsecure_base_url')}/w/authorize"

                    headers = {
                        "Client-Auth-Token": base64.b64encode(
                            f"{config_dict.get('connectsecure_tenant_name')}+{config_dict.get('connectsecure_client_id')}:{config_dict.get('connectsecure_client_secret_b64')}".encode()
                        ).decode(),
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    }

                    async with httpx.AsyncClient() as client:
                        auth_response = await client.post(auth_url, headers=headers, timeout=30.0)
                        auth_response.raise_for_status()
                        token_data = auth_response.json()

                        access_token = token_data.get('access_token')
                        user_id = str(token_data.get('user_id'))

                        # Fetch companies
                        company_headers = {
                            'Authorization': f'Bearer {access_token}',
                            'X-User-ID': user_id,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }

                        company_response = await client.get(
                            f"{config_dict.get('connectsecure_base_url')}/r/company/companies",
                            headers=company_headers,
                            timeout=30.0
                        )
                        company_response.raise_for_status()
                        company_data = company_response.json()

                        # Handle different response formats
                        if isinstance(company_data, list):
                            connectsecure_companies = company_data
                        elif isinstance(company_data, dict) and 'data' in company_data:
                            connectsecure_companies = company_data['data']
                        elif isinstance(company_data, dict) and 'companies' in company_data:
                            connectsecure_companies = company_data['companies']
                        else:
                            connectsecure_companies = []

                        platforms_tested.append('connectsecure')
                        logger.info(f"✓ ConnectSecure tested successfully - {len(connectsecure_companies)} companies fetched")

            except Exception as e:
                logger.warning(f"⚠ {platform_name.title()} test failed: {e}")
                platforms_failed.append({
                    'platform': platform_name,
                    'error': str(e)
                })

        # Step 6: Perform fuzzy matching using OrganizationMatcher
        try:
            from app.services.organizations.matcher import OrganizationMatcher

            matcher = OrganizationMatcher()
            organization_mappings = matcher.match_organizations(
                ninjaone_orgs,
                autotask_companies,
                connectsecure_companies
            )

            logger.info(f"Created {len(organization_mappings)} organization mappings")

        except Exception as e:
            logger.error(f"Organization matching failed: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Organization matching failed: {str(e)}"
            )

        # Step 7: Save organization mappings to organizations table
        organizations_created = 0
        organizations_updated = 0
        organizations_failed = 0

        try:
            # Get integration IDs for mapping
            integrations_map = {}
            try:
                integrations_list = supabase.table('integrations')\
                    .select('id, integration_key')\
                    .execute()

                for integration in integrations_list.data:
                    integrations_map[integration['integration_key']] = integration['id']

                logger.info(f"Loaded integrations map: {integrations_map}")
            except Exception as e:
                logger.error(f"Failed to load integrations: {e}")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error=f"Failed to load platform integrations: {str(e)}"
                )

            for mapping in organization_mappings:
                try:
                    # Check if organization already exists by organization_name and account_id
                    existing_org = supabase.table('organizations') \
                        .select('id') \
                        .eq('account_id', request.companyId) \
                        .eq('organization_name', mapping['organization_name']) \
                        .limit(1) \
                        .execute()

                    org_data = {
                        'account_id': request.companyId,
                        'organization_name': mapping['organization_name'],
                        'status': 'Active',
                        'updated_at': datetime.now().isoformat()
                    }

                    org_id = None
                    if existing_org.data and len(existing_org.data) > 0:
                        # Update existing organization
                        org_id = existing_org.data[0]['id']
                        supabase.table('organizations')\
                            .update(org_data)\
                            .eq('id', org_id)\
                            .execute()
                        organizations_updated += 1
                        logger.info(f"Updated organization: {mapping['organization_name']} (ID: {org_id})")
                    else:
                        # Insert new organization
                        org_data['created_at'] = datetime.now().isoformat()
                        insert_result = supabase.table('organizations')\
                            .insert(org_data)\
                            .execute()
                        org_id = insert_result.data[0]['id']
                        organizations_created += 1
                        logger.info(f"Created new organization: {mapping['organization_name']} (ID: {org_id})")

                    # Now insert/update organization_integrations for each platform
                    platform_mappings = {
                        'ninjaone': mapping.get('ninjaone_org_id'),
                        'autotask': mapping.get('autotask_id'),
                        'connectsecure': mapping.get('connect_secure_id')
                    }

                    for platform_key, platform_org_id in platform_mappings.items():
                        if platform_org_id and platform_key in integrations_map:
                            integration_id = integrations_map[platform_key]

                            # Check if integration mapping exists
                            existing_integration = supabase.table('organization_integrations')\
                                .select('id')\
                                .eq('organization_id', org_id)\
                                .eq('integration_id', integration_id)\
                                .limit(1)\
                                .execute()

                            integration_data = {
                                'organization_id': org_id,
                                'integration_id': integration_id,
                                'platform_organization_id': str(platform_org_id),
                                'is_active': True,
                                'last_synced': datetime.now().isoformat(),
                                'updated_at': datetime.now().isoformat()
                            }

                            if existing_integration.data and len(existing_integration.data) > 0:
                                # Update existing integration mapping
                                supabase.table('organization_integrations')\
                                    .update(integration_data)\
                                    .eq('id', existing_integration.data[0]['id'])\
                                    .execute()
                                logger.debug(f"  Updated {platform_key} integration mapping")
                            else:
                                # Insert new integration mapping
                                integration_data['created_at'] = datetime.now().isoformat()
                                supabase.table('organization_integrations')\
                                    .insert(integration_data)\
                                    .execute()
                                logger.debug(f"  Created {platform_key} integration mapping")

                except Exception as e:
                    logger.error(f"Failed to save organization {mapping.get('organization_name')}: {e}")
                    logger.error(f"Error details: {str(e)}")
                    organizations_failed += 1

            logger.info(f"Organizations saved: {organizations_created} created, {organizations_updated} updated, {organizations_failed} failed")

        except Exception as e:
            logger.error(f"Failed to save organizations: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to save organization mappings: {str(e)}"
            )

        # Step 8: Build response
        response_data = {
            "success": True,
            "message": f"Integration credentials saved and {len(organization_mappings)} organizations synced",
            "credential_id": credential_id,
            "platforms_tested": platforms_tested,
            "platforms_failed": platforms_failed if platforms_failed else None,
            "organizations_summary": {
                "total_synced": len(organization_mappings),
                "created": organizations_created,
                "updated": organizations_updated,
                "failed": organizations_failed
            },
            "organization_mappings": [
                {
                    "organization_name": m['organization_name'],
                    "ninjaone_org_id": m['ninjaone_org_id'],
                    "autotask_id": m.get('autotask_id'),
                    "connect_secure_id": m.get('connect_secure_id'),
                    "match_confidence": m.get('match_confidence', 0.0),
                    "match_method": m.get('match_method', 'unknown')
                }
                for m in organization_mappings[:50]  # Limit to first 50 for response size
            ]
        }

        logger.info(f"✓ SaveIntegrationCredentials completed successfully for account {request.companyId}")

        return GraphApiResponse(
            status_code=200,
            data=response_data,
            error=None
        )

    except Exception as e:
        logger.error(f"Unexpected error in SaveIntegrationCredentials: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Internal server error: {str(e)}"
        )


@router.post("/SaveSecurityReport", response_model=GraphApiResponse, summary="Generate and Save Security Report")
async def save_security_report_endpoint(
        user_id: str,
        org_id: int,
        month: Optional[str] = None
):
    """
    Generate a security report and save it to the database.

    This endpoint:
    1. Calls the existing GenerateSecurityReportJSON endpoint to get the report data
    2. Extracts organization and platform data from the response
    3. Saves the report to generated_reports and report_platform_data tables

    Args:
        user_id: User UUID (auth_user_id) from platform_users table
        org_id: Organization ID
        month: Optional month in 'month_year' format (e.g., 'november_2024', 'december_2024'). Defaults to previous month.

    Returns:
        GraphApiResponse with report_id and saved platforms information

    Example Usage:
        POST /api/SaveSecurityReport
        Body: {
            "user_id": "uuid-here",
            "org_id": 41,
            "month": "december_2024"
        }
    """
    try:
        logger.info(f"SaveSecurityReport called for user_id: {user_id}, org_id: {org_id}, month: {month or 'previous_month'}")

        # Step 1: Call the existing GenerateSecurityReportJSON endpoint to get report data
        logger.info("Calling GenerateSecurityReportJSON endpoint to fetch report data")
        report_response = await generate_security_report_json_endpoint(
            user_id=user_id,
            org_id=org_id,
            month=month
        )

        # Check if report generation was successful
        if report_response.status_code != 200 or not report_response.data:
            logger.error(f"Failed to generate report: status={report_response.status_code}, error={report_response.error}")
            return GraphApiResponse(
                status_code=report_response.status_code,
                data=None,
                error=f"Failed to generate report: {report_response.error}"
            )

        json_response = report_response.data
        logger.info("Successfully fetched report JSON from GenerateSecurityReportJSON")

        # Step 2: Initialize Supabase client
        from app.core.database.supabase_services import supabase

        # Step 3: Parse month from month_year format (e.g., "november_2024")
        organization_data = json_response.get("organization", {})

        # Parse month parameter if provided, otherwise use reporting_period fallback
        if month and '_' in month:
            # Parse "november_2024" format
            parts = month.split('_')
            month_name_lowercase = parts[0].lower()
            report_year = int(parts[1])

            # Capitalize first letter for database storage: "November"
            report_month = month_name_lowercase.capitalize()

            logger.info(f"Parsed month parameter '{month}' -> report_month: {report_month}, report_year: {report_year}")
        else:
            # Fallback: Extract from reporting_period in organization data (legacy)
            reporting_period = organization_data.get("reporting_period", "")

            if reporting_period:
                parts = reporting_period.split()
                report_month = parts[0] if len(parts) > 0 else "Unknown"
                report_year = int(parts[1]) if len(parts) > 1 else datetime.now().year
            else:
                report_month = "Unknown"
                report_year = datetime.now().year

            logger.info(f"Extracted from reporting_period: {report_month}, {report_year}")

        # Step 4: Check if report already exists for this org_id, month, and year
        logger.info(f"Checking if report already exists for org_id={org_id}, month={report_month}, year={report_year}")

        existing_report_response = supabase.table('generated_reports')\
            .select('id')\
            .eq('organization_id', org_id)\
            .eq('report_month', report_month)\
            .eq('report_year', report_year)\
            .execute()

        execution_info = json_response.get("execution_info", {})

        report_insert_data = {
            "organization_id": org_id,
            "report_month": report_month,
            "report_year": report_year,
            "organization_data": organization_data,
            "execution_info": execution_info,
            "status": "completed",
            "generated_at": datetime.now().isoformat()
        }

        # If report exists, update it; otherwise, insert new one
        if existing_report_response.data and len(existing_report_response.data) > 0:
            existing_report_id = existing_report_response.data[0]['id']
            logger.info(f"Report already exists with ID: {existing_report_id}. Updating existing report.")

            # Update existing report
            report_update_response = supabase.table('generated_reports')\
                .update(report_insert_data)\
                .eq('id', existing_report_id)\
                .execute()

            if not report_update_response.data or len(report_update_response.data) == 0:
                logger.error("Failed to update existing report in generated_reports table")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Failed to update existing report in database"
                )

            report_id = existing_report_id
            logger.info(f"Successfully updated report with ID: {report_id}")

            # Delete old platform data for this report before inserting new data
            logger.info(f"Deleting old platform data for report_id={report_id}")
            supabase.table('report_platform_data')\
                .delete()\
                .eq('report_id', report_id)\
                .execute()

        else:
            logger.info("No existing report found. Inserting new report.")

            # Insert new report
            report_insert_response = supabase.table('generated_reports').insert(report_insert_data).execute()

            if not report_insert_response.data or len(report_insert_response.data) == 0:
                logger.error("Failed to insert report into generated_reports table")
                return GraphApiResponse(
                    status_code=500,
                    data=None,
                    error="Failed to save report to database"
                )

            report_id = report_insert_response.data[0]['id']
            logger.info(f"Successfully inserted new report with ID: {report_id}")

        # Step 5: Query integrations table to get platform mapping
        logger.info("Querying integrations table for platform mapping")
        integrations_response = supabase.table('integrations')\
            .select('id, json_object_name')\
            .eq('is_active', True)\
            .execute()

        if not integrations_response.data:
            logger.warning("No active integrations found in database")
            integration_mapping = {}
        else:
            # Create mapping: json_object_name -> integration_id
            integration_mapping = {
                row['json_object_name']: row['id']
                for row in integrations_response.data
            }
            logger.info(f"Created integration mapping for {len(integration_mapping)} platforms")

        # Step 6: Loop through JSON response and insert platform data
        platforms_saved = []
        platforms_skipped = []

        for key, value in json_response.items():
            # Skip non-platform keys
            if key in ["organization", "execution_info"]:
                continue

            # Get integration_id for this platform
            integration_id = integration_mapping.get(key)

            if integration_id:
                logger.info(f"Saving platform data for: {key} (integration_id: {integration_id})")

                try:
                    # Insert into report_platform_data table
                    platform_insert_data = {
                        "report_id": report_id,
                        "integration_id": integration_id,
                        "platform_data": value,
                        "created_at": datetime.now().isoformat()
                    }

                    platform_insert_response = supabase.table('report_platform_data').insert(platform_insert_data).execute()

                    if platform_insert_response.data:
                        platforms_saved.append(key)
                        logger.info(f"Successfully saved platform data for: {key}")
                    else:
                        logger.warning(f"Failed to save platform data for: {key}")
                        platforms_skipped.append(key)

                except Exception as e:
                    logger.error(f"Error saving platform data for {key}: {e}")
                    platforms_skipped.append(key)
            else:
                logger.warning(f"Platform '{key}' not found in integrations table. Skipping.")
                platforms_skipped.append(key)

        # Step 7: Return success response
        response_data = {
            "success": True,
            "report_id": report_id,
            "organization_id": org_id,
            "report_month": report_month,
            "report_year": report_year,
            "platforms_saved": platforms_saved,
            "platforms_skipped": platforms_skipped,
            "total_platforms": len(platforms_saved),
            "pdf_url": None
        }

        logger.info(f"SaveSecurityReport completed successfully. Report ID: {report_id}, Platforms saved: {len(platforms_saved)}")

        return GraphApiResponse(
            status_code=200,
            data=response_data,
            error=None
        )

    except Exception as e:
        logger.error(f"Unexpected error in SaveSecurityReport: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Internal server error: {str(e)}"
        )


@router.get("/GetSavedSecurityReport", response_model=GraphApiResponse, summary="Get Saved Security Report")
async def get_saved_security_report_endpoint(
        org_id: int = Query(..., description="Organization ID"),
        month: str = Query(..., description="Report month in 'month_year' format (e.g., 'november_2024')")
):
    """
    Retrieve a previously saved security report from the database.

    This endpoint:
    1. Parses the month_year parameter into month and year
    2. Queries generated_reports table by org_id, month, and year
    3. Fetches all platform data from report_platform_data table
    4. Reconstructs the JSON response in the same format as /GenerateSecurityReportJSON

    Args:
        org_id: Organization ID
        month: Month in 'month_year' format (e.g., 'november_2024', 'december_2024')

    Returns:
        GraphApiResponse with the same JSON structure as GenerateSecurityReportJSON

    Example Usage:
        GET /api/GetSavedSecurityReport?org_id=41&month=november_2024
    """
    try:
        logger.info(f"GetSavedSecurityReport called for org_id: {org_id}, month: {month}")

        # Step 1: Parse month_year format
        if '_' not in month:
            return GraphApiResponse(
                status_code=400,
                data=None,
                error=f"Invalid month format: '{month}'. Expected format: 'monthlowercase_year' (e.g., 'november_2024')"
            )

        parts = month.split('_')
        if len(parts) != 2:
            return GraphApiResponse(
                status_code=400,
                data=None,
                error=f"Invalid month format: '{month}'. Expected format: 'monthlowercase_year'"
            )

        month_name_lowercase = parts[0].lower()
        year_str = parts[1]

        # Validate year
        if not year_str.isdigit() or len(year_str) != 4:
            return GraphApiResponse(
                status_code=400,
                data=None,
                error=f"Invalid year: '{year_str}'. Year must be a 4-digit number."
            )

        report_year = int(year_str)
        # Capitalize month for database query
        report_month = month_name_lowercase.capitalize()

        logger.info(f"Parsed month: {report_month}, year: {report_year}")

        # Step 2: Initialize Supabase client
        from app.core.database.supabase_services import supabase

        # Step 3: Query generated_reports table
        logger.info(f"Querying generated_reports for org_id={org_id}, month={report_month}, year={report_year}")
        report_response = supabase.table('generated_reports')\
            .select('id, organization_data, execution_info, report_month, report_year, pdf_file_url, generated_at')\
            .eq('organization_id', org_id)\
            .eq('report_month', report_month)\
            .eq('report_year', report_year)\
            .order('generated_at', desc=True)\
            .limit(1)\
            .execute()

        if not report_response.data or len(report_response.data) == 0:
            logger.warning(f"No saved report found for org_id={org_id}, month={report_month}, year={report_year}")
            return GraphApiResponse(
                status_code=404,
                data=None,
                error=f"No saved report found for organization {org_id} in {report_month} {report_year}"
            )

        report = report_response.data[0]
        report_id = report['id']

        logger.info(f"Found report with ID: {report_id}")

        # Step 4: Query report_platform_data table for all platform data
        logger.info(f"Fetching platform data for report_id={report_id}")
        platform_response = supabase.table('report_platform_data')\
            .select('integration_id, platform_data')\
            .eq('report_id', report_id)\
            .execute()

        # Step 5: Query integrations table to map integration_id -> json_object_name
        integrations_response = supabase.table('integrations')\
            .select('id, json_object_name')\
            .execute()

        # Create reverse mapping: integration_id -> json_object_name
        integration_id_to_name = {
            row['id']: row['json_object_name']
            for row in integrations_response.data
        }

        # Step 6: Reconstruct the JSON response
        reconstructed_json = {
            "organization": report['organization_data'],
            "execution_info": report['execution_info']
        }

        # Add platform data using json_object_name as keys
        for platform in platform_response.data:
            integration_id = platform['integration_id']
            platform_name = integration_id_to_name.get(integration_id)

            if platform_name:
                reconstructed_json[platform_name] = platform['platform_data']
                logger.info(f"Added platform data for: {platform_name}")
            else:
                logger.warning(f"No integration name found for integration_id: {integration_id}")

        logger.info(f"Successfully reconstructed report with {len(platform_response.data)} platforms")

        # Step 7: Return the reconstructed JSON
        return GraphApiResponse(
            status_code=200,
            data=reconstructed_json,
            error=None
        )

    except Exception as e:
        logger.error(f"Unexpected error in GetSavedSecurityReport: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return GraphApiResponse(
            status_code=500,
            data=None,
            error=f"Internal server error: {str(e)}"
        )