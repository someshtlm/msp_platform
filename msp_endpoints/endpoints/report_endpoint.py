# report_endpoint.py

import logging
import sys
import os
import io
import base64
from fastapi import APIRouter, HTTPException, Path, Depends, Query
from fastapi.responses import StreamingResponse
from typing import Optional
from models import GraphApiResponse
from schemas import AccountAllocationRequest

# Add msp_platform root to Python path so we can import security_reporting_system as a package
msp_platform_root = os.path.join(os.path.dirname(__file__), '..', '..')
if msp_platform_root not in sys.path:
    sys.path.insert(0, msp_platform_root)

# === ADD DEBUG CODE RIGHT HERE ===
print("=== DEBUG: Python Path ===")
for path in sys.path:
    print(f"  {path}")
print("=== DEBUG: Current Directory ===")
print(f"  {os.getcwd()}")
print("=== DEBUG: File Location ===")
print(f"  {__file__}")

# Check if security_reporting_system exists
security_system_path = os.path.join(msp_platform_root, 'security_reporting_system')
print(f"=== DEBUG: Security System Path ===")
print(f"  {security_system_path}")
print(f"  Exists: {os.path.exists(security_system_path)}")

if os.path.exists(security_system_path):
    print("=== DEBUG: Security System Contents ===")
    for item in os.listdir(security_system_path):
        item_path = os.path.join(security_system_path, item)
        print(f"  {item} - is_dir: {os.path.isdir(item_path)}")

    # Check config location specifically
    config_path = os.path.join(security_system_path, 'config')
    print(f"=== DEBUG: Config Path ===")
    print(f"  {config_path}")
    print(f"  Exists: {os.path.exists(config_path)}")
    if os.path.exists(config_path):
        print("  Config contents:")
        for item in os.listdir(config_path):
            print(f"    {item}")

# Try to import and see what fails
print("=== DEBUG: Attempting Import ===")
try:
    from security_reporting_system.src.main import SecurityAssessmentOrchestrator

    print("✅ SecurityAssessmentOrchestrator imported successfully")
except ImportError as e:
    print(f"❌ Failed to import SecurityAssessmentOrchestrator: {e}")
    import traceback

    traceback.print_exc()

    # Try to import step by step to find exactly where it fails
    print("=== DEBUG: Step-by-step Import Test ===")
    try:
        import security_reporting_system

        print("✅ security_reporting_system package imported")
    except ImportError as e:
        print(f"❌ security_reporting_system package: {e}")

    try:
        from security_reporting_system import src

        print("✅ security_reporting_system.src imported")
    except ImportError as e:
        print(f"❌ security_reporting_system.src: {e}")

    try:
        from security_reporting_system.src import main

        print("✅ security_reporting_system.src.main imported")
    except ImportError as e:
        print(f"❌ security_reporting_system.src.main: {e}")
# === END DEBUG CODE ===

# Add msp_platform root to Python path so we can import security_reporting_system as a package
msp_platform_root = os.path.join(os.path.dirname(__file__), '..', '..')
if msp_platform_root not in sys.path:
    sys.path.insert(0, msp_platform_root)

# Import from the restructured security reporting system
from security_reporting_system.src.main import SecurityAssessmentOrchestrator
# === ADD MORE DEBUGGING ===
import security_reporting_system.src.main as main_module
print("=== DEBUG: SecurityAssessmentOrchestrator methods ===")
print([method for method in dir(SecurityAssessmentOrchestrator) if not method.startswith('_')])

# Check what's in the main module
print("=== DEBUG: Main module imports ===")
import inspect
for name, obj in inspect.getmembers(main_module):
    if inspect.ismodule(obj):
        print(f"  {name}: {obj}")
# === END DEBUGGING ===


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
        # Import month selector from security_reporting_system
        from security_reporting_system.src.utils.month_selector import MonthSelector

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
                    "description": "Use the 'month_name' field when calling the report generation endpoint",
                    "example": "GET /api/GenerateSecurityReport/41?month=August"
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





# Add this import at the top with the other imports
from security_reporting_system.src.utils.frontend_transformer import FrontendTransformer


# Add this new endpoint after the existing GenerateSecurityReport endpoint

@router.get("/GenerateSecurityReportJSON/{user_id}/{org_id}", response_model=GraphApiResponse,
            summary="Generate Security Assessment Report JSON")
async def generate_security_report_json_endpoint(
        user_id: str = Path(..., description="User UUID (auth_user_id) from frontend"),
        org_id: int = Path(..., description="Organization ID"),
        month: Optional[str] = Query(None,
                                     description="Report month name (e.g., 'August', 'July', 'June'). If not provided, defaults to previous month.")
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
        month: Optional month name (August, July, June). Defaults to previous month.

    Returns:
        GraphApiResponse: Contains JSON data from frontend transformer

    Example Usage:
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id} (previous month - default)
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id}?month=August (August 2025)
        - GET /api/GenerateSecurityReportJSON/{uuid}/{org_id}?month=July (July 2025)
    """
    try:
        logger.info(
            f"Generating security report JSON for user_id: {user_id}, org_id: {org_id}, month: {month or 'previous_month'}")

        # HARDCODED DEMO DATA FOR SPECIFIC USER
        if user_id == "201d1004-4d25-4466-9d10-1936afd62a78":
            logger.info(f"Returning hardcoded demo data for user_id: {user_id}")
            demo_data = {
                "organization": {
                    "id": "41",
                    "name": "Crimson Retail",
                    "report_date": "2025-10-09T19:05:15.407535",
                    "created_by": "Security Reporting System",
                    "company": "Innovate Tech Partners",
                    "reporting_period": "October 2025"
                },
                "summary": {
                    "total_devices": 82,
                    "online_devices": 42,
                    "offline_devices": 40,
                    "total_assets": 6,
                    "online_assets": 1,
                    "offline_assets": 5,
                    "total_tickets": 128,
                    "completed_tickets": 109,
                    "total_patches": 687,
                    "patch_compliance_percentage": 73.8,
                    "security_risk_score": 12.24,
                    "risk_level": "Low",
                    "total_vulnerabilities": 580,
                    "data_sources": [
                        "NinjaOne",
                        "Autotask",
                        "ConnectSecure"
                    ]
                },
                "charts": {
                    "daily_tickets_trend": {
                        "created": [1, 14, 3, 8, 5, 0, 1, 7, 7, 12, 2, 3, 0, 0, 9, 7, 4, 0, 5, 0, 0, 4, 6, 9, 2, 4, 1, 1, 7, 6],
                        "completed": [0, 10, 7, 5, 4, 0, 0, 4, 8, 11, 10, 2, 0, 0, 6, 7, 4, 1, 5, 0, 0, 1, 4, 1, 1, 8, 1, 0, 3, 6],
                        "days": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
                    },
                    "monthly_tickets_by_type": {
                        "workstation": 19,
                        "email": 15,
                        "user_access": 18,
                        "application_software": 16,
                        "server": 1,
                        "network_internet": 5,
                        "printer_scanner": 2,
                        "shared_drive": 5,
                        "cybersecurity": 3,
                        "other": 14
                    },
                    "open_ticket_priority_distribution": {
                        "critical": 0,
                        "high": 0,
                        "medium": 14,
                        "low": 0
                    },
                    "sla_performance": {
                        "first_response_percentage": 98.1,
                        "resolution_percentage": 71.9
                    },
                    "patch_management_enablement": {
                        "enabled": 81,
                        "disabled": 1
                    },
                    "patch_status_distribution": {
                        "installed": 651,
                        "approved": 36,
                        "failed": 0,
                        "pending": 0
                    },
                    "device_os_distribution": {
                        "windows_workstations": 81,
                        "windows_servers": 1
                    },
                    "asset_status": {
                        "online": 31,
                        "offline": 0
                    },
                    "asset_type_distribution": {
                        "discovered": 6,
                        "other_asset": 25,
                        "unknown": 0
                    },
                    "operating_system_distribution": {
                        "Unknown": 2,
                        "Windows": 1,
                        "Windows 11": 3
                    },
                    "vulnerability_severity": {
                        "critical": 19,
                        "high": 361,
                        "medium": 190,
                        "low": 10,
                        "total": 580
                    },
                    "agent_type_distribution": {
                        "total_agents": 82,
                        "breakdown": [
                            {
                                "agent_type": "LIGHTWEIGHT",
                                "count": 81,
                                "percentage": 98.8
                            },
                            {
                                "agent_type": "PROBE",
                                "count": 1,
                                "percentage": 1.2
                            }
                        ]
                    },
                    "open_tickets_by_issue_type": [
                        {
                            "issue_type": "Email",
                            "total_count": 3,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "SPAM",
                                    "count": 1
                                },
                                {
                                    "sub_issue_type": "Email Delivery Failure",
                                    "count": 2
                                }
                            ]
                        },
                        {
                            "issue_type": "Network/Internet",
                            "total_count": 2,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "Network Performance",
                                    "count": 2
                                }
                            ]
                        },
                        {
                            "issue_type": "Phone",
                            "total_count": 2,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "VoIP Not Working",
                                    "count": 1
                                },
                                {
                                    "sub_issue_type": "Call Quality Issues",
                                    "count": 1
                                }
                            ]
                        },
                        {
                            "issue_type": "Printer/Scanner/Copier",
                            "total_count": 2,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "Print Error",
                                    "count": 1
                                },
                                {
                                    "sub_issue_type": "Scanner Not Detected",
                                    "count": 1
                                }
                            ]
                        },
                        {
                            "issue_type": "Shared Drive",
                            "total_count": 2,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "Shared Drive Access/Permissions",
                                    "count": 1
                                },
                                {
                                    "sub_issue_type": "File Synchronization Issue",
                                    "count": 1
                                }
                            ]
                        },
                        {
                            "issue_type": "User Access and Management",
                            "total_count": 2,
                            "sub_issues": [
                                {
                                    "sub_issue_type": "Employee Termination",
                                    "count": 1
                                },
                                {
                                    "sub_issue_type": "Password Reset Request",
                                    "count": 1
                                }
                            ]
    },
    {
        "issue_type": "Workstation (Laptop/Desktop)",
        "total_count": 1,
        "sub_issues": [
            {
                "sub_issue_type": "Other Peripheral Device",
                "count": 1
            }
        ]
    }
]

                },
                "tickets_by_contact": [
                    {
                        "name": "John Smith",
                        "tickets": 42
                    },
                    {
                        "name": "Automation",
                        "tickets": 24
                    },
                    {
                        "name": "Other",
                        "tickets": 24
                    },
                    {
                        "name": "Care life",
                        "tickets": 11
                    },
                    {
                        "name": "Luka Wood",
                        "tickets": 8
                    },
                    {
                        "name": "Jonh doe",
                        "tickets": 3
                    },
                    {
                        "name": "Richard Elles",
                        "tickets": 3
                    },
                    {
                        "name": "Evans",
                        "tickets": 2
                    },
                    {
                        "name": "Joe Francis",
                        "tickets": 2
                    },
                    {
                        "name": "Cam Gordon",
                        "tickets": 2
                    },
                    {
                        "name": "Robert Liboon",
                        "tickets": 2
                    },
                    {
                        "name": "Chris Morris",
                        "tickets": 2
                    },
                    {
                        "name": "Arya Dane",
                        "tickets": 2
                    }
                ],
                "tickets_by_contact_summary": {
                    "contacts_summary": {
                        "contacts_count": 33,
                        "total_tickets": 127,
                        "top_contact": "John Smith"
                    }
                },
                "patch_management": {
                    "os_patches": {
                        "summary": {
                            "total": 651,
                            "successful": 651,
                            "failed": 0,
                            "success_rate": 100.0
                        },
                        "failed_devices": []
                    },
                    "third_party_patches": {
                        "summary": {
                            "total": 360,
                            "successful": 360,
                            "failed": 0,
                            "success_rate": 100.0
                        },
                        "failed_devices": []
                    }
                },
                "devices_with_failed_patches": {
                    "count": 0,
                    "devices": [],
                    "message": "No devices with failed patches"
                },
                "last_scan_info": {
                    "last_successful_scan": "2025-10-09T00:32:40",
                    "scan_status": "completed"
                },
                "tables": {
                    "device_inventory": [
                        {
                            "device": "CR036",
                            "lastLoggedInUser": "emily",
                            "manufacturer": "Dell Inc.",
                            "model": "Latitude 5520",
                            "os": "Windows 11 Professional Edition",
                            "ram": "31.7GB",
                            "cpu": "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz",
                            "total_storage": "474.1GB",
                            "free_storage": "315.9GB",
                            "age": "2.2 years",
                            "age_category": "<4 years",
                            "location": "SOLA"
                        },
                        {
                            "device": "CR038",
                            "lastLoggedInUser": "john",
                            "manufacturer": "Dell Inc.",
                            "model": "Latitude 5320",
                            "os": "Windows 11 Professional Edition",
                            "ram": "15.8GB",
                            "cpu": "11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz",
                            "total_storage": "235.8GB",
                            "free_storage": "35.7GB",
                            "age": "2.2 years",
                            "age_category": "<4 years",
                            "location": "Capetown"
                        },
                        {
                            "device": "CR106",
                            "lastLoggedInUser": "jane",
                            "manufacturer": "Alienware",
                            "model": "Alienware x17 R2",
                            "os": "Windows 11 Professional Edition",
                            "ram": "31.7GB",
                            "cpu": "12th Gen Intel(R) Core(TM) i9-12900HK",
                            "total_storage": "1905.7GB",
                            "free_storage": "967.1GB",
                            "age": "1.5 years",
                            "age_category": "<4 years",
                            "location": "Texas"
                        },
                        {
                            "device": "CR76976",
                            "lastLoggedInUser": "alen",
                            "manufacturer": "Dell Inc.",
                            "model": "Latitude 3550",
                            "os": "Windows 11 Professional Edition",
                            "ram": "31.7GB",
                            "cpu": "13th Gen Intel(R) Core(TM) i7-1355U",
                            "total_storage": "473.8GB",
                            "free_storage": "320.0GB",
                            "age": "1.3 years",
                            "age_category": "<4 years",
                            "location": "Capetown"
                        }
                    ],
                    "device_inventory_server": [
                        {
                            "device": "CR-7",
                            "lastLoggedInUser": "network",
                            "manufacturer": "Microsoft Corporation",
                            "model": "Virtual Machine",
                            "os": "Windows Server 2016 Standard Edition",
                            "ram": "11.6GB",
                            "cpu": "Intel(R) Xeon(R) Silver 4114 CPU @ 2.20GHz",
                            "total_storage": "4523.3GB",
                            "free_storage": "1087.7GB",
                            "age": "2.2 years",
                            "age_category": "<4 years",
                            "location": "Wall street"
                        }
                    ]
                },
                "metrics": {
                    "patch_compliance": {
                        "success_rate": 73.8,
                        "total_patches": 687,
                        "installed": 651,
                        "failed": 0,
                        "pending": 0
                    },
                    "security_metrics": {
                        "risk_score": 12.24,
                        "risk_level": "Low",
                        "total_vulnerabilities": 580,
                        "critical_vulnerabilities": 19,
                        "high_vulnerabilities": 361,
                        "medium_vulnerabilities": 186,
                        "low_vulnerabilities": 14
                    },
                    "infrastructure_health": {
                        "total_assets": 6,
                        "online_percentage": 51.2,
                        "offline_percentage": 48.8,
                        "patch_enablement_percentage": 98.8
                    },
                    "support_metrics": {
                        "total_tickets_month": 128,
                        "completed_tickets": 109,
                        "open_tickets": 24,
                        "sla_first_response": 94.1,
                        "sla_resolution": 76.9
                    }
                },
                "alerts": [
                    {
                        "type": "critical",
                        "message": "580 total vulnerabilities detected",
                        "critical_count": 19,
                        "action_required": "Review vulnerability assessment"
                    }
                ],
                "execution_info": {
                    "generated_at": "2025-10-09T19:05:15.407535",
                    "data_sources_processed": [
                        "NinjaOne",
                        "Autotask",
                        "ConnectSecure"
                    ],
                    "report_type": "Monthly Customer Report",
                    "processing_time_seconds": 60.8,
                    "next_update": "2025-11-08T19:05:51.260348"
                }
            }

            return GraphApiResponse(
                status_code=200,
                data=demo_data,
                error=None
            )

        # Step 1: Get account_id from user_id using Supabase RPC function
        try:
            from supabase import create_client
            import os

            supabase_url = os.getenv("SUPABASE_URL")
            supabase_key = os.getenv("SUPABASE_KEY")
            supabase = create_client(supabase_url, supabase_key)

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
            org_response = supabase.table('organizations')\
                .select('id, account_id, organization_name, ninjaone_org_id, autotask_id, connect_secure_id, status')\
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
            ninjaone_org_id = organization.get('ninjaone_org_id')
            org_name = organization.get('organization_name')

            logger.info(f"Validated organization: {org_name} (ninjaone_org_id: {ninjaone_org_id})")

            if not ninjaone_org_id:
                logger.error(f"Organization {org_id} has no ninjaone_org_id configured")
                return GraphApiResponse(
                    status_code=400,
                    data=None,
                    error=f"Organization {org_name} is not configured with NinjaOne integration"
                )

        except Exception as e:
            logger.error(f"Error fetching organization {org_id}: {e}")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error=f"Failed to fetch organization details: {str(e)}"
            )

        # Validate month if provided
        if month:
            try:
                # Import month selector to validate
                from security_reporting_system.src.utils.month_selector import MonthSelector

                month_selector = MonthSelector()
                available_months = month_selector.list_available_months()
                available_month_names = [m['name'] for m in available_months]

                if month not in available_month_names:
                    return GraphApiResponse(
                        status_code=400,
                        data=None,
                        error=f"Invalid month: {month}. Available months: {', '.join(available_month_names)}. Use /api/GetAvailableReportMonths to see all options."
                    )

                logger.info(f"Using month: {month}")

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

        # Transform the data using FrontendTransformer
        try:
            logger.info("Transforming data using FrontendTransformer...")

            transformer = FrontendTransformer()
            frontend_json = transformer.transform_to_frontend_json(security_data)

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

        # Get organization info for response (already fetched earlier)
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
        from supabase import create_client

        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")

        if not supabase_url or not supabase_key:
            logger.error("Supabase credentials not configured")
            return GraphApiResponse(
                status_code=500,
                data=None,
                error="Server configuration error: Supabase credentials missing"
            )

        supabase = create_client(supabase_url, supabase_key)

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