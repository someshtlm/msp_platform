# report_endpoint.py

import logging
import sys
import os
import io
import base64
from datetime import datetime
from fastapi import APIRouter, HTTPException, Path, Depends, Query
from fastapi.responses import StreamingResponse
from typing import Optional, Dict, Any
from models import GraphApiResponse
from schemas import AccountAllocationRequest, SaveIntegrationCredentialsRequest
from dotenv import load_dotenv

load_dotenv()

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

    print(" SecurityAssessmentOrchestrator imported successfully")
except ImportError as e:
    print(f"Failed to import SecurityAssessmentOrchestrator: {e}")
    import traceback

    traceback.print_exc()

    # Try to import step by step to find exactly where it fails
    print("=== DEBUG: Step-by-step Import Test ===")
    try:
        import security_reporting_system

        print("security_reporting_system package imported")
    except ImportError as e:
        print(f"security_reporting_system package: {e}")

    try:
        from security_reporting_system import src

        print("security_reporting_system.src imported")
    except ImportError as e:
        print(f"security_reporting_system.src: {e}")

    try:
        from security_reporting_system.src import main

        print(" security_reporting_system.src.main imported")
    except ImportError as e:
        print(f" security_reporting_system.src.main: {e}")
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
        demo_user_id = os.getenv("DEMO_USER_ID", "")
        if demo_user_id and user_id == demo_user_id:
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
                    "NinjaOne": {
                        "charts": {
                            "patch_management_enablement": {
                                "enabled": 81,
                                "disabled": 1
                            },
                            "patch_status_distribution": {
                                "installed": 651,
                                "approved": 36,
                                "failed": 2,
                                "pending": 5
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
                            }
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
                        }
                    },
                    "Autotask": {
                        "charts": {
                            "daily_tickets_trend": {
                                "created": [
                                    1,
                                    14,
                                    3,
                                    8,
                                    5,
                                    0,
                                    1,
                                    7,
                                    7,
                                    12,
                                    2,
                                    3,
                                    0,
                                    0,
                                    9,
                                    7,
                                    4,
                                    0,
                                    5,
                                    0,
                                    0,
                                    4,
                                    6,
                                    9,
                                    2,
                                    4,
                                    1,
                                    1,
                                    7,
                                    6
                                ],
                                "completed": [
                                    0,
                                    10,
                                    7,
                                    5,
                                    4,
                                    0,
                                    0,
                                    4,
                                    8,
                                    11,
                                    10,
                                    2,
                                    0,
                                    0,
                                    6,
                                    7,
                                    4,
                                    1,
                                    5,
                                    0,
                                    0,
                                    1,
                                    4,
                                    1,
                                    1,
                                    8,
                                    1,
                                    0,
                                    3,
                                    6
                                ],
                                "days": [
                                    1,
                                    2,
                                    3,
                                    4,
                                    5,
                                    6,
                                    7,
                                    8,
                                    9,
                                    10,
                                    11,
                                    12,
                                    13,
                                    14,
                                    15,
                                    16,
                                    17,
                                    18,
                                    19,
                                    20,
                                    21,
                                    22,
                                    23,
                                    24,
                                    25,
                                    26,
                                    27,
                                    28,
                                    29,
                                    30
                                ]
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
                                "critical": 2,
                                "high": 3,
                                "medium": 8,
                                "low": 1
                            },
                            "sla_performance": {
                                "first_response_percentage": 98.1,
                                "resolution_percentage": 71.9
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
                            ],
                            "tickets_by_contact": {
                                "tickets_by_contact_summary": {
                                    "contacts_summary": {
                                        "contacts_count": 22,
                                        "total_tickets": 111,
                                        "top_contact": "Emily Gupton"
                                    }
                                },
                                "data": [
                                    {
                                        "name": "L. Gupton",
                                        "tickets": 42
                                    },
                                    {
                                        "name": "Automation Sheets",
                                        "tickets": 26
                                    },
                                    {
                                        "name": "Other",
                                        "tickets": 10
                                    },
                                    {
                                        "name": "TLIT unknown",
                                        "tickets": 6
                                    },
                                    {
                                        "name": "Mark Wood",
                                        "tickets": 5
                                    },
                                    {
                                        "name": "Sarah Williams",
                                        "tickets": 5
                                    },
                                    {
                                        "name": "Stinnette True",
                                        "tickets": 5
                                    },
                                    {
                                        "name": "Amy Vans",
                                        "tickets": 2
                                    },
                                    {
                                        "name": "Chris Morris",
                                        "tickets": 2
                                    },
                                    {
                                        "name": "Camille Gordon",
                                        "tickets": 2
                                    },
                                    {
                                        "name": "Scott Lee",
                                        "tickets": 2
                                    },
                                    {
                                        "name": "Pamela Frisina-Rosado",
                                        "tickets": 2
                                    },
                                    {
                                        "name": "JD Frank",
                                        "tickets": 2
                                    }
                                ]
                            }
                        }
                    },
                    "Cove": {
                        "charts": {
                            "total_devices_storage_summary_cove": {
                              "totalDevices": 10,
                              "totalStorage": 4.30
                            },
                            "asset_type_distribution_cove": {
                              "workstations": 7,
                              "servers": 3,
                              "others": 0
                            },
                            "devices_distribution_cove": {
                              "physical": 7,
                              "virtual": 3,
                              "others": 0
                            },
                            "retention_policy_distribution_cove": {
                              "365 Day Retention": 4,
                              "90D-52W-36M-7Y 2": 3,
                              "180 Day Retention": 5
                              }
                            }
                          },
                    "Proofpoint": {
                            "charts": {
                              "threat_by_org_pp": [
                                { "organization": "TechCorp", "spam": 8900, "virus": 450, "phishing": 820 },
                                { "organization": "Global Finance", "spam": 6200, "virus": 320, "phishing": 640 },
                                { "organization": "Healthcare", "spam": 4800, "virus": 280, "phishing": 510 }
                              ],
                              "traffic_direction_comparison_pp": [
                                { "category": "Clean", "inbound": 12500, "outbound": 11800 },
                                { "category": "Spam", "inbound": 8900, "outbound": 1200 },
                                { "category": "Virus", "inbound": 450, "outbound": 85 },
                                { "category": "Fraud", "inbound": 320, "outbound": 45 },
                                { "category": "Blacklist", "inbound": 680, "outbound": 120 }
                              ],
                              "top_orgs_by_inbound_volume_pp": {
                                "TechCorp Industries": 58200,
                                "Global Finance Ltd": 41500,
                                "Healthcare Systems": 32800,
                                "Manufacturing Co": 24100,
                                "Retail Solutions": 18900
                              },
                              "inbound_mail_composition_pp": {
                                "clean": 1500,
                                "spam": 5200,
                                "virus": 1850,
                                "fraud": 720
                              }
                            }
                          },
                    "ConnectSecure": {
                        "charts": {
                            "asset_type_distribution": {
                                "live_count": {
                                    "discovered": 110,
                                    "other_asset": 83,
                                    "unknown": 4
                                },
                                "monthly_count": {
                                    "discovered": 6,
                                    "other_asset": 25,
                                    "unknown": 1
                                }
                            },
                            "operating_system_distribution": {
                                "live_count": {
                                    "Windows": 80,
                                    "Linux": 2,
                                    "Others": 29
                                },
                                "monthly_count": {
                                    "Others": 27,
                                    "Windows": 13
                                }
                            },
                            "security_risk_score": {
                                "live_count": 55.39,
                                "monthly_count": 2.17
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
                            "vulnerability_severity": {
                                "live_count": {
                                    "critical": 28,
                                    "high": 425,
                                    "medium": 277,
                                    "low": 25
                                },
                                "monthly_count": {
                                    "critical": 0,
                                    "high": 0,
                                    "medium": 0,
                                    "low": 0
                                }
                            }
                        }
                    },
                    "Bitdefender": {
                    "charts": {
                        "endpoint_utilization_bitdefender": {
                            "activeEndpoints": 80,
                            "managedEndpoints": 82
                        },
                        "riskScore_bitdefender" : {
                                "value": "50%",
                                "impact": "Medium",
                                "misconfigurations": "80%",
                                "appVulnerabilities": "30%",
                                "humanRisks": "10%",
                                "industryModifier": "0%"},
                     "inventory_summary_bitdefender": {
                            "summary": {
                                "windowsWorkstations": 82,
                                "windowsServers": 1,
                                "macOS": 0,
                                "linux": 0
                            },
                            "count": {
                                "physicalMachines": 82,
                                "virtualMachines": 1
                            }
                        }
            },
            "tables": {
                "networkinventory_bitdefender": [
                    {
                        "Module": "antimalware",
                        "enable": 80,
                        "disable": 0,
                        "notInstalled": 2,
                        "displayName": "Antimalware"
                    },
                    {
                        "Module": "advancedThreatControl",
                        "enable": 81,
                        "disable": 1,
                        "notInstalled": 0,
                        "displayName": "Advanced Threat Control"
                    },
                    {
                        "Module": "advancedAntiExploit",
                        "enable": 82,
                        "disable": 0,
                        "notInstalled": 0,
                        "displayName": "Advanced Anti-Exploit"
                    },
                    {
                        "Module": "firewall",
                        "enable": 78,
                        "disable": 1,
                        "notInstalled": 3,
                        "displayName": "Firewall"
                    },
                    {
                        "Module": "networkAttackDefense",
                        "enable": 75,
                        "disable": 2,
                        "notInstalled": 5,
                        "displayName": "Network Protection"
                    },
                    {
                        "Module": "deviceControl",
                        "enable": 82,
                        "disable": 0,
                        "notInstalled": 0,
                        "displayName": "Device Control"
                    },
                    {
                        "Module": "encryption",
                        "enable": 2,
                        "disable": 0,
                        "notInstalled": 80,
                        "displayName": "Encryption"
                    },
                    {
                        "Module": "patchManagement",
                        "enable": 70,
                        "disable": 5,
                        "notInstalled": 7,
                        "displayName": "Patch Management"
                    },
                    {
                        "Module": "edrSensor",
                        "enable": 65,
                        "disable": 0,
                        "notInstalled": 17,
                        "displayName": "EDR Sensor"
                    },
                    {
                        "Module": "powerUser",
                        "enable": 12,
                        "disable": 0,
                        "notInstalled": 70,
                        "displayName": "Power User"
                    },
                    {
                        "Module": "exchange",
                        "enable": 0,
                        "disable": 0,
                        "notInstalled": 82,
                        "displayName": "Exchange Protection"
                    },
                    {
                        "Module": "containerProtection",
                        "enable": 0,
                        "disable": 0,
                        "notInstalled": 82,
                        "displayName": "Container Protection"
                    },
                    {
                        "Module": "integrityMonitoring",
                        "enable": 10,
                        "disable": 3,
                        "notInstalled": 70,
                        "displayName": "Integrity Monitoring"
                    },
                    {
                        "Module": "phASR",
                        "enable": 5,
                        "disable": 0,
                        "notInstalled": 77,
                        "displayName": "PHASR"
                    }
                ]
            }
            },
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

        try:
            logger.info("Transforming data using FrontendTransformer...")

            transformer = FrontendTransformer()
            frontend_json = transformer.transform_to_frontend_json(security_data, account_id=account_id)

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
            from security_reporting_system.src.services.encryption_manager import EncryptionManager

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
            from security_reporting_system.src.utils.organization_matcher import OrganizationMatcher

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