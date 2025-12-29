"""
Month selector endpoints for multi-month reporting functionality
"""

import logging
from fastapi import APIRouter
from models import GraphApiResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/ListAvailableMonths", response_model=GraphApiResponse, summary="List Available Months for Reporting")
async def list_available_months():
    """
    Lists the available months for security report generation.
    Returns the last 3 months (excluding current month) for report generation.
    """
    try:
        # Import the month selector from security_reporting_system
        import sys
        import os

        # Add security_reporting_system to path
        security_system_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'security_reporting_system')
        if security_system_path not in sys.path:
            sys.path.insert(0, security_system_path)

        from src.utils.month_selector import MonthSelector

        month_selector = MonthSelector()
        available_months = month_selector.list_available_months()

        # Format for API response
        result_data = {
            "available_months": available_months,
            "usage_info": {
                "description": "Use the 'name' field in GenerateSecurityReport endpoint",
                "example_usage": "POST /api/GenerateSecurityReport with {'month': 'August'} in request body"
            }
        }

        return GraphApiResponse(status_code=200, data=result_data)

    except Exception as e:
        logger.error(f"Error listing available months: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data={},
            error=f"Failed to list available months: {str(e)}"
        )