"""
Integration Platform Charts Endpoints
======================================
Endpoints for managing integration platforms and their available charts
"""

import logging
from fastapi import APIRouter
from typing import List, Dict, Any
from models import GraphApiResponse
from supabase_services import supabase

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/PlatformList", response_model=GraphApiResponse, summary="Get All Integration Platforms")
async def get_platform_list():
    """
    Get list of all integration platforms from the integrations table.

    Returns a list of platforms with their details including:
    - platform_id: Unique identifier
    - name: Display name of the platform
    - description: Platform description
    - enabled: Whether the platform is active
    - integrationFields: Required fields for integration

    Example Response:
    ```json
    {
        "status_code": 200,
        "data": [
            {
                "platform_id": 1,
                "name": "Autotask",
                "description": "Integrate with Autotask PSA for professional services automation",
                "enabled": true,
                "integrationFields": ["username", "secret", "integration_code"]
            }
        ],
        "error": null
    }
    ```
    """
    try:
        logger.info("Fetching all integration platforms from database")

        # Query integrations table - get all platforms (including inactive)
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

        # Transform database records to API response format
        platforms = []
        for record in response.data:
            platform = {
                "platform_id": record.get('id'),
                "name": record.get('integration_display_name'),
                "description": record.get('description', ''),
                "enabled": record.get('is_active', False),
                "integrationFields": record.get('integration_fields', [])
            }
            platforms.append(platform)

        logger.info(f"Successfully retrieved {len(platforms)} integration platforms")

        return GraphApiResponse(
            status_code=200,
            data=platforms,
            error=None
        )

    except Exception as e:
        logger.error(f"Error fetching integration platforms: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data=[],
            error=f"Failed to fetch integration platforms: {str(e)}"
        )
