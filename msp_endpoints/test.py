import time
import logging
import asyncio
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, HttpUrl
import httpx
import csv
import io
from msal import ConfidentialClientApplication

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Azure AD / Microsoft Graph configuration
# In a production environment, use environment variables or a secret manager.


# Initialize MSAL confidential client
msal_app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
)


# --- Helper Functions ---

def get_cached_token() -> str:
    """Acquires a token from MSAL, using the cache if available."""
    # First, try to get a token from the cache
    result = msal_app.acquire_token_silent(scopes=SCOPE, account=None)

    # If no suitable token is in the cache, get a new one from AAD
    if not result:
        logger.info("No suitable token in cache, acquiring a new one.")
        result = msal_app.acquire_token_for_client(scopes=SCOPE)

    if not result or 'access_token' not in result:
        error = result.get('error_description', result.get('error', 'Unknown error'))
        logger.error(f"Token acquisition failed: {error}")
        # This will be caught and raised as an HTTPException by the endpoint
        raise Exception(f"Failed to acquire token: {error}")

    return result['access_token']


async def _make_graph_api_request(url: str) -> Dict[str, Any]:
    """
    A reusable helper function to make GET requests to the MS Graph API.
    Handles token acquisition, request execution, and error handling.
    """
    logger.info(f"Making Graph API request to: {url}")
    try:
        token = get_cached_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=30.0)

            # Raise an exception for 4xx/5xx (client/server error) responses
            response.raise_for_status()

            return response.json()

    except httpx.HTTPStatusError as e:
        # The API returned an error (e.g., 401 Unauthorized, 404 Not Found)
        logger.error(f"HTTP Status Error fetching from '{url}': {e.response.status_code}")
        # Try to return the error details from the Graph API response if available
        try:
            error_detail = e.response.json()
        except Exception:
            error_detail = e.response.text
        raise HTTPException(
            status_code=e.response.status_code,
            detail=error_detail
        )
    except Exception as e:
        # Other errors like token acquisition failure, network issues, or timeouts
        logger.error(f"An unexpected error occurred while processing request for '{url}': {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )


# --- FastAPI Application Setup ---

app = FastAPI(
    title="Microsoft Graph API Service",
    version="3.0.0",
    description="A FastAPI service to interact with various Microsoft Graph API endpoints, "
                "including device management and a generic data fetcher."
)


# --- API Endpoints ---

@app.get("/deviceManagement/managedDevices",
         summary="Get All Managed Devices",
         tags=["Device Management"])
async def get_managed_devices():
    """
    Retrieves a list of all managed devices for the organization from Microsoft Intune.
    This corresponds to the Graph API endpoint: `GET /deviceManagement/managedDevices`.
    """
    endpoint_url = f"{GRAPH_BASE_URL}/deviceManagement/managedDevices"
    return await _make_graph_api_request(endpoint_url)


@app.get("/deviceManagement/detectedApps",
         summary="Get All Detected Applications",
         tags=["Device Management"])
async def get_detected_apps():
    """
    Retrieves a list of all applications discovered on the organization's managed devices.
    This corresponds to the Graph API endpoint: `GET /deviceManagement/detectedApps`.
    """
    endpoint_url = f"{GRAPH_BASE_URL}/deviceManagement/detectedApps"
    return await _make_graph_api_request(endpoint_url)


@app.get("/fetch-generic-endpoint",
         summary="Fetch Data from a Generic Graph API Endpoint",
         tags=["Generic Fetcher"])
async def fetch_generic_endpoint(
        endpoint_url: HttpUrl = Query(...,
                                      description="The full URL of the Microsoft Graph API endpoint to fetch.",
                                      example="https://graph.microsoft.com/v1.0/users?$top=5")
):
    """
    Provides a generic proxy to GET data from any Microsoft Graph v1.0 endpoint.
    This is useful for exploring the Graph API or fetching data not covered by other endpoints.
    """
    # HttpUrl is a Pydantic type, convert it to a string for the request
    return await _make_graph_api_request(str(endpoint_url))


@app.get("/health", summary="Health Check", tags=["Utilities"])
async def health_check():
    """Simple health check to verify the service is running and can acquire a token."""
    try:
        get_cached_token()
        return {"status": "healthy", "message": "Service is running and token can be acquired."}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail={"status": "unhealthy", "error": str(e)})




# --- Entry Point for Running the App ---

if __name__ == "__main__":
    import uvicorn

    # Use reload=True for development to automatically restart on code changes
    uvicorn.run(app, host="127.0.0.1", port=9000, log_level="info", reload=True)
