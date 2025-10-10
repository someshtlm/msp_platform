import logging
import os
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel
from typing import Optional
from supabase import create_client, Client
from models import GraphApiResponse
from datetime import datetime
from crypto_utils import encrypt_client_secret
from typing import Optional


# Create router for client endpoints
router = APIRouter()
logger = logging.getLogger(__name__)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# Request model for the form data
class AddClientRequest(BaseModel):
    organization_name: str
    primary_domain: str
    tenant_id: str
    client_id: str
    client_secret: str
    industry: Optional[str] = None
    organization_size: Optional[str] = None

class EditClientRequest(BaseModel):
    organization_name: Optional[str] = None
    primary_domain: Optional[str] = None
    industry: Optional[str] = None
    organization_size: Optional[str] = None


# ----------- Add Client Endpoint --------------
@router.post("/AddClient", response_model=GraphApiResponse, summary="Add New Client Organization")
async def add_client(request: AddClientRequest):
    """
    Adds a new client organization to the database with their Microsoft Graph API credentials.
    The client_secret is automatically encrypted before storage.
    Validates for duplicate tenant IDs and client secrets to prevent conflicts.
    """
    try:
        logger.info(f"Adding new client organization: {request.organization_name}")

        # Encrypt the client_secret before storing
        try:
            encrypted_secret = encrypt_client_secret(request.client_secret)
        except ValueError as e:
            logger.error(f"Failed to encrypt client_secret for {request.organization_name}: {str(e)}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error="Failed to process client credentials securely"
            )

        result = supabase.table("organization_mapping").insert({
            "organization_name": request.organization_name,
            "domain": request.primary_domain,
            "tenant_id": request.tenant_id,
            "client_id": request.client_id,
            "client_secret": encrypted_secret,  # Store encrypted version
            "industry": request.industry,
            "organization_size": request.organization_size
        }).execute()

        logger.info(f"Successfully added client organization with ID: {result.data[0]['id']}")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": "Client organization added successfully",
                "ninjaone_org_id": result.data[0].get('ninjaone_org_id'),
                "client_id": result.data[0].get('client_id')
            },
            error=None
        )

    except Exception as e:
        error_message = str(e).lower()
        logger.error(f"Error adding client organization {request.organization_name}: {str(e)}")

        # Handle unique constraint violations
        if "duplicate key" in error_message:
            if "client_secret" in error_message:
                return GraphApiResponse(
                    status_code=400,
                    data={"success": False},
                    error="This client secret is already in use. Please use a different secret key."
                )
            elif "tenant_id" in error_message:
                return GraphApiResponse(
                    status_code=400,
                    data={"success": False},
                    error="This tenant ID already exists. Please check your tenant ID."
                )

        # Generic error response
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Failed to add client: {str(e)}"
        )

# ----------- Get Clients Endpoint -------------


@router.get("/GetClients", response_model=GraphApiResponse, summary="List All Active Client Organizations")
async def get_clients():
    """
    Retrieves all active client organizations from the database.
    Returns organization_name, domain (with link), client_id, created (created & updated date),
    status, industry, and organization_size.
    """
    try:
        logger.info("Fetching all active client organizations")

        result = supabase.table("organization_mapping").select(
            "ninjaone_org_id, client_id, organization_name, domain, status, created_at, updated_at, industry, organization_size"
        ).eq("status", "Active").execute()

        clients = []
        for item in result.data:
            # Use from isoformat() to parse ISO8601 string with timezone
            created_at = datetime.fromisoformat(item["created_at"])
            updated_at = datetime.fromisoformat(item["updated_at"])

            clients.append({
                "ninjaone_org_id": item["ninjaone_org_id"],
                "organization_name": item["organization_name"],
                "domain": {
                    "url": item["domain"],
                    "text": "Visit Website"
                },
                "client_id": item["client_id"],
                "created": {
                    "created_date": created_at.strftime("%m/%d/%Y"),
                    "updated_date": updated_at.strftime("%m/%d/%Y")
                },
                "status": item["status"],
                "industry": item["industry"],
                "organization_size": item["organization_size"]
            })

        logger.info(f"Successfully retrieved {len(clients)} active client organizations")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "clients": clients,
                "count": len(clients)
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error fetching client organizations: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data={
                "success": False,
                "clients": []
            },
            error=f"Failed to retrieve client organizations: {str(e)}"
        )

@router.delete("/DeleteClient/{client_id}", response_model=GraphApiResponse, summary="Delete Client Organization")
async def delete_client(client_id: str = Path(..., description="The client ID of the organization to delete")):
    """
    Permanently deletes a client organization from the database using client_id.
    This is a hard delete operation and cannot be undone.
    """
    try:
        logger.info(f"Attempting to delete client organization with client_id: {client_id}")

        # First check if client exists
        existing_client = supabase.table("organization_mapping").select("id, organization_name").eq("client_id",
                                                                                              client_id).execute()

        if not existing_client.data:
            logger.warning(f"Client with client_id {client_id} not found")
            return GraphApiResponse(
                status_code=404,
                data={"success": False},
                error="Client organization not found"
            )

        client_name = existing_client.data[0]["organization_name"]
        ninjaone_org_id = existing_client.data[0].get("ninjaone_org_id")
        db_id = existing_client.data[0]["id"]

        # Perform hard delete and verify
        result = supabase.table("organization_mapping").delete().eq("client_id", client_id).execute()

        # Verify deletion by checking if record still exists
        verify_delete = supabase.table("organization_mapping").select("id").eq("client_id", client_id).execute()

        if verify_delete.data:
            # Record still exists, deletion failed
            logger.error(f"Delete operation appeared successful but record still exists for client_id: {client_id}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error="Delete operation failed - record still exists. This may be due to RLS policies or permissions."
            )

        logger.info(f"Successfully deleted client organization: {client_name} (client_id: {client_id})")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": f"Client organization '{client_name}' deleted successfully",
                "deleted_client_id": client_id,
                "ninjaone_org_id": ninjaone_org_id
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error deleting client organization with client_id {client_id}: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Failed to delete client: {str(e)}"
        )


# ----------- Edit Client Endpoint -------------
@router.put("/EditClient/{client_id}", response_model=GraphApiResponse, summary="Edit Client Organization")
async def edit_client(
        client_id: str = Path(..., description="The client ID of the organization to edit"),
        request: EditClientRequest = None
):
    """
    Updates client organization information. Only allows editing of:
    - organization_name (stored as client_name)
    - primary_domain (stored as domain)
    - industry
    - organization_size

    This is a partial update - only provided fields will be updated.
    """
    try:
        logger.info(f"Attempting to edit client organization with client_id: {client_id}")

        # First check if client exists
        existing_client = supabase.table("organization_mapping").select("id, organization_name").eq("client_id",
                                                                                              client_id).execute()

        if not existing_client.data:
            logger.warning(f"Client with client_id {client_id} not found")
            return GraphApiResponse(
                status_code=404,
                data={"success": False},
                error="detail Not Found"
            )

        # Build update dictionary with only provided fields
        update_data = {}
        if request.organization_name is not None:
            update_data["organization_name"] = request.organization_name
        if request.primary_domain is not None:
            update_data["domain"] = request.primary_domain
        if request.industry is not None:
            update_data["industry"] = request.industry
        if request.organization_size is not None:
            update_data["organization_size"] = request.organization_size

        # Check if any fields to update
        if not update_data:
            return GraphApiResponse(
                status_code=400,
                data={"success": False},
                error="No fields provided for update"
            )

        # Add updated timestamp
        update_data["updated_at"] = datetime.now().isoformat()

        # Perform update
        result = supabase.table("organization_mapping").update(update_data).eq("client_id", client_id).execute()

        logger.info(f"Successfully updated client organization with client_id: {client_id}")

        # Get the ninjaone_org_id from existing_client for response
        ninjaone_org_id = existing_client.data[0].get("ninjaone_org_id")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": "Client organization updated successfully",
                "updated_fields": list(update_data.keys()),
                "client_id": client_id,
                "ninjaone_org_id": ninjaone_org_id
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error updating client organization with client_id {client_id}: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Failed to update client: {str(e)}"
        )


# @router.get("/GetClientOrganizations", response_model=GraphApiResponse, summary="List All Client Organizations from Mapping Table")
# async def get_client_organizations():
#     """
#     Retrieves all organization mappings from the 'organization_mapping' table.
#     Returns ninjaone_org_id and organization_name.
#     """
#     try:
#         logger.info("Fetching all organization mappings")
#
#         result = supabase.table("organization_mapping").select(
#             "ninjaone_org_id, organization_name"
#         ).execute()
#
#         organizations = result.data if result.data else []
#
#         logger.info(f"Successfully retrieved {len(organizations)} organization mappings")
#
#         return GraphApiResponse(
#             status_code=200,
#             data={
#                 "success": True,
#                 "organizations": organizations,
#                 "count": len(organizations)
#             },
#             error=None
#         )
#
#     except Exception as e:
#         logger.error(f"Error fetching organization mappings: {str(e)}")
#         return GraphApiResponse(
#             status_code=500,
#             data={
#                 "success": False,
#                 "organizations": []
#             },
#             error=f"Failed to retrieve organization mappings: {str(e)}"
#         )
#

