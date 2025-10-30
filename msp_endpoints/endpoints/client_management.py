import logging
import os
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel
from typing import Optional, List
from supabase import create_client, Client
from models import GraphApiResponse
from datetime import datetime
from crypto_utils import encrypt_client_secret


# Create router for client endpoints
router = APIRouter()
logger = logging.getLogger(__name__)

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# POC model
class POCModel(BaseModel):
    poc_name: str
    poc_email: str
    poc_role: str

# Request model for the form data
class AddClientRequest(BaseModel):
    user_id: str  # UUID from auth table (auth_user_id)
    organization_name: str
    primary_domain: str
    tenant_id: Optional[str] = ""
    client_id: Optional[str] = ""
    client_secret: Optional[str] = ""
    industry: Optional[str] = None
    organization_size: Optional[str] = None
    pocs_list: Optional[List[POCModel]] = []

class EditClientRequest(BaseModel):
    organization_name: Optional[str] = None
    primary_domain: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    industry: Optional[str] = None
    organization_size: Optional[str] = None
    pocs_list: Optional[List[POCModel]] = None


# ----------- Add Client Endpoint --------------
@router.post("/AddClient", response_model=GraphApiResponse, summary="Add New Client Organization")
async def add_client(request: AddClientRequest):
    """
    Adds a new client organization to the database with their Microsoft Graph API credentials and POCs.
    - Resolves user_id (UUID) to account_id and platform_user_id
    - Inserts into organizations table
    - Encrypts tenant_id, client_id, client_secret (all 3 fields) if provided and inserts into m365_credentials
    - Inserts POCs into organization_pocs table
    """
    try:
        logger.info(f"Adding new client organization: {request.organization_name}")

        # Step 1: Resolve user_id to account_id and platform_user_id
        user_response = supabase.table("platform_users").select("id, account_id").eq("auth_user_id", request.user_id).execute()

        if not user_response.data or len(user_response.data) == 0:
            logger.error(f"No platform user found for user_id: {request.user_id}")
            return GraphApiResponse(
                status_code=404,
                data={"success": False},
                error=f"User not found. Invalid user_id: {request.user_id}"
            )

        platform_user_id = user_response.data[0]['id']
        account_id = user_response.data[0]['account_id']
        logger.info(f"Resolved user_id to platform_user_id: {platform_user_id}, account_id: {account_id}")

        # Step 2: Insert into organizations table
        org_result = supabase.table("organizations").insert({
            "account_id": account_id,
            "platform_user_id": platform_user_id,
            "organization_name": request.organization_name,
            "domain": request.primary_domain,
            "industry": request.industry,
            "organization_size": request.organization_size,
            "status": "Active"
        }).execute()

        if not org_result.data:
            raise Exception("Failed to insert organization")

        org_id = org_result.data[0]['id']
        logger.info(f"Successfully added organization with org_id: {org_id}")

        # Step 3: Encrypt and insert credentials if provided
        credentials_saved = False
        if (request.tenant_id and request.tenant_id.strip() and
            request.client_id and request.client_id.strip() and
            request.client_secret and request.client_secret.strip()):
            try:
                # Encrypt all three credential fields
                encrypted_tenant_id = encrypt_client_secret(request.tenant_id)
                encrypted_client_id = encrypt_client_secret(request.client_id)
                encrypted_client_secret = encrypt_client_secret(request.client_secret)

                # Insert into m365_credentials table
                creds_result = supabase.table("m365_credentials").insert({
                    "organization_id": org_id,
                    "account_id": account_id,
                    "tenant_id": encrypted_tenant_id,
                    "client_id": encrypted_client_id,
                    "client_secret": encrypted_client_secret,
                    "credential_status": "Active"
                }).execute()

                credentials_saved = True
                logger.info(f"Successfully saved encrypted credentials for org_id: {org_id}")

            except ValueError as e:
                logger.error(f"Failed to encrypt credentials for {request.organization_name}: {str(e)}")
                # Don't fail the entire operation, just log the error
                credentials_saved = False
        else:
            logger.info("No credentials provided, skipping credential storage")

        # Step 4: Insert POCs if provided
        pocs_saved = 0
        if request.pocs_list and len(request.pocs_list) > 0:
            try:
                pocs_data = []
                for poc in request.pocs_list:
                    pocs_data.append({
                        "organization_id": org_id,
                        "poc_name": poc.poc_name,
                        "poc_email": poc.poc_email,
                        "poc_role": poc.poc_role
                    })

                if pocs_data:
                    pocs_result = supabase.table("organization_pocs").insert(pocs_data).execute()
                    pocs_saved = len(pocs_result.data) if pocs_result.data else 0
                    logger.info(f"Successfully saved {pocs_saved} POCs for org_id: {org_id}")

            except Exception as e:
                logger.error(f"Failed to save POCs for {request.organization_name}: {str(e)}")
                # Don't fail the entire operation, just log the error

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": "Client organization added successfully",
                "org_id": org_id,
                "credentials_saved": credentials_saved,
                "pocs_saved": pocs_saved
            },
            error=None
        )

    except Exception as e:
        error_message = str(e).lower()
        logger.error(f"Error adding client organization {request.organization_name}: {str(e)}")

        # Handle duplicate organization name
        if "duplicate key" in error_message and "organization_name" in error_message:
            return GraphApiResponse(
                status_code=400,
                data={"success": False},
                error="An organization with this name already exists."
            )

        # Generic error response
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Failed to add client: {str(e)}"
        )

# ----------- Get Clients Endpoint -------------


# @router.get("/GetClients", response_model=GraphApiResponse, summary="List All Active Client Organizations")
# async def get_clients():
#     """
#     Retrieves all active client organizations from the database.
#     Returns organization_name, domain (with link), client_id, created (created & updated date),
#     status, industry, and organization_size.
#     """
#     try:
#         logger.info("Fetching all active client organizations")
#
#         result = supabase.table("organization_mapping").select(
#             "ninjaone_org_id, client_id, organization_name, domain, status, created_at, updated_at, industry, organization_size"
#         ).eq("status", "Active").execute()
#
#         clients = []
#         for item in result.data:
#             # Use from isoformat() to parse ISO8601 string with timezone
#             created_at = datetime.fromisoformat(item["created_at"])
#             updated_at = datetime.fromisoformat(item["updated_at"])
#
#             clients.append({
#                 "ninjaone_org_id": item["ninjaone_org_id"],
#                 "organization_name": item["organization_name"],
#                 "domain": {
#                     "url": item["domain"],
#                     "text": "Visit Website"
#                 },
#                 "client_id": item["client_id"],
#                 "created": {
#                     "created_date": created_at.strftime("%m/%d/%Y"),
#                     "updated_date": updated_at.strftime("%m/%d/%Y")
#                 },
#                 "status": item["status"],
#                 "industry": item["industry"],
#                 "organization_size": item["organization_size"]
#             })
#
#         logger.info(f"Successfully retrieved {len(clients)} active client organizations")
#
#         return GraphApiResponse(
#             status_code=200,
#             data={
#                 "success": True,
#                 "clients": clients,
#                 "count": len(clients)
#             },
#             error=None
#         )
#
#     except Exception as e:
#         logger.error(f"Error fetching client organizations: {str(e)}")
#         return GraphApiResponse(
#             status_code=500,
#             data={
#                 "success": False,
#                 "clients": []
#             },
#             error=f"Failed to retrieve client organizations: {str(e)}"
#         )

@router.delete("/DeleteClient/{org_id}", response_model=GraphApiResponse, summary="Delete Client Organization")
async def delete_client(org_id: int = Path(..., description="The organization ID to delete")):
    """
    Permanently deletes a client organization and all related data from the database.
    This is a hard delete operation and cannot be undone.

    Deletes from:
    - organization_pocs table
    - m365_credentials table
    - organizations table
    """
    try:
        logger.info(f"Attempting to delete client organization with org_id: {org_id}")

        # Step 1: Check if organization exists
        existing_org = supabase.table("organizations").select("id, organization_name").eq("id", org_id).execute()

        if not existing_org.data:
            logger.warning(f"Organization with org_id {org_id} not found")
            return GraphApiResponse(
                status_code=404,
                data={"success": False},
                error="Organization not found"
            )

        org_name = existing_org.data[0]["organization_name"]
        logger.info(f"Found organization to delete: {org_name}")

        # Step 2: Delete related POCs first
        try:
            pocs_delete = supabase.table("organization_pocs").delete().eq("organization_id", org_id).execute()
            logger.info(f"Deleted POCs for org_id: {org_id}")
        except Exception as e:
            logger.warning(f"Error deleting POCs (may not exist): {str(e)}")

        # Step 3: Delete credentials
        try:
            creds_delete = supabase.table("m365_credentials").delete().eq("organization_id", org_id).execute()
            logger.info(f"Deleted credentials for org_id: {org_id}")
        except Exception as e:
            logger.warning(f"Error deleting credentials (may not exist): {str(e)}")

        # Step 4: Delete the organization itself
        org_delete = supabase.table("organizations").delete().eq("id", org_id).execute()

        # Step 5: Verify deletion
        verify_delete = supabase.table("organizations").select("id").eq("id", org_id).execute()

        if verify_delete.data:
            # Record still exists, deletion failed
            logger.error(f"Delete operation appeared successful but record still exists for org_id: {org_id}")
            return GraphApiResponse(
                status_code=500,
                data={"success": False},
                error="Delete operation failed - record still exists. This may be due to RLS policies or permissions."
            )

        logger.info(f"Successfully deleted client organization: {org_name} (org_id: {org_id})")

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": f"Client organization '{org_name}' and all related data deleted successfully",
                "deleted_org_id": org_id
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error deleting client organization with org_id {org_id}: {str(e)}")
        return GraphApiResponse(
            status_code=500,
            data={"success": False},
            error=f"Failed to delete client: {str(e)}"
        )


# ----------- Edit Client Endpoint -------------
@router.put("/EditClient/{org_id}", response_model=GraphApiResponse, summary="Edit Client Organization")
async def edit_client(
        org_id: int = Path(..., description="The organization ID to edit"),
        request: EditClientRequest = None
):
    """
    Updates client organization information with credentials and POCs.
    - Updates organizations table
    - Encrypts and updates/inserts credentials in m365_credentials if provided
    - Replaces POCs in organization_pocs table if provided

    This is a partial update - only provided fields will be updated.
    """
    try:
        logger.info(f"Attempting to edit client organization with org_id: {org_id}")

        # First check if organization exists
        existing_org = supabase.table("organizations").select("id, organization_name").eq("id", org_id).execute()

        if not existing_org.data:
            logger.warning(f"Organization with org_id {org_id} not found")
            return GraphApiResponse(
                status_code=404,
                data={"success": False},
                error="Organization not found"
            )

        # Step 1: Build update dictionary for organizations table
        update_data = {}
        if request.organization_name is not None:
            update_data["organization_name"] = request.organization_name
        if request.primary_domain is not None:
            update_data["domain"] = request.primary_domain
        if request.industry is not None:
            update_data["industry"] = request.industry
        if request.organization_size is not None:
            update_data["organization_size"] = request.organization_size

        # Update organizations table if there are fields to update
        if update_data:
            update_data["updated_at"] = datetime.now().isoformat()
            org_result = supabase.table("organizations").update(update_data).eq("id", org_id).execute()
            logger.info(f"Updated organization fields: {list(update_data.keys())}")

        # Step 2: Update credentials if provided
        credentials_updated = False
        has_tenant = request.tenant_id and request.tenant_id.strip()
        has_client = request.client_id and request.client_id.strip()
        has_secret = request.client_secret and request.client_secret.strip()

        if has_tenant or has_client or has_secret:
            try:
                # Check if credentials already exist for this organization
                existing_creds = supabase.table("m365_credentials").select("id").eq("organization_id", org_id).execute()

                # Prepare credential update data (only encrypt fields that are provided)
                creds_data = {}
                if has_tenant:
                    creds_data["tenant_id"] = encrypt_client_secret(request.tenant_id)
                if has_client:
                    creds_data["client_id"] = encrypt_client_secret(request.client_id)
                if has_secret:
                    creds_data["client_secret"] = encrypt_client_secret(request.client_secret)

                if creds_data:
                    if existing_creds.data:
                        # Update existing credentials
                        creds_data["updated_at"] = datetime.now().isoformat()
                        creds_result = supabase.table("m365_credentials").update(creds_data).eq("organization_id", org_id).execute()
                        credentials_updated = True
                        logger.info(f"Updated credentials for org_id: {org_id}")
                    else:
                        # Insert new credentials (need all three fields)
                        if has_tenant and has_client and has_secret:
                            creds_data["organization_id"] = org_id
                            creds_data["credential_status"] = "Active"
                            creds_result = supabase.table("m365_credentials").insert(creds_data).execute()
                            credentials_updated = True
                            logger.info(f"Inserted new credentials for org_id: {org_id}")
                        else:
                            logger.warning("Cannot insert partial credentials - all three fields required")

            except Exception as e:
                logger.error(f"Failed to update credentials for org_id {org_id}: {str(e)}")
                # Don't fail the entire operation

        # Step 3: Update POCs if provided
        pocs_updated = 0
        if request.pocs_list is not None:
            try:
                # Delete existing POCs
                supabase.table("organization_pocs").delete().eq("organization_id", org_id).execute()
                logger.info(f"Deleted existing POCs for org_id: {org_id}")

                # Insert new POCs
                if len(request.pocs_list) > 0:
                    pocs_data = []
                    for poc in request.pocs_list:
                        pocs_data.append({
                            "organization_id": org_id,
                            "poc_name": poc.poc_name,
                            "poc_email": poc.poc_email,
                            "poc_role": poc.poc_role
                        })

                    if pocs_data:
                        pocs_result = supabase.table("organization_pocs").insert(pocs_data).execute()
                        pocs_updated = len(pocs_result.data) if pocs_result.data else 0
                        logger.info(f"Inserted {pocs_updated} new POCs for org_id: {org_id}")

            except Exception as e:
                logger.error(f"Failed to update POCs for org_id {org_id}: {str(e)}")
                # Don't fail the entire operation

        return GraphApiResponse(
            status_code=200,
            data={
                "success": True,
                "message": "Client organization updated successfully",
                "org_id": org_id,
                "updated_fields": list(update_data.keys()) if update_data else [],
                "credentials_updated": credentials_updated,
                "pocs_updated": pocs_updated
            },
            error=None
        )

    except Exception as e:
        logger.error(f"Error updating client organization with org_id {org_id}: {str(e)}")
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


