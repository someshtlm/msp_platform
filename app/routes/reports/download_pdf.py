"""
Download Report PDF Endpoint
Generates PDF from HTML content and returns as downloadable file
"""

import logging
import os
import subprocess
import tempfile
import re
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from app.services.ppt.pdf_to_pptx import convert_pdf_to_pptx

router = APIRouter()
logger = logging.getLogger(__name__)

# Path to Node.js PDF generator script
PDF_GENERATOR_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "services",
    "pdf",
    "generate_pdf.js"
)


# ============================================================================
# REQUEST SCHEMA
# ============================================================================

class DownloadReportPDFRequest(BaseModel):
    """Request to generate and download PDF from HTML"""
    html_content: str                   # Full HTML content
    organization_name: str              # Organization name
    month_display_name: str             # Format: "December 2025"
    org_id: Optional[int] = None        # Organization ID (optional)
    uuid: Optional[str] = None          # Report UUID (optional)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def sanitize_filename(name: str) -> str:
    """
    Sanitize organization name for filename
    - Replace spaces with underscores
    - Remove special characters except underscores and hyphens

    Example: "TeamLogic IT - Burlington" → "TeamLogic_IT_Burlington"
    """
    # Replace spaces with underscores
    name = name.replace(" ", "_")
    # Remove special characters except underscores and hyphens
    name = re.sub(r'[^a-zA-Z0-9_-]', '', name)
    return name


def generate_pdf_filename(org_name: str, month_display_name: str) -> str:
    """
    Generate PDF filename in format: {org_name}_{MonthYear}_report.pdf

    Example: "Terra-Vaults_December2025_report.pdf"

    Args:
        org_name: Organization name (will be sanitized)
        month_display_name: Already formatted date like "December 2025"
    """
    sanitized_org = sanitize_filename(org_name)
    # Remove space from month_display_name: "December 2025" → "December2025"
    month_year_no_space = month_display_name.replace(" ", "")
    return f"{sanitized_org}_{month_year_no_space}_report.pdf"


def generate_pptx_filename(org_name: str, month_display_name: str) -> str:
    """
    Generate PPTX filename in format: {org_name}_{MonthYear}_report.pptx

    Example: "Terra-Vaults_December2025_report.pptx"

    Args:
        org_name: Organization name (will be sanitized)
        month_display_name: Already formatted date like "December 2025"
    """
    sanitized_org = sanitize_filename(org_name)
    # Remove space from month_display_name: "December 2025" → "December2025"
    month_year_no_space = month_display_name.replace(" ", "")
    return f"{sanitized_org}_{month_year_no_space}_report.pptx"


async def call_node_pdf_generator(html_content: str, output_pdf_path: str) -> bool:
    """
    Call Node.js PDF generator script with retry logic handled by the script

    Args:
        html_content: Full HTML content string
        output_pdf_path: Where to save the generated PDF

    Returns:
        True if successful, False otherwise
    """
    temp_html_file = None

    try:
        # Create temp HTML file
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.html', delete=False) as f:
            temp_html_file = f.name
            f.write(html_content)

        logger.info(f"Created temp HTML file: {temp_html_file}")

        # Call Node.js script
        # Script handles retry logic internally (3 attempts)
        logger.info("Calling Node.js PDF generator...")
        result = subprocess.run(
            ['node', PDF_GENERATOR_SCRIPT, temp_html_file, output_pdf_path],
            capture_output=True,
            text=True,
            timeout=180  # 3 minutes timeout for large reports
        )

        # Log Node.js script output
        if result.stdout:
            logger.info(f"Node.js output: {result.stdout}")
        if result.stderr:
            logger.warning(f"Node.js stderr: {result.stderr}")

        if result.returncode != 0:
            logger.error(f"PDF generation failed with return code {result.returncode}")
            return False

        # Verify PDF was created
        if not os.path.exists(output_pdf_path):
            logger.error(f"PDF file not found at: {output_pdf_path}")
            return False

        file_size = os.path.getsize(output_pdf_path)
        logger.info(f"PDF generated successfully: {file_size} bytes")

        return True

    except subprocess.TimeoutExpired:
        logger.error("PDF generation timed out after 180 seconds")
        return False
    except Exception as e:
        logger.error(f"Error calling Node.js PDF generator: {e}")
        return False
    finally:
        # Clean up temp HTML file
        if temp_html_file and os.path.exists(temp_html_file):
            try:
                os.remove(temp_html_file)
                logger.info(f"Cleaned up temp HTML file: {temp_html_file}")
            except Exception as e:
                logger.warning(f"Failed to remove temp HTML file: {e}")


# ============================================================================
# MAIN ENDPOINT
# ============================================================================

@router.post("/DownloadReportPDF")
async def download_report_pdf(request: DownloadReportPDFRequest):
    """
    Generate PDF from HTML content and return as downloadable file.

    Workflow:
    1. Receive HTML content and metadata from frontend
    2. Write HTML to temporary file
    3. Call Node.js Puppeteer script to generate PDF (with retry logic)
    4. Return PDF as file download
    5. Clean up temporary files

    Filename format: {org_name}_{Month Year}_report.pdf
    Example: "Terra-Vaults_December 2025_report.pdf"

    Returns:
        FileResponse with PDF file for download
    """
    temp_pdf_file = None

    try:
        logger.info(f"DownloadReportPDF called for org: {request.organization_name}, month: {request.month_display_name}")
        logger.info(f"HTML content length: {len(request.html_content)} characters")

        # Generate filename
        pdf_filename = generate_pdf_filename(request.organization_name, request.month_display_name)
        logger.info(f"Generated filename: {pdf_filename}")

        # Create temp PDF file path
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            temp_pdf_file = f.name

        logger.info(f"Temp PDF path: {temp_pdf_file}")

        # Generate PDF using Node.js script
        success = await call_node_pdf_generator(request.html_content, temp_pdf_file)

        if not success:
            raise HTTPException(
                status_code=500,
                detail="PDF generation failed after all retry attempts. Please try again."
            )

        # Return PDF as download
        logger.info(f"Returning PDF file: {pdf_filename}")
        return FileResponse(
            path=temp_pdf_file,
            filename=pdf_filename,
            media_type='application/pdf',
            background=None  # File will be kept until response is sent
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error in DownloadReportPDF: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

        # Clean up temp PDF file on error
        if temp_pdf_file and os.path.exists(temp_pdf_file):
            try:
                os.remove(temp_pdf_file)
            except:
                pass

        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF: {str(e)}"
        )


# ============================================================================
# PPTX DOWNLOAD ENDPOINT
# ============================================================================

@router.post("/DownloadPPT")
async def download_report_ppt(request: DownloadReportPDFRequest):
    """
    Generate PPTX from HTML content and return as downloadable file.

    Workflow:
    1. Receive HTML content and metadata from frontend
    2. Generate PDF from HTML (using Node.js Puppeteer)
    3. Convert PDF to PPTX (using ConvertHub API)
    4. Return PPTX as file download
    5. Clean up temporary files

    Filename format: {org_name}_{MonthYear}_report.pptx
    Example: "Terra-Vaults_December2025_report.pptx"

    Returns:
        FileResponse with PPTX file for download
    """
    temp_pdf_file = None
    temp_pptx_file = None

    try:
        logger.info(f"DownloadPPT called for org: {request.organization_name}, month: {request.month_display_name}")
        logger.info(f"HTML content length: {len(request.html_content)} characters")

        # ================================================================
        # Step 1: Generate PDF from HTML
        # ================================================================
        logger.info("Step 1: Generating PDF from HTML...")

        # Create temp PDF file path
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            temp_pdf_file = f.name

        logger.info(f"Temp PDF path: {temp_pdf_file}")

        # Generate PDF using Node.js script
        pdf_success = await call_node_pdf_generator(request.html_content, temp_pdf_file)

        if not pdf_success:
            raise HTTPException(
                status_code=500,
                detail="PDF generation failed. Cannot proceed with PPTX conversion."
            )

        logger.info("✓ PDF generated successfully")

        # ================================================================
        # Step 2: Convert PDF to PPTX
        # ================================================================
        logger.info("Step 2: Converting PDF to PPTX...")

        # Create temp PPTX file path
        with tempfile.NamedTemporaryFile(suffix='.pptx', delete=False) as f:
            temp_pptx_file = f.name

        logger.info(f"Temp PPTX path: {temp_pptx_file}")

        # Convert PDF to PPTX (API key loaded from .env inside function)
        pptx_success = convert_pdf_to_pptx(temp_pdf_file, temp_pptx_file)

        if not pptx_success:
            raise HTTPException(
                status_code=500,
                detail="PPTX conversion failed. Check CONVERTHUB_API_KEY in .env file."
            )

        logger.info("✓ PPTX converted successfully")

        # ================================================================
        # Step 3: Generate filename and return PPTX
        # ================================================================
        pptx_filename = generate_pptx_filename(request.organization_name, request.month_display_name)
        logger.info(f"Returning PPTX file: {pptx_filename}")

        # Return PPTX as download
        return FileResponse(
            path=temp_pptx_file,
            filename=pptx_filename,
            media_type='application/vnd.openxmlformats-officedocument.presentationml.presentation',
            background=None
        )

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Error in DownloadPPT: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PPTX: {str(e)}"
        )
    finally:
        # Clean up temp PDF file (always delete after conversion)
        if temp_pdf_file and os.path.exists(temp_pdf_file):
            try:
                os.remove(temp_pdf_file)
                logger.info(f"Cleaned up temp PDF: {temp_pdf_file}")
            except Exception as e:
                logger.warning(f"Failed to remove temp PDF: {e}")

        # Clean up temp PPTX file on error only
        # On success, FileResponse handles cleanup
        if temp_pptx_file and os.path.exists(temp_pptx_file):
            # Check if we're in error state (exception occurred)
            import sys
            if sys.exc_info()[0] is not None:
                try:
                    os.remove(temp_pptx_file)
                    logger.info(f"Cleaned up temp PPTX after error: {temp_pptx_file}")
                except Exception as e:
                    logger.warning(f"Failed to remove temp PPTX: {e}")
