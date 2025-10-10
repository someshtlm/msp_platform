
from dotenv import load_dotenv
load_dotenv()
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI
import os

# Configure logging
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- FastAPI Application Setup ---
app = FastAPI(
    title="FastAPI Microsoft Graph Client",
    version="2.0.0",
    description="A flexible FastAPI service to query various Microsoft Graph API v1.0 and beta endpoints."
)

# 👇 ADD THIS PART for CORS
origins = [
    "http://localhost:3000",         # frontend dev (React/Vue local)
     "https://d1098e1697d4.ngrok-free.app" # not strictly needed, this is backend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # 👈 allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    """Custom validation error handler for better user experience"""
    error_details = []
    for error in exc.errors():
        field_path = " -> ".join(str(loc) for loc in error["loc"])
        error_details.append({
            "field": field_path,
            "message": error["msg"],
            "invalid_value": error.get("input", "N/A")
        })

    return JSONResponse(
        status_code=422,
        content={
            "error": "Validation failed",
            "status_code": 422,
            "details": error_details,
            "message": "Please check the provided data and try again"
        }
    )


# Import routers from endpoints folder
from endpoints.security_issues import router as security_router
from endpoints.mfa_status import router as mfa_router
from endpoints.license_management import router as license_router
from endpoints.user_details import router as user_router
from endpoints.microsoft_secure_score import router as secure_router
from endpoints.all_complaince_status import router as all_router
from endpoints.complaince_status_post_endpoints import router as post_router
from endpoints.client_management import router as client_router
from endpoints.report_endpoint import router as report_router
from endpoints.cache_test_endpoints import router as cache_test_router



# Include all routers with /api prefix
app.include_router(mfa_router, prefix="/api", tags=["mfa"])
app.include_router(secure_router, prefix="/api", tags=["microsoft secure"])
app.include_router(security_router, prefix="/api", tags=["security"])
app.include_router(all_router, prefix="/api", tags=[ "compliance status get endpoints"])
app.include_router(post_router, prefix="/api", tags=["complaince status post endpoints"])
app.include_router(license_router, prefix="/api", tags=["licenses overview"])
app.include_router(user_router, prefix="/api", tags=["users dashboard"])
app.include_router(client_router, prefix="/api",tags=["client page"])
app.include_router(report_router, prefix="/api", tags=["security reports"])
app.include_router(cache_test_router, prefix="/api", tags=["cache testing"])

# Configure static file serving for PDF reports
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")





