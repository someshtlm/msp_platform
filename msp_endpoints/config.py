# --- Configuration ---
# Configure logging to provide visibility into the application's operations
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Microsoft Graph configuration - these remain constant across tenants
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_V1_URL = "https://graph.microsoft.com/v1.0"
GRAPH_BETA_URL = "https://graph.microsoft.com/beta"
