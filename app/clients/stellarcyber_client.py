# app/clients/stellarcyber_client.py

import logging
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class StellarCyberClient:
    """
    Low-level client for interacting with Stellar Cyber REST APIs.

    Responsibilities:
    - Handle authentication
    - Call Stellar Cyber endpoints
    - Return raw responses
    """

    def __init__(self, base_url: str, api_token: str, timeout: int = 30):
        """
        Initialize StellarCyberClient.

        Args:
            base_url: Stellar Cyber platform base URL
                      e.g. https://cyflare.stellarcyber.cloud
            api_token: API token with SOC / report read permissions
            timeout: HTTP timeout in seconds
        """
        if not base_url:
            raise ValueError("Stellar Cyber base_url is required")

        if not api_token:
            raise ValueError("Stellar Cyber api_token is required")

        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }

        logger.info("StellarCyberClient initialized")

    # ------------------------------------------------------------------
    # Report configuration endpoints
    # ------------------------------------------------------------------

    def list_report_configs(self) -> List[Dict[str, Any]]:
        """
        Fetch available report configurations.

        Endpoint:
            GET /connect/api/v1/report-configs

        Returns:
            List of raw report configuration objects
        """
        url = f"{self.base_url}/connect/api/v1/report-config"
        logger.debug(f"Fetching Stellar Cyber report configs: {url}")

        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout
        )

        response.raise_for_status()
        return response.json()

    def get_report_data(self, report_id: str) -> Dict[str, Any]:
        """
        Fetch report data for a given report ID.

        Endpoint:
            GET /connect/api/v1/report-configs/{report_id}/data

        Args:
            report_id: Stellar Cyber report configuration ID

        Returns:
            Raw report data
        """
        if not report_id:
            raise ValueError("report_id is required")

        url = f"{self.base_url}/connect/api/v1/report-config/{report_id}/data"
        logger.debug(f"Fetching Stellar Cyber report data: {url}")

        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout
        )

        response.raise_for_status()
        return response.json()

    def export_report(self, report_id: str) -> Any:
        """
        Export report data for a given report ID.

        Endpoint:
            GET /connect/api/v1/report-configs/{report_id}/export

        Args:
            report_id: Stellar Cyber report configuration ID

        Returns:
            Raw export response (JSON or text depending on API behavior)
        """
        if not report_id:
            raise ValueError("report_id is required")

        url = f"{self.base_url}/connect/api/v1/report-config/{report_id}/export"
        logger.debug(f"Exporting Stellar Cyber report: {url}")

        response = requests.get(
            url,
            headers=self.headers,
            timeout=self.timeout
        )

        response.raise_for_status()

        # Some exports may not be JSON
        try:
            return response.json()
        except ValueError:
            return response.text
