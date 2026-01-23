import os
import httpx


class StellarCyberClient:
    def __init__(self):
        self.base_url = os.getenv("STELLAR_CYBER_BASE_URL")
        api_token = os.getenv("STELLAR_CYBER_API_TOKEN")

        if not self.base_url or not api_token:
            raise ValueError(
                "Missing Stellar Cyber configuration. "
                "Please set STELLAR_CYBER_BASE_URL and STELLAR_CYBER_API_TOKEN."
            )

        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Accept": "application/json",
        }

    async def list_report_configs(self, cust_id: str):
        url = f"{self.base_url}/report-configs"
        params = {"cust_id": cust_id}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()

    async def fetch_report_export(self, report_id: str) -> dict:
        """
        Fetches generated report data for a given report ID.
        NOTE: Will be wired to real API once credentials are available.
        """
        raise NotImplementedError("Report export not wired yet")
