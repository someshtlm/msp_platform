"""
Raw Data Fetcher for All Endpoints
Shows the exact JSON responses from all API endpoints for debugging
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

# Import all clients
try:
    from clients.ninjaone_client import NinjaOneAPIClient
    from clients.autotask_client import AutotaskClient, AutotaskConfig
    from clients.connectsecure_client import ConnectSecureClient
except ImportError:
    from src.clients.ninjaone_client import NinjaOneAPIClient
    from src.clients.autotask_client import AutotaskClient, AutotaskConfig
    from src.clients.connectsecure_client import ConnectSecureClient

# Import config
try:
    from security_reporting_system.config.config import config_manager
except ImportError:
    try:
        from config.config import config_manager
    except ImportError:
        from ..config.config import config_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RawDataFetcher:
    """Fetches raw data from all endpoints and organizes by client."""

    def __init__(self, credential_id: str = None):
        self.credential_id = credential_id
        self.config = config_manager.load_credentials(credential_id)

    async def fetch_all_raw_data(self,
                                ninjaone_org_id: str = "41",
                                autotask_company_id: int = None,
                                connectsecure_company_id: str = None,
                                month_name: str = "August") -> Dict[str, Any]:
        """Fetch raw data from all endpoints."""

        raw_data = {
            "timestamp": datetime.now().isoformat(),
            "parameters": {
                "ninjaone_org_id": ninjaone_org_id,
                "autotask_company_id": autotask_company_id,
                "connectsecure_company_id": connectsecure_company_id,
                "month_name": month_name
            },
            "NinjaOne": {},
            "Autotask": {},
            "ConnectSecure": {}
        }

        # Fetch NinjaOne raw data
        raw_data["NinjaOne"] = await self._fetch_ninjaone_raw(ninjaone_org_id, month_name)

        # Fetch Autotask raw data
        if autotask_company_id:
            raw_data["Autotask"] = await self._fetch_autotask_raw(autotask_company_id, month_name)

        # Fetch ConnectSecure raw data
        if connectsecure_company_id:
            raw_data["ConnectSecure"] = await self._fetch_connectsecure_raw(connectsecure_company_id, month_name)

        return raw_data

    async def _fetch_ninjaone_raw(self, org_id: str, month_name: str) -> Dict[str, Any]:
        """Fetch all NinjaOne raw endpoint data."""
        ninjaone_data = {}

        try:
            # Initialize NinjaOne client
            ninja_client = NinjaOneAPIClient(
                client_id=self.config['ninjaone_client_id'],
                client_secret=self.config['ninjaone_client_secret'],
                instance_url=self.config['ninjaone_instance_url'],
                org_id=org_id
            )

            # Fetch from all NinjaOne endpoints
            endpoints = {
                "devices": "get_devices",
                "os_patch_installs": "get_os_patch_installs",
                "software_patch_installs": "get_software_patch_installs",
                "os_patches": "get_os_patches",
                "software_patches": "get_software_patches",
                "queries": "get_queries",
                "activities": "get_activities"
            }

            for endpoint_name, method_name in endpoints.items():
                try:
                    logger.info(f"Fetching NinjaOne {endpoint_name}...")
                    method = getattr(ninja_client, method_name)

                    # Add month filtering for supported endpoints
                    if endpoint_name in ["activities", "os_patch_installs", "software_patch_installs"]:
                        raw_response = method(month_name=month_name)
                    else:
                        raw_response = method()

                    ninjaone_data[endpoint_name] = {
                        "count": len(raw_response) if isinstance(raw_response, list) else 1,
                        "sample_record": raw_response[0] if isinstance(raw_response, list) and raw_response else raw_response,
                        "raw_data": raw_response
                    }
                    logger.info(f"✅ NinjaOne {endpoint_name}: {ninjaone_data[endpoint_name]['count']} records")

                except Exception as e:
                    ninjaone_data[endpoint_name] = {"error": str(e)}
                    logger.error(f"❌ NinjaOne {endpoint_name} failed: {e}")

        except Exception as e:
            ninjaone_data["connection_error"] = str(e)
            logger.error(f"❌ NinjaOne connection failed: {e}")

        return ninjaone_data

    async def _fetch_autotask_raw(self, company_id: int, month_name: str) -> Dict[str, Any]:
        """Fetch all Autotask raw endpoint data."""
        autotask_data = {}

        try:
            # Initialize Autotask client
            autotask_config = AutotaskConfig(
                username=self.config['autotask_username'],
                secret=self.config['autotask_secret'],
                integration_code=self.config['autotask_integration_code'],
                base_url=self.config['autotask_base_url']
            )

            async with AutotaskClient(autotask_config) as autotask_client:
                # Fetch from all Autotask endpoints
                endpoints = {
                    "tickets": ("get_tickets", {"month_name": month_name}),
                    "companies": ("get_companies", {}),
                    "contacts": ("get_contacts", {"company_id": company_id}),
                    "slo_metrics": ("get_slo_metrics", {"company_id": company_id, "month_name": month_name})
                }

                for endpoint_name, (method_name, params) in endpoints.items():
                    try:
                        logger.info(f"Fetching Autotask {endpoint_name}...")
                        method = getattr(autotask_client, method_name)

                        if params:
                            raw_response = await method(**params)
                        else:
                            raw_response = await method()

                        autotask_data[endpoint_name] = {
                            "count": len(raw_response) if isinstance(raw_response, list) else 1,
                            "sample_record": raw_response[0] if isinstance(raw_response, list) and raw_response else raw_response,
                            "raw_data": raw_response
                        }
                        logger.info(f"✅ Autotask {endpoint_name}: {autotask_data[endpoint_name]['count']} records")

                    except Exception as e:
                        autotask_data[endpoint_name] = {"error": str(e)}
                        logger.error(f"❌ Autotask {endpoint_name} failed: {e}")

        except Exception as e:
            autotask_data["connection_error"] = str(e)
            logger.error(f"❌ Autotask connection failed: {e}")

        return autotask_data

    async def _fetch_connectsecure_raw(self, company_id: str, month_name: str) -> Dict[str, Any]:
        """Fetch all ConnectSecure raw endpoint data."""
        connectsecure_data = {}

        try:
            # Initialize ConnectSecure client
            connectsecure_client = ConnectSecureClient(credential_id=self.credential_id)

            # Fetch from all ConnectSecure endpoints
            endpoints = {
                # Month-filtered endpoints
                "asset_view_data": ("get_asset_view_data", {"company_id": company_id, "month_name": month_name}),
                "risk_score": ("get_risk_score", {"company_id": company_id, "month_name": month_name}),
                "agents_monthly": ("get_agents_monthly", {"company_id": company_id, "month_name": month_name}),

                # Non-month-filtered endpoints
                "total_asset_count": ("get_total_asset_count", {"company_id": company_id}),
                "assets_by_company": ("get_assets_by_company", {"company_id": company_id}),
                "asset_view": ("get_asset_view", {"company_id": company_id}),
                "agents": ("get_agents", {"company_id": company_id}),
                "vulnerabilities_count": ("get_vulnerabilities_count", {"company_id": company_id})
            }

            for endpoint_name, (method_name, params) in endpoints.items():
                try:
                    logger.info(f"Fetching ConnectSecure {endpoint_name}...")
                    method = getattr(connectsecure_client, method_name)

                    raw_response = method(**params)

                    connectsecure_data[endpoint_name] = {
                        "count": len(raw_response) if isinstance(raw_response, list) else 1,
                        "sample_record": raw_response[0] if isinstance(raw_response, list) and raw_response else raw_response,
                        "raw_data": raw_response
                    }
                    logger.info(f"✅ ConnectSecure {endpoint_name}: {connectsecure_data[endpoint_name]['count']} records")

                except Exception as e:
                    connectsecure_data[endpoint_name] = {"error": str(e)}
                    logger.error(f"❌ ConnectSecure {endpoint_name} failed: {e}")

        except Exception as e:
            connectsecure_data["connection_error"] = str(e)
            logger.error(f"❌ ConnectSecure connection failed: {e}")

        return connectsecure_data


async def main():
    """Main function to fetch and save raw data."""

    # Configuration - UPDATE THESE VALUES
    CREDENTIAL_ID = "4ffdf31a-9ea7-4962-a8ff-4ef440c793f3"
    NINJAONE_ORG_ID = "29"  # Safequip org ID
    AUTOTASK_COMPANY_ID = 29956  # Safequip company ID
    CONNECTSECURE_COMPANY_ID = "6376"  # Safequip ConnectSecure ID
    MONTH_NAME = "August"

    print("🔍 Starting Raw Data Fetch...")
    print(f"Parameters: NinjaOne={NINJAONE_ORG_ID}, Autotask={AUTOTASK_COMPANY_ID}, ConnectSecure={CONNECTSECURE_COMPANY_ID}, Month={MONTH_NAME}")

    # Initialize fetcher
    fetcher = RawDataFetcher(credential_id=CREDENTIAL_ID)

    # Fetch all raw data
    all_raw_data = await fetcher.fetch_all_raw_data(
        ninjaone_org_id=NINJAONE_ORG_ID,
        autotask_company_id=AUTOTASK_COMPANY_ID,
        connectsecure_company_id=CONNECTSECURE_COMPANY_ID,
        month_name=MONTH_NAME
    )

    # Save to file
    output_file = f"raw_data_dump_{MONTH_NAME}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_raw_data, f, indent=2, ensure_ascii=False, default=str)

        print(f"✅ Raw data saved to: {output_file}")
        print(f"📊 Summary:")
        print(f"   NinjaOne endpoints: {len(all_raw_data.get('NinjaOne', {}))}")
        print(f"   Autotask endpoints: {len(all_raw_data.get('Autotask', {}))}")
        print(f"   ConnectSecure endpoints: {len(all_raw_data.get('ConnectSecure', {}))}")

    except Exception as e:
        print(f"❌ Failed to save raw data: {e}")


if __name__ == "__main__":
    asyncio.run(main())