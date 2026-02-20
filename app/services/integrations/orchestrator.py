"""
Security Assessment Orchestrator
Extracted from: security_reporting_system/src/main.py (lines 56-593)

Main orchestrator for security assessment data collection and reporting.
Coordinates data collection from multiple platforms:
- NinjaOne
- Autotask
- ConnectSecure
- Bitdefender
- Cove
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional

# Import processors from new structure
from app.processors.ninjaone_processor import NinjaOneProcessor
from app.processors.autotask_processor import AutotaskProcessor
from app.processors.connectsecure_processor import ConnectSecureProcessor
from app.processors.bitdefender_processor import BitdefenderProcessor
from app.processors.cove_processor import CoveProcessor
from app.processors.sentinelone_processor import SentinelOneProcessor

logger = logging.getLogger(__name__)


# ============================================================================
#                    GLOBAL CACHE VARIABLES
# ============================================================================
# Global cache to prevent duplicate API calls
_ninjaone_cache = None
_autotask_cache = None
_cache_timestamp = None


def _reset_cache():
    """Reset cache for new execution."""
    global _ninjaone_cache, _autotask_cache, _cache_timestamp
    _ninjaone_cache = None
    _autotask_cache = None
    _cache_timestamp = datetime.now()


# ============================================================================
#                    SECURITY ASSESSMENT ORCHESTRATOR CLASS
# ============================================================================
class SecurityAssessmentOrchestrator:
    """Main orchestrator for security assessment data collection and reporting."""

    def __init__(self, account_id: int = None, org_id: int = None, credential_id: str = None):
        """
        Initialize SecurityAssessmentOrchestrator.

        Args:
            account_id: Account ID for fetching credentials from integration_credentials table (NEW)
            org_id: Organization ID for fetching org-specific IDs from organizations table (NEW)
            credential_id: DEPRECATED - Legacy UUID for old user_credentials table
        """
        self.account_id = account_id
        self.org_id = org_id
        self.credential_id = credential_id

        # Store for later initialization with org-specific IDs
        self.ninjaone_processor = None
        self.autotask_processor = None
        self.connectsecure_processor = None
        self.bitdefender_processor = None
        self.cove_processor = None
        self.sentinelone_processor = None

        logger.info(f"SecurityAssessmentOrchestrator initialized with account_id: {account_id}, org_id: {org_id}")

    def _initialize_processors_with_org_id(self):
        """
        NEW: Initialize processors using account_id and org_id from organizations table.
        This is the preferred method for the new credential system.
        """
        from app.core.config.supabase import SupabaseCredentialManager

        if not self.account_id or not self.org_id:
            raise ValueError("Both account_id and org_id are required for new credential system")

        # Fetch organization-specific IDs from organizations table
        credential_manager = SupabaseCredentialManager()
        org_data = credential_manager.get_organization_by_id(self.org_id)

        if not org_data:
            raise ValueError(f"No organization found for org_id: {self.org_id}")

        # Verify account_id matches
        if org_data.get('account_id') != self.account_id:
            raise ValueError(f"Organization {self.org_id} does not belong to account {self.account_id}")

        ninjaone_org_id = org_data.get('ninjaone_org_id')
        autotask_company_id = org_data.get('autotask_id')
        connectsecure_company_id = org_data.get('connectsecure_id')
        bitdefender_company_id = org_data.get('bitdefender_company_id')
        cove_customer_id = org_data.get('cove_customer_id')
        sentinelone_site_id = org_data.get('sentinelone_site_id')

        logger.info(f"Organization: {org_data.get('name', 'Unknown')} (ID: {self.org_id})")
        logger.info(f"  NinjaOne Org ID: {ninjaone_org_id}")
        logger.info(f"  Autotask Company ID: {autotask_company_id}")
        logger.info(f"  ConnectSecure Company ID: {connectsecure_company_id}")
        logger.info(f"  Bitdefender Company ID: {bitdefender_company_id}")
        logger.info(f"  Cove Customer ID: {cove_customer_id}")
        logger.info(f"  SentinelOne Site ID: {sentinelone_site_id}")

        if ninjaone_org_id:
            self.ninjaone_processor = NinjaOneProcessor(
                account_id=self.account_id,
                ninjaone_org_id=ninjaone_org_id
            )
        else:
            logger.warning(f"No NinjaOne org_id found - NinjaOne data will be skipped")
            self.ninjaone_processor = None

        if autotask_company_id:
            self.autotask_processor = AutotaskProcessor(account_id=self.account_id)
        else:
            logger.warning(f"No Autotask company_id found - Autotask data will be skipped")
            self.autotask_processor = None

        if connectsecure_company_id:
            self.connectsecure_processor = ConnectSecureProcessor(
                account_id=self.account_id,
                connectsecure_company_id=connectsecure_company_id
            )
        else:
            logger.warning(f"No ConnectSecure company_id found - ConnectSecure data will be skipped")
            self.connectsecure_processor = None

        if bitdefender_company_id:
            self.bitdefender_processor = BitdefenderProcessor(
                account_id=self.account_id,
                bitdefender_company_id=bitdefender_company_id
            )
        else:
            logger.warning(f"No Bitdefender company_id found - Bitdefender data will be skipped")
            self.bitdefender_processor = None

        if cove_customer_id:
            self.cove_processor = CoveProcessor(
                account_id=self.account_id,
                cove_customer_id=cove_customer_id
            )
        else:
            logger.warning(f"No Cove customer_id found - Cove data will be skipped")
            self.cove_processor = None

        if sentinelone_site_id:
            self.sentinelone_processor = SentinelOneProcessor(
                account_id=self.account_id,
                sentinelone_site_id=sentinelone_site_id
            )
        else:
            logger.warning(f"No SentinelOne site_id found - SentinelOne data will be skipped")
            self.sentinelone_processor = None

        return {
            'ninjaone_org_id': ninjaone_org_id,
            'autotask_company_id': autotask_company_id,
            'connectsecure_company_id': connectsecure_company_id,
            'bitdefender_company_id': bitdefender_company_id,
            'cove_customer_id': cove_customer_id,
            'sentinelone_site_id': sentinelone_site_id,
            'organization_name': org_data.get('name', 'Unknown')
        }

    def _initialize_processors_for_org(self, organization_mapping: Dict[str, Any]):
        """
        DEPRECATED: Initialize processors with organization_mapping (old method).
        Use _initialize_processors_with_org_id() instead.
        """
        ninjaone_org_id = organization_mapping.get('ninjaone_org_id')
        autotask_company_id = organization_mapping.get('autotask_company_id')
        connectsecure_company_id = organization_mapping.get('connectsecure_company_id')

        if self.account_id is not None:
            if ninjaone_org_id:
                self.ninjaone_processor = NinjaOneProcessor(
                    account_id=self.account_id,
                    ninjaone_org_id=ninjaone_org_id
                )
            else:
                logger.warning(f"No NinjaOne org_id found - NinjaOne data will be skipped")
                self.ninjaone_processor = None

            if autotask_company_id:
                self.autotask_processor = AutotaskProcessor(account_id=self.account_id)
            else:
                logger.warning(f"No Autotask company_id found - Autotask data will be skipped")
                self.autotask_processor = None

            if connectsecure_company_id:
                self.connectsecure_processor = ConnectSecureProcessor(
                    account_id=self.account_id,
                    connectsecure_company_id=connectsecure_company_id
                )
            else:
                logger.warning(f"No ConnectSecure company_id found - ConnectSecure data will be skipped")
                self.connectsecure_processor = None

        elif self.credential_id is not None:
            logger.warning("Using DEPRECATED credential_id method. Please migrate to account_id.")
            if ninjaone_org_id:
                self.ninjaone_processor = NinjaOneProcessor(
                    credential_id=self.credential_id,
                    ninjaone_org_id=ninjaone_org_id
                )
            else:
                logger.warning(f"No NinjaOne org_id found - NinjaOne data will be skipped")
                self.ninjaone_processor = None

            if autotask_company_id:
                self.autotask_processor = AutotaskProcessor(credential_id=self.credential_id)
            else:
                logger.warning(f"No Autotask company_id found - Autotask data will be skipped")
                self.autotask_processor = None

            if connectsecure_company_id:
                self.connectsecure_processor = ConnectSecureProcessor(
                    credential_id=self.credential_id,
                    connectsecure_company_id=connectsecure_company_id
                )
            else:
                logger.warning(f"No ConnectSecure company_id found - ConnectSecure data will be skipped")
                self.connectsecure_processor = None

        else:
            raise ValueError("Either account_id or credential_id must be provided")

    async def collect_all_data_with_org_id(self, month_name: str = None) -> Dict[str, Any]:
        """
        NEW: Collect data using account_id and org_id from organizations table.
        This is the preferred method for the new credential system.
        """
        if not self.account_id or not self.org_id:
            raise ValueError("Both account_id and org_id are required")

        # Initialize processors using org_id
        org_info = self._initialize_processors_with_org_id()

        logger.info(f"Processing organization: {org_info['organization_name']} (Org ID: {self.org_id})")

        # Use the autotask_company_id from org_info for data collection
        autotask_company_id = org_info.get('autotask_company_id')

        # Collect data from all platforms
        final_data = await self.collect_all_data(company_id=autotask_company_id, month_name=month_name)

        # Ensure execution_info always has organization_name (even if NinjaOne is not configured)
        if "execution_info" not in final_data:
            final_data["execution_info"] = {
                "organization_id": str(self.org_id),
                "organization_name": org_info['organization_name'],
                "timestamp": datetime.now().isoformat(),
                "data_sources": []
            }
        else:
            # Override with correct org info from database
            final_data["execution_info"]["organization_id"] = str(self.org_id)
            final_data["execution_info"]["organization_name"] = org_info['organization_name']

        return final_data

    async def collect_all_data_for_org(self, ninjaone_org_id: str, month_name: str = None) -> Dict[str, Any]:
        """
        DEPRECATED: Collect data for a specific organization using organization_mapping.
        Use collect_all_data_with_org_id() instead for new credential system.
        """
        from app.services.organizations.service import OrganizationMappingService

        # Get organization mapping
        mapping_service = OrganizationMappingService()
        organization_mapping = mapping_service.get_mapping_by_ninjaone_id(ninjaone_org_id)

        if not organization_mapping:
            raise ValueError(f"No organization mapping found for NinjaOne org ID: {ninjaone_org_id}")

        logger.info(f"Processing organization: {organization_mapping.get('organization_name')} (NinjaOne ID: {ninjaone_org_id})")

        # Initialize processors with organization-specific IDs
        self._initialize_processors_for_org(organization_mapping)

        # Use the autotask_company_id from mapping for data collection
        autotask_company_id = organization_mapping.get('autotask_company_id')

        return await self.collect_all_data(company_id=autotask_company_id, month_name=month_name)

    async def collect_all_data(self, company_id: Optional[int] = None, month_name: str = None) -> Dict[str, Any]:
        """Collect data from all available sources with caching - NOW PARALLEL."""
        global _ninjaone_cache, _autotask_cache, _cache_timestamp
        _ninjaone_cache = None
        _autotask_cache = None
        _cache_timestamp = datetime.now()

        final_data = {}

        async def fetch_ninjaone():
            if not self.ninjaone_processor:
                logger.info("Skipping NinjaOne - not configured")
                return None, None
            logger.info("Fetching NinjaOne data...")
            try:
                raw = await asyncio.to_thread(
                    self.ninjaone_processor.fetch_all_data,
                    use_time_filter=True,
                    month_name=month_name
                )
                logger.info("NinjaOne data fetched successfully")
                return raw, None
            except Exception as e:
                logger.error(f"Failed to fetch NinjaOne data: {e}")
                return None, e

        async def fetch_autotask():
            if not self.autotask_processor:
                logger.info("Skipping Autotask - not configured")
                return None, None
            logger.info("Fetching Autotask data...")
            try:
                raw = await self.autotask_processor.fetch_all_data(company_id, month_name)
                logger.info("Autotask data fetched successfully")
                return raw, None
            except Exception as e:
                logger.warning(f"Failed to fetch Autotask data: {e}")
                return None, e

        async def fetch_connectsecure():
            if not self.connectsecure_processor:
                logger.info("Skipping ConnectSecure - not configured")
                return None, None
            logger.info("Fetching ConnectSecure data...")
            try:
                raw = await asyncio.to_thread(
                    self.connectsecure_processor.fetch_all_data,
                    self.connectsecure_processor.company_id,
                    month_name
                )
                logger.info("ConnectSecure data fetched successfully")
                return raw, None
            except Exception as e:
                logger.warning(f"Failed to fetch ConnectSecure data: {e}")
                return None, e

        async def fetch_bitdefender():
            if not self.bitdefender_processor:
                logger.info("=== SKIPPING BITDEFENDER - NOT CONFIGURED FOR THIS ORG ===")
                return None, None
            logger.info("=== FETCHING BITDEFENDER DATA ===")
            try:
                raw = await asyncio.to_thread(
                    self.bitdefender_processor.fetch_all_data,
                    month_name
                )
                logger.info(f"=== BITDEFENDER DATA FETCHED: {len(raw.get('endpoints_list', []))} endpoints, {len(raw.get('network_inventory', []))} inventory items ===")
                return raw, None
            except Exception as e:
                logger.error(f"=== BITDEFENDER FETCH FAILED: {e} ===")
                import traceback
                logger.error(traceback.format_exc())
                return None, e

        async def fetch_cove():
            if not self.cove_processor:
                logger.info("Skipping Cove - not configured")
                return None, None
            logger.info("Fetching Cove data...")
            try:
                raw = await asyncio.to_thread(
                    self.cove_processor.fetch_all_data,
                    self.cove_processor.customer_id
                )
                logger.info("Cove data fetched successfully")
                return raw, None
            except Exception as e:
                logger.warning(f"Failed to fetch Cove data: {e}")
                return None, e

        async def fetch_sentinelone():
            if not self.sentinelone_processor:
                logger.info("Skipping SentinelOne - not configured")
                return None, None
            logger.info("Fetching SentinelOne data...")
            try:
                raw = await asyncio.to_thread(
                    self.sentinelone_processor.fetch_all_data,
                    month_name
                )
                logger.info(f"SentinelOne data fetched: {len(raw.get('agents', []))} agents, {len(raw.get('threats', []))} threats")
                return raw, None
            except Exception as e:
                logger.error(f"Failed to fetch SentinelOne data: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return None, e

        logger.info("Starting PARALLEL data fetching from all platforms...")

        ninjaone_result, autotask_result, connectsecure_result, bitdefender_result, cove_result, sentinelone_result = await asyncio.gather(
            fetch_ninjaone(),
            fetch_autotask(),
            fetch_connectsecure(),
            fetch_bitdefender(),
            fetch_cove(),
            fetch_sentinelone()
        )

        logger.info("Processing fetched data...")

        ninjaone_raw, ninjaone_error = ninjaone_result
        if ninjaone_raw and not ninjaone_error:
            logger.info("Processing NinjaOne data...")
            ninjaone_processed = self.ninjaone_processor.process_all_data(ninjaone_raw)
            final_data.update(ninjaone_processed)
            _ninjaone_cache = ninjaone_raw
            logger.info("NinjaOne data processed successfully")
        elif ninjaone_error:
            logger.error(f"NinjaOne fetch failed: {ninjaone_error}")

        autotask_raw, autotask_error = autotask_result
        if autotask_raw and not autotask_error:
            logger.info("Processing Autotask data...")
            autotask_processed = self.autotask_processor.process_all_data(autotask_raw, company_id)
            final_data.update(autotask_processed)
            if "execution_info" in final_data:
                final_data["execution_info"]["data_sources"].append("Autotask")
            _autotask_cache = autotask_raw
            logger.info("Autotask data processed successfully")
        elif autotask_error:
            logger.warning(f"Autotask fetch failed: {autotask_error}")
            logger.info("Continuing without Autotask data...")

        connectsecure_raw, connectsecure_error = connectsecure_result
        if connectsecure_raw and not connectsecure_error:
            if len(connectsecure_raw.get('assets', [])) > 0:
                logger.info("Processing ConnectSecure data...")
                connectsecure_processed = self.connectsecure_processor.process_all_data(connectsecure_raw, month_name=month_name)
                final_data.update(connectsecure_processed)
                if "execution_info" in final_data:
                    final_data["execution_info"]["data_sources"].append("ConnectSecure")
                logger.info("ConnectSecure data processed successfully")
            else:
                logger.warning("ConnectSecure: No assets found")
        elif connectsecure_error:
            logger.warning(f"ConnectSecure fetch failed: {connectsecure_error}")
            logger.info("Continuing with available data sources...")

        bitdefender_raw, bitdefender_error = bitdefender_result
        if bitdefender_raw and not bitdefender_error:
            logger.info("=== PROCESSING BITDEFENDER DATA ===")
            bitdefender_processed = self.bitdefender_processor.process_all_data(bitdefender_raw)
            logger.info(f"=== BITDEFENDER PROCESSED DATA KEYS: {list(bitdefender_processed.keys())} ===")
            final_data.update(bitdefender_processed)
            if "execution_info" in final_data:
                final_data["execution_info"]["data_sources"].append("Bitdefender")
            logger.info("=== BITDEFENDER DATA ADDED TO FINAL OUTPUT ===")
        elif bitdefender_error:
            logger.error(f"=== BITDEFENDER FETCH FAILED: {bitdefender_error} ===")
            logger.info("Continuing with available data sources...")
        else:
            logger.info("=== BITDEFENDER: NO DATA (PROCESSOR NOT CONFIGURED) ===")

        cove_raw, cove_error = cove_result
        if cove_raw and not cove_error:
            logger.info("Processing Cove data...")
            cove_processed = self.cove_processor.process_all_data(cove_raw)
            final_data.update(cove_processed)
            if "execution_info" in final_data:
                final_data["execution_info"]["data_sources"].append("Cove")
            logger.info("Cove data processed successfully")
        elif cove_error:
            logger.warning(f"Cove fetch failed: {cove_error}")
            logger.info("Continuing with available data sources...")

        sentinelone_raw, sentinelone_error = sentinelone_result
        if sentinelone_raw and not sentinelone_error:
            logger.info("Processing SentinelOne data...")
            sentinelone_processed = self.sentinelone_processor.process_all_data(sentinelone_raw)
            final_data.update(sentinelone_processed)
            if "execution_info" in final_data:
                final_data["execution_info"]["data_sources"].append("SentinelOne")
            logger.info("SentinelOne data processed successfully")
        elif sentinelone_error:
            logger.error(f"SentinelOne fetch failed: {sentinelone_error}")
            logger.info("Continuing with available data sources...")

        return final_data

    async def stream_data_per_platform(self, company_id: Optional[int] = None, month_name: str = None):
        """
        Async generator that yields each platform's data as it completes.
        All platforms run in PARALLEL, but results are yielded one-by-one as each finishes.
        Heartbeats are sent every 10 seconds to keep the connection alive.

        Yields:
            dict with keys: type, platform (optional), data (optional), progress, message (optional)
        """
        global _ninjaone_cache, _autotask_cache, _cache_timestamp
        _ninjaone_cache = None
        _autotask_cache = None
        _cache_timestamp = datetime.now()

        data_sources = []
        platforms_done = 0
        total_platforms = sum(1 for p in [
            self.ninjaone_processor, self.autotask_processor,
            self.connectsecure_processor, self.bitdefender_processor,
            self.cove_processor, self.sentinelone_processor
        ] if p is not None)

        if total_platforms == 0:
            yield {"type": "error", "message": "No platforms configured", "progress": 0}
            return

        # Map platform name to its fetch+process coroutine
        async def fetch_and_process_ninjaone():
            if not self.ninjaone_processor:
                return None
            raw = await asyncio.to_thread(
                self.ninjaone_processor.fetch_all_data,
                use_time_filter=True,
                month_name=month_name
            )
            processed = self.ninjaone_processor.process_all_data(raw)
            _ninjaone_cache = raw
            return processed

        async def fetch_and_process_autotask():
            if not self.autotask_processor:
                return None
            raw = await self.autotask_processor.fetch_all_data(company_id, month_name)
            processed = self.autotask_processor.process_all_data(raw, company_id)
            _autotask_cache = raw
            return processed

        async def fetch_and_process_connectsecure():
            if not self.connectsecure_processor:
                return None
            raw = await asyncio.to_thread(
                self.connectsecure_processor.fetch_all_data,
                self.connectsecure_processor.company_id,
                month_name
            )
            if len(raw.get('assets', [])) == 0:
                logger.warning("ConnectSecure: No assets found")
                return None
            processed = self.connectsecure_processor.process_all_data(raw, month_name=month_name)
            return processed

        async def fetch_and_process_bitdefender():
            if not self.bitdefender_processor:
                return None
            raw = await asyncio.to_thread(
                self.bitdefender_processor.fetch_all_data,
                month_name
            )
            processed = self.bitdefender_processor.process_all_data(raw)
            return processed

        async def fetch_and_process_cove():
            if not self.cove_processor:
                return None
            raw = await asyncio.to_thread(
                self.cove_processor.fetch_all_data,
                self.cove_processor.customer_id
            )
            processed = self.cove_processor.process_all_data(raw)
            return processed

        async def fetch_and_process_sentinelone():
            if not self.sentinelone_processor:
                return None
            raw = await asyncio.to_thread(
                self.sentinelone_processor.fetch_all_data,
                month_name
            )
            processed = self.sentinelone_processor.process_all_data(raw)
            return processed

        # Create named tasks for all configured platforms
        tasks = {}
        if self.ninjaone_processor:
            tasks["NinjaOne"] = asyncio.create_task(fetch_and_process_ninjaone())
        if self.autotask_processor:
            tasks["Autotask"] = asyncio.create_task(fetch_and_process_autotask())
        if self.connectsecure_processor:
            tasks["ConnectSecure"] = asyncio.create_task(fetch_and_process_connectsecure())
        if self.bitdefender_processor:
            tasks["Bitdefender"] = asyncio.create_task(fetch_and_process_bitdefender())
        if self.cove_processor:
            tasks["Cove"] = asyncio.create_task(fetch_and_process_cove())
        if self.sentinelone_processor:
            tasks["SentinelOne"] = asyncio.create_task(fetch_and_process_sentinelone())

        logger.info(f"Started {len(tasks)} platform tasks in parallel: {list(tasks.keys())}")

        # Poll tasks every 2 seconds, send heartbeat every 10 seconds
        heartbeat_interval = 10
        last_heartbeat = asyncio.get_event_loop().time()
        completed_platforms = set()

        while len(completed_platforms) < len(tasks):
            # Check each task
            for platform_name, task in tasks.items():
                if platform_name in completed_platforms:
                    continue
                if task.done():
                    completed_platforms.add(platform_name)
                    platforms_done += 1
                    progress = int((platforms_done / total_platforms) * 85) + 10  # 10-95 range

                    try:
                        result = task.result()
                        if result:
                            data_sources.append(platform_name)
                            yield {
                                "type": "platform_data",
                                "platform": platform_name,
                                "data": result,
                                "progress": progress
                            }
                            logger.info(f"Streamed {platform_name} data (progress: {progress}%)")
                        else:
                            yield {
                                "type": "error",
                                "platform": platform_name,
                                "message": f"{platform_name}: No data available",
                                "progress": progress
                            }
                    except Exception as e:
                        logger.error(f"{platform_name} fetch failed: {e}")
                        yield {
                            "type": "error",
                            "platform": platform_name,
                            "message": f"{platform_name} failed: {str(e)}",
                            "progress": progress
                        }

            # Send heartbeat every 10 seconds if not all done
            if len(completed_platforms) < len(tasks):
                now = asyncio.get_event_loop().time()
                if now - last_heartbeat >= heartbeat_interval:
                    pending = [p for p in tasks if p not in completed_platforms]
                    yield {
                        "type": "heartbeat",
                        "progress": int((platforms_done / total_platforms) * 85) + 10,
                        "message": f"Waiting for: {', '.join(pending)}"
                    }
                    last_heartbeat = now
                await asyncio.sleep(2)  # Poll every 2 seconds

        # Yield data_sources list for execution_info
        yield {
            "type": "stream_done",
            "data_sources": data_sources,
            "progress": 95
        }

    async def test_all_connections(self) -> Dict[str, bool]:
        """Test connectivity to all data sources."""
        results = {}

        if self.ninjaone_processor:
            try:
                org_info = self.ninjaone_processor.client.get_organization_info()
                results['ninjaone'] = bool(org_info.get('id'))
            except Exception as e:
                logger.error(f"NinjaOne connection test failed: {e}")
                results['ninjaone'] = False
        else:
            results['ninjaone'] = False

        if self.autotask_processor:
            try:
                results['autotask'] = await self.autotask_processor.test_connection()
            except Exception as e:
                logger.error(f"Autotask connection test failed: {e}")
                results['autotask'] = False
        else:
            results['autotask'] = False

        if self.connectsecure_processor:
            try:
                results['connectsecure'] = self.connectsecure_processor.test_connection()
            except Exception as e:
                logger.error(f"ConnectSecure connection test failed: {e}")
                results['connectsecure'] = False
        else:
            results['connectsecure'] = False

        if self.cove_processor:
            try:
                results['cove'] = self.cove_processor.test_connection()
            except Exception as e:
                logger.error(f"Cove connection test failed: {e}")
                results['cove'] = False
        else:
            results['cove'] = False

        return results
