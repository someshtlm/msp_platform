"""
Refactored Main Entry Point

"""

import json
import logging
import asyncio
import argparse
from datetime import datetime
from typing import Dict, Any, Optional

# Add parent directory to path for local running
import sys
import os
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Smart imports - try absolute first (for msp_endpoints), fallback to relative (for standalone)
try:
    from security_reporting_system.src.processors.ninjaone_processor import NinjaOneProcessor
    from security_reporting_system.src.processors.autotask_processor import AutotaskProcessor
    from security_reporting_system.src.processors.connectsecure_processor import ConnectSecureProcessor
    from security_reporting_system.src.processors.bitdefender_processor import BitdefenderProcessor
    from security_reporting_system.src.processors.cove_processor import CoveProcessor
    from security_reporting_system.src.utils.frontend_transformer import FrontendTransformer
except ImportError:
    from src.processors.ninjaone_processor import NinjaOneProcessor
    from src.processors.autotask_processor import AutotaskProcessor
    from src.processors.connectsecure_processor import ConnectSecureProcessor
    from src.processors.bitdefender_processor import BitdefenderProcessor
    from src.processors.cove_processor import CoveProcessor
    from src.utils.frontend_transformer import FrontendTransformer

# Import PDF report generator - UNCHANGED
try:
    from security_reporting_system.src.reports.pdf_report_generator import generate_security_report
    PDF_AVAILABLE = True
except ImportError:
    try:
        from src.reports.pdf_report_generator import generate_security_report
        PDF_AVAILABLE = True
    except ImportError as e:
        PDF_AVAILABLE = False
        print(f"PDF dependencies not available: {e}")

# Configure logging for production use
logging.basicConfig(
    level=logging.WARNING,  # Only show warnings and errors
    format='%(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


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

def fetch_ninjaone_data(ninja_client=None, use_time_filter: bool = True, month_name: str = None) -> Dict[str, Any]:
    """
    Backward compatibility wrapper for PDF generator with caching.
    Uses the new NinjaOneProcessor internally.

    NOTE: Cache is disabled for PDF generation to ensure each organization gets fresh data.
    """
    global _ninjaone_cache

    # Get organization ID from client for cache key
    org_id = getattr(ninja_client, 'org_id', 'unknown') if ninja_client else 'default'
    cache_key = f"{org_id}_{month_name or 'default'}"

    # DISABLED CACHING for PDF generation to prevent cross-organization data contamination
    logger.debug(f"🔄 Fetching fresh NinjaOne data for org {org_id}, month: {month_name or 'default'}")

    if ninja_client:
        # Extract org_id from the ninja_client to ensure processor uses correct organization
        org_id = getattr(ninja_client, 'org_id', None)
        processor = NinjaOneProcessor(ninjaone_org_id=org_id)
        processor.client = ninja_client  # Use the same client instance
        _ninjaone_cache = processor.fetch_all_data(use_time_filter=use_time_filter, month_name=month_name)
        logger.debug(f"✅ Used ninja_client with org_id: {org_id}")
    else:
        processor = NinjaOneProcessor()
        _ninjaone_cache = processor.fetch_all_data(use_time_filter=use_time_filter, month_name=month_name)
        logger.debug("✅ Used default processor configuration")

    logger.debug("✅ NinjaOne data fetched fresh (no caching)")
    return _ninjaone_cache

async def fetch_autotask_data(autotask_client=None, company_id: Optional[int] = None, month_name: str = None) -> Dict[str, Any]:
    """
    Backward compatibility wrapper for PDF generator with caching.
    Uses the new AutotaskProcessor internally.

    NOTE: Cache is disabled for PDF generation to ensure each organization gets fresh data.
    """
    global _autotask_cache

    # DISABLED CACHING for PDF generation to prevent cross-organization data contamination
    logger.debug(f"🔄 Fetching fresh Autotask data for company {company_id}")

    processor = AutotaskProcessor()
    _autotask_cache = await processor.fetch_all_data(company_id=company_id, month_name=month_name)
    logger.debug("✅ Autotask data fetched fresh (no caching)")

    return _autotask_cache


def generate_final_output(ninja_data: Dict[str, Any], autotask_data: Optional[Dict[str, Any]] = None, month_name: str = None, connectsecure_company_id: str = None) -> Dict[str, Any]:

    print("🔍 DEBUG: generate_final_output called")

    # Process NinjaOne data
    ninjaone_processor = NinjaOneProcessor()
    final_output = ninjaone_processor.process_all_data(ninja_data)

    # Process Autotask data if available
    if autotask_data:
        autotask_processor = AutotaskProcessor()
        autotask_processed = autotask_processor.process_all_data(autotask_data)
        final_output.update(autotask_processed)

    # ADDED: Process ConnectSecure data
    if connectsecure_company_id:
        try:
            print(f"🔍 DEBUG: Adding ConnectSecure data for company {connectsecure_company_id}")
            connectsecure_processor = ConnectSecureProcessor(connectsecure_company_id=connectsecure_company_id)

            # Fetch ConnectSecure data using the working endpoint with month filtering
            connectsecure_raw = connectsecure_processor.fetch_all_data(connectsecure_company_id, month_name)

            if len(connectsecure_raw.get('assets', [])) > 0:
                # Process the ConnectSecure data with month filtering
                connectsecure_processed = connectsecure_processor.process_all_data(connectsecure_raw, month_name=month_name)

                # Add to final output
                final_output.update(connectsecure_processed)

                print(f"🔍 DEBUG: ConnectSecure data added - {len(connectsecure_raw.get('assets', []))} assets")
                print(f"🔍 DEBUG: Final output now has keys: {list(final_output.keys())}")
            else:
                print("🔍 DEBUG: No ConnectSecure assets found")

        except Exception as e:
            print(f"🔍 DEBUG: ConnectSecure processing failed for company {connectsecure_company_id}: {e}")
            # Don't fail the entire report if ConnectSecure fails
            pass
    else:
        print("🔍 DEBUG: No ConnectSecure company_id provided, skipping ConnectSecure data")

    return final_output

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

        logger.info(f"SecurityAssessmentOrchestrator initialized with account_id: {account_id}, org_id: {org_id}")

    def _initialize_processors_with_org_id(self):
        """
        NEW: Initialize processors using account_id and org_id from organizations table.
        This is the preferred method for the new credential system.
        """
        try:
            from security_reporting_system.config.supabase_client import SupabaseCredentialManager
        except ImportError:
            from config.supabase_client import SupabaseCredentialManager

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

        logger.info(f"Organization: {org_data.get('name', 'Unknown')} (ID: {self.org_id})")
        logger.info(f"  NinjaOne Org ID: {ninjaone_org_id}")
        logger.info(f"  Autotask Company ID: {autotask_company_id}")
        logger.info(f"  ConnectSecure Company ID: {connectsecure_company_id}")
        logger.info(f"  Bitdefender Company ID: {bitdefender_company_id}")
        logger.info(f"  Cove Customer ID: {cove_customer_id}")

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

        return {
            'ninjaone_org_id': ninjaone_org_id,
            'autotask_company_id': autotask_company_id,
            'connectsecure_company_id': connectsecure_company_id,
            'bitdefender_company_id': bitdefender_company_id,
            'cove_customer_id': cove_customer_id,
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

        return await self.collect_all_data(company_id=autotask_company_id, month_name=month_name)

    async def collect_all_data_for_org(self, ninjaone_org_id: str, month_name: str = None) -> Dict[str, Any]:
        """
        DEPRECATED: Collect data for a specific organization using organization_mapping.
        Use collect_all_data_with_org_id() instead for new credential system.
        """
        try:
            from security_reporting_system.src.services.organization_service import OrganizationMappingService
        except ImportError:
            from .services.organization_service import OrganizationMappingService

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

        logger.info("Starting PARALLEL data fetching from all platforms...")

        ninjaone_result, autotask_result, connectsecure_result, bitdefender_result, cove_result = await asyncio.gather(
            fetch_ninjaone(),
            fetch_autotask(),
            fetch_connectsecure(),
            fetch_bitdefender(),
            fetch_cove()
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

        return final_data

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


async def main() -> None:
    """Main execution function with command-line arguments."""
    parser = argparse.ArgumentParser(description='IT Security Assessment Data Collection and Reporting')
    parser.add_argument('--output', choices=['json', 'pdf', 'both', 'frontend'], default='json',
                        help='Output format: json (full), frontend (optimized), pdf, both (default: json)')
    parser.add_argument('--account-id', type=int,
                        help='NEW: Account ID for fetching credentials from integration_credentials table')
    parser.add_argument('--org-id', type=int,
                        help='NEW: Organization ID for fetching org-specific IDs from organizations table')
    parser.add_argument('--ninjaone-org-id', type=str, default='41',
                        help='[DEPRECATED] NinjaOne Organization ID for report generation. Use --org-id instead.')
    parser.add_argument('--company-id', type=int, default=625,
                        help='[DEPRECATED] Autotask company ID for filtering (use --org-id instead)')
    parser.add_argument('--filename', type=str,
                        help='Custom filename for PDF output')
    parser.add_argument('--credential-id', type=str, default='4ffdf31a-9ea7-4962-a8ff-4ef440c793f3',
                        help='[DEPRECATED] Credential ID for Supabase lookup. Use --account-id instead.')
    parser.add_argument('--month', type=str,
                        help='Specific month for report generation in month_year format (e.g., "november_2024", "december_2024"). Defaults to previous month')
    parser.add_argument('--list-months', action='store_true',
                        help='List available months for report generation and exit')
    parser.add_argument('--test-connections', action='store_true',
                        help='Test connectivity to all data sources and exit')

    args = parser.parse_args()

    # Handle month listing
    if args.list_months:
        try:
            from security_reporting_system.src.utils.month_selector import MonthSelector
        except ImportError:
            from src.utils.month_selector import MonthSelector
        month_selector = MonthSelector()
        available_months = month_selector.list_available_months()

        print("\n=== Available Months for Report Generation ===")
        for month in available_months:
            month_lowercase = month['name'].lower()
            month_year_format = f"{month_lowercase}_{month['year']}"
            print(f"  • {month['display_name']} (use --month \"{month_year_format}\")")
        print("\nExample usage:")
        print("  python src/main.py --month \"november_2024\" --output pdf")
        return

    # Handle connection testing
    if args.test_connections:
        try:
            # Initialize orchestrator with account_id/org_id or credential_id
            orchestrator = SecurityAssessmentOrchestrator(
                account_id=args.account_id,
                org_id=args.org_id,
                credential_id=args.credential_id
            )

            logger.info("Testing connections to all data sources...")
            results = await orchestrator.test_all_connections()

            print("\n=== Connection Test Results ===")
            for service, status in results.items():
                status_icon = "✅" if status else "❌"
                print(f"{status_icon} {service.title()}: {'Connected' if status else 'Failed'}")

            overall_status = all(results.values())
            print(f"\n Overall Status: {'All systems operational' if overall_status else 'Some connections failed'}")

            # Provide specific guidance for failed connections
            if not overall_status:
                print("\n Troubleshooting failed connections:")
                if not results.get('ninjaone', True):
                    print("   • NinjaOne: Check credentials in Supabase for ID:", args.credential_id)
                if not results.get('autotask', True):
                    print("   • Autotask: Verify credentials in Supabase for ID:", args.credential_id)
                if not results.get('connectsecure', True):
                    print("   • ConnectSecure: Check credentials in Supabase for ID:", args.credential_id)

            return

        except ValueError as e:
            print(f"Configuration Error: {e}")
            print("Please ensure credentials exist in Supabase for ID:", args.credential_id)
            return
        except Exception as e:
            print(f"Connection test failed: {e}")
            return

    try:
        # Initialize orchestrator with account_id/org_id or credential_id
        try:
            orchestrator = SecurityAssessmentOrchestrator(
                account_id=args.account_id,
                org_id=args.org_id,
                credential_id=args.credential_id
            )
        except ValueError as e:
            print(f"Configuration Error: {e}")
            if args.account_id or args.org_id:
                print("Please ensure both account_id and org_id are provided, or use credential_id for legacy mode")
            else:
                print("Please ensure credentials exist in Supabase for ID:", args.credential_id)
            return
        except Exception as e:
            print(f"Initialization Error: {e}")
            return

        # Collect all data
        logger.info("Starting comprehensive security assessment data collection...")
        start_time = datetime.now()

        # NEW: Use account_id and org_id if both are provided
        if args.account_id and args.org_id:
            logger.info(f"✅ Using NEW credential system: account_id={args.account_id}, org_id={args.org_id}")
            final_output = await orchestrator.collect_all_data_with_org_id(args.month)
        # OLD: Fallback to ninjaone_org_id method
        else:
            logger.warning("⚠️ Using DEPRECATED ninjaone_org_id method. Please migrate to --account-id and --org-id.")
            final_output = await orchestrator.collect_all_data_for_org(args.ninjaone_org_id, args.month)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Add execution metadata
        final_output["execution_info"]["duration_seconds"] = round(duration, 2)
        final_output["execution_info"]["start_time"] = start_time.isoformat()
        final_output["execution_info"]["end_time"] = end_time.isoformat()

        # Output based on requested format
        if args.output in ['json', 'both']:
            json_output = json.dumps(final_output, indent=2, default=str)
            print(json_output)  # Still print to console

            # Save JSON to file in output directory
            os.makedirs('output', exist_ok=True)

            # Generate JSON filename with timestamp and organization
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            org_identifier = f"org{args.org_id}" if args.org_id else args.ninjaone_org_id
            json_filename = f"output/security_report_{org_identifier}_{timestamp}.json"

            with open(json_filename, 'w', encoding='utf-8') as f:
                f.write(json_output)

            print(f"\nJSON report saved: {json_filename}")

        if args.output == 'frontend':
            logger.info("Generating frontend-optimized JSON...")

            # Convert month parameter to "November 2024" format for reporting_period
            reporting_period = None
            if args.month:
                try:
                    parts = args.month.split('_')
                    month_name = parts[0].capitalize()
                    year = parts[1]
                    reporting_period = f"{month_name} {year}"
                except:
                    pass

            transformer = FrontendTransformer()
            frontend_json = transformer.transform_to_frontend_json(
                final_output,
                account_id=args.account_id,
                reporting_period=reporting_period
            )

            frontend_output = json.dumps(frontend_json, indent=2, default=str)
            print(frontend_output)  # Print to console

            # Save frontend JSON to file
            os.makedirs('output', exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            org_identifier = f"org{args.org_id}" if args.org_id else args.ninjaone_org_id
            frontend_filename = f"output/frontend_report_{org_identifier}_{timestamp}.json"

            with open(frontend_filename, 'w', encoding='utf-8') as f:
                f.write(frontend_output)

            print(f"\nFrontend JSON report saved: {frontend_filename}")

            # Print summary statistics
            print(f"Data sources included: {', '.join(frontend_json.get('summary', {}).get('data_sources', []))}")
            print(f"Total devices: {frontend_json.get('summary', {}).get('total_devices', 0)}")
            print(f"Security risk score: {frontend_json.get('summary', {}).get('security_risk_score', 0)}")
            print(f"Patch compliance: {frontend_json.get('summary', {}).get('patch_compliance_percentage', 0)}%")

        if args.output in ['pdf', 'both'] and PDF_AVAILABLE:
            logger.info("Generating comprehensive PDF report...")
            # Pass account_id if available, otherwise fall back to credential_id
            filename = await generate_security_report(
                ninjaone_org_id=args.ninjaone_org_id,
                filename=args.filename,
                account_id=args.account_id,
                credential_id=args.credential_id,
                month_name=args.month
            )
            print(f"\nPDF report generated: {filename}")

            # Print summary of data included
            data_sources = final_output.get("execution_info", {}).get("data_sources", [])
            print(f"Data sources included: {', '.join(data_sources)}")

            if 'connectsecure_metrics' in final_output:
                cs_summary = final_output['connectsecure_metrics'].get('summary', {})
                total_assets = cs_summary.get('total_assets', 0)
                total_vulns = cs_summary.get('total_vulnerabilities', 0)
                risk_score = cs_summary.get('risk_score', 'N/A')
                print(f"ConnectSecure: {total_assets} assets, {total_vulns} vulnerabilities, Risk Score: {risk_score}")
            elif 'ConnectSecure' not in data_sources:
                print("ConnectSecure: No data available - API endpoints may not be accessible")

        elif args.output in ['pdf', 'both'] and not PDF_AVAILABLE:
            print("\n PDF generation not available. Please install required dependencies:")
            print("pip install reportlab plotly pandas")

        # Print execution summary
        print(f"\nExecution completed in {duration:.1f} seconds")
        data_sources = final_output.get("execution_info", {}).get("data_sources", [])
        print(f"Data sources processed: {len(data_sources)}")
        for source in data_sources:
            print(f"   ✓ {source}")

    except ValueError as e:
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "credential_id": args.credential_id,
            "troubleshooting": {
                "check_credentials": f"Verify credentials exist in Supabase for ID: {args.credential_id}",
                "check_network": "Ensure network connectivity to API endpoints",
                "check_logs": "Review console output for specific error details"
            }
        }
        print(json.dumps(error_result, indent=2))
        logger.error(f"Security assessment failed: {e}")

    except Exception as e:
        error_result = {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "credential_id": args.credential_id,
            "troubleshooting": {
                "check_credentials": f"Verify credentials exist in Supabase for ID: {args.credential_id}",
                "check_network": "Ensure network connectivity to API endpoints",
                "check_logs": "Review console output for specific error details"
            }
        }
        print(json.dumps(error_result, indent=2))
        logger.error(f"Security assessment failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())