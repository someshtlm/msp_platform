"""
Cove Data Protection Processor
Handles data fetching and processing for Cove Backup Management platform
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class CoveProcessor:
    """Processor for Cove Data Protection data."""

    def __init__(
        self,
        account_id: int = None,
        cove_customer_id: str = None
    ):
        """
        Initialize CoveProcessor.

        Args:
            account_id: Account ID for fetching credentials from integration_credentials table
            cove_customer_id: Cove customer ID from organization_integrations (integration_id=5)
        """
        self.customer_id = cove_customer_id
        self.client = None

        if not account_id:
            logger.warning("No account_id provided - Cove data will be skipped")
            return

        try:
            try:
                from src.clients.cove_client import CoveAPIClient
            except ImportError:
                from security_reporting_system.src.clients.cove_client import CoveAPIClient

            self.client = CoveAPIClient(account_id=account_id)
            logger.info(f"Cove processor initialized for account_id: {account_id}")

        except Exception as e:
            logger.error(f"Failed to initialize Cove client: {e}")
            self.client = None

    def fetch_all_data(self, customer_id: str = None) -> Dict[str, Any]:
        """
        Fetch all Cove data for the customer.

        Makes ONE API call to get all data (not multiple calls like before).

        Args:
            customer_id: Cove customer ID (if None, uses self.customer_id)

        Returns:
            Dictionary containing raw Cove API response
        """
        if not self.client:
            logger.warning("⚠Cove client not initialized - returning empty data")
            return {}

        customer_id = customer_id or self.customer_id

        if not customer_id:
            logger.error("No customer_id provided for Cove data fetch")
            return {}

        logger.info(f"Fetching Cove data for customer: {customer_id}")

        try:
            # Single API call with all columns and totals
            # Based on working test_cove_endpoints.py implementation
            logger.info("📊 Fetching account statistics (all data in one call)...")

            response = self.client.get_account_statistics(
                customer_id=customer_id,
                columns=["I1", "I14", "I32", "I81", "PN", "GM", "G@", "JM"],  # Name, Storage, OSType, Physical/Virtual, RetentionPolicy, UserMailboxes, SharedMailboxes, OneDriveAccounts
                totals=["SUM(I14)", "SUM(GM)", "SUM(G@)", "SUM(JM)"],  # Total storage, user mailboxes, shared mailboxes, onedrive accounts
                start_record=0,
                records_count=100  # Get up to 100 devices
            )

            logger.info("Account statistics fetched successfully")
            return response

        except Exception as e:
            logger.error(f"Failed to fetch Cove data: {e}")
            return {}

    def process_all_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw Cove data into structured metrics.

        Processes the single API response to extract 5 charts:
        1. Total Storage Used
        2. Device Count
        3. Device Distribution (Workstation/Server/Undefined)
        4. Asset Distribution (Physical/Virtual/Undefined)
        5. Retention Policy Distribution

        Args:
            raw_data: Raw data from fetch_all_data() (single API response)

        Returns:
            Processed data with cove_metrics
        """
        if not raw_data or 'result' not in raw_data:
            logger.warning("⚠No raw data provided - returning default metrics")
            return {"cove_metrics": self._get_default_metrics()}

        logger.info("Processing Cove data...")

        metrics = {}

        # Extract data from API response (use 'or' to handle None values)
        result_data = raw_data.get('result') or {}
        devices = result_data.get('result') or []  # Array of device records
        total_statistics = result_data.get('totalStatistics') or []

        # ============================================================
        # 1. Total Storage Used (from totalStatistics)
        # Convert from bytes to TB (1 TB = 10^12 = 1,000,000,000,000 bytes)
        # totalStatistics is array of objects: [{"SUM(G@)": "0"}, {"SUM(GM)": "0"}, {"SUM(I14)": "4188932699497"}]
        # ============================================================
        if total_statistics and len(total_statistics) > 0:
            # Search for keys in the array
            total_storage_str = '0'
            user_mailboxes_str = '0'
            shared_mailboxes_str = '0'
            onedrive_accounts_str = '0'

            for stat_obj in total_statistics:
                if 'SUM(I14)' in stat_obj:
                    total_storage_str = stat_obj['SUM(I14)']
                if 'SUM(GM)' in stat_obj:
                    user_mailboxes_str = stat_obj['SUM(GM)']
                if 'SUM(G@)' in stat_obj:
                    shared_mailboxes_str = stat_obj['SUM(G@)']
                if 'SUM(JM)' in stat_obj:
                    onedrive_accounts_str = stat_obj['SUM(JM)']

            # Parse and convert storage to TB
            try:
                total_storage_bytes = int(total_storage_str)
                total_storage_tb = round(total_storage_bytes / 1_000_000_000_000, 2)  # 2 decimal places
                metrics['total_storage_used'] = total_storage_tb
            except (ValueError, TypeError):
                metrics['total_storage_used'] = 0

            # Parse user mailboxes
            try:
                metrics['user_mailboxes'] = int(user_mailboxes_str)
            except (ValueError, TypeError):
                metrics['user_mailboxes'] = 0

            # Parse shared mailboxes
            try:
                metrics['shared_mailboxes'] = int(shared_mailboxes_str)
            except (ValueError, TypeError):
                metrics['shared_mailboxes'] = 0

            # Parse OneDrive user accounts
            try:
                metrics['onedrive_user_accounts'] = int(onedrive_accounts_str)
            except (ValueError, TypeError):
                metrics['onedrive_user_accounts'] = 0
        else:
            metrics['total_storage_used'] = 0
            metrics['user_mailboxes'] = 0
            metrics['shared_mailboxes'] = 0
            metrics['onedrive_user_accounts'] = 0

        # ============================================================
        # 2. Device Count (count of devices array)
        # ============================================================
        metrics['device_count'] = len(devices) if devices else 0

        # ============================================================
        # 3. Device Distribution (Workstation vs Server)
        # ============================================================
        device_dist = {"Workstation": 0, "Server": 0, "Undefined": 0}

        for device in devices:
            settings = device.get('Settings') or []
            for setting in settings:
                if 'I32' in setting:
                    os_type = setting['I32']
                    # Convert to string for comparison (handles both int and string values)
                    os_type_str = str(os_type)
                    if os_type_str == "1":
                        device_dist['Workstation'] += 1
                    elif os_type_str == "2":
                        device_dist['Server'] += 1
                    elif os_type_str == "0":
                        device_dist['Undefined'] += 1
                    else:
                        device_dist['Undefined'] += 1
                    break  # Found I32, move to next device

        metrics['device_distribution'] = device_dist

        # ============================================================
        # 4. Asset Distribution (Physical vs Virtual)
        # ============================================================
        asset_dist = {"Physical": 0, "Virtual": 0, "Undefined": 0}

        for device in devices:
            settings = device.get('Settings') or []
            for setting in settings:
                if 'I81' in setting:
                    physicality = str(setting['I81']).lower()
                    if 'physical' in physicality:
                        asset_dist['Physical'] += 1
                    elif 'virtual' in physicality:
                        asset_dist['Virtual'] += 1
                    else:
                        asset_dist['Undefined'] += 1
                    break  # Found I81, move to next device

        metrics['asset_distribution'] = asset_dist

        # ============================================================
        # 5. Retention Policy Distribution
        # ============================================================
        retention_dist = {}

        for device in devices:
            settings = device.get('Settings') or []
            policy = None

            for setting in settings:
                if 'PN' in setting:
                    policy = setting['PN']
                    break

            if policy:
                if policy not in retention_dist:
                    retention_dist[policy] = 0
                retention_dist[policy] += 1

        metrics['retention_policy_distribution'] = retention_dist

        logger.info("Cove data processed successfully")
        logger.info(f"   Storage Used: {metrics['total_storage_used']} TB")
        logger.info(f"   Device Count: {metrics['device_count']}")
        logger.info(f"   User Mailboxes: {metrics['user_mailboxes']}, Shared Mailboxes: {metrics['shared_mailboxes']}, OneDrive Accounts: {metrics['onedrive_user_accounts']}")
        logger.info(f"   Workstations: {device_dist['Workstation']}, Servers: {device_dist['Server']}")

        return {"cove_metrics": metrics}

    def _get_default_metrics(self) -> Dict[str, Any]:
        """
        Return default empty metrics structure.

        Returns:
            Dictionary with default/empty metrics
        """
        return {
            "total_storage_used": 0,
            "device_count": 0,
            "user_mailboxes": 0,
            "shared_mailboxes": 0,
            "onedrive_user_accounts": 0,
            "device_distribution": {"Workstation": 0, "Server": 0, "Undefined": 0},
            "asset_distribution": {"Physical": 0, "Virtual": 0, "Undefined": 0},
            "retention_policy_distribution": {}
        }

    def test_connection(self) -> bool:
        """
        Test Cove API connection.

        Returns:
            True if connection successful, False otherwise
        """
        if not self.client:
            return False

        try:
            return self.client.test_connection()
        except Exception as e:
            logger.error(f" Cove connection test failed: {e}")
            return False
