"""
Bitdefender Processor
Processes Bitdefender GravityZone API data into chart and table format
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.clients.bitdefender_client import BitdefenderClient

logger = logging.getLogger(__name__)


class BitdefenderProcessor:
    """Processes Bitdefender GravityZone data for security reporting"""

    def __init__(self, account_id: int, bitdefender_company_id: str):
        """
        Initialize Bitdefender processor

        Args:
            account_id: Account ID for credential lookup
            bitdefender_company_id: Bitdefender company ID from organization_integrations
        """
        self.account_id = account_id
        self.company_id = bitdefender_company_id

        api_key = self._get_bitdefender_api_key()
        self.client = BitdefenderClient(api_key)

        logger.info(f"BitdefenderProcessor initialized for account_id={account_id}, company_id={bitdefender_company_id}")

    def _get_bitdefender_api_key(self) -> str:
        """
        Fetch and decrypt Bitdefender API key from integration_credentials

        Returns:
            Decrypted API key
        """
        try:
            from app.core.config.supabase import SupabaseCredentialManager
            from app.services.encryption.manager import EncryptionManager

            supabase_manager = SupabaseCredentialManager()
            encryption_manager = EncryptionManager()

            response = supabase_manager.supabase.table('integration_credentials')\
                .select('credentials')\
                .eq('account_id', self.account_id)\
                .eq('is_active', True)\
                .limit(1)\
                .execute()

            if not response.data or len(response.data) == 0:
                raise ValueError(f"No credentials found for account_id={self.account_id}")

            encrypted_blob = response.data[0]['credentials']
            decrypted_creds = encryption_manager.decrypt_integration_credentials(encrypted_blob)

            bitdefender_creds = decrypted_creds.get('bitdefender', {})
            api_key = bitdefender_creds.get('bitdefender_api_key')

            if not api_key:
                raise ValueError(f"Bitdefender API key not found for account_id={self.account_id}")

            logger.info(f"Successfully retrieved Bitdefender API key for account_id={self.account_id}")
            return api_key

        except Exception as e:
            logger.error(f"Failed to retrieve Bitdefender API key: {e}")
            raise

    def fetch_all_data(self, month_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch all Bitdefender data from API

        Args:
            month_name: Month name (e.g., "October") - only used for active endpoints

        Returns:
            Dict with raw API responses
        """
        logger.info(f"Fetching Bitdefender data for company_id={self.company_id}")

        target_month = self._convert_month_to_target_format(month_name)

        raw_data = {
            "company_details": self.client.get_company_details(self.company_id),
            "endpoints_list": self.client.get_all_endpoints_paginated(self.company_id, per_page=10),
            "network_inventory": self.client.get_all_network_inventory_paginated(self.company_id, per_page=1000),
            "monthly_usage": self.client.get_monthly_usage(self.company_id, target_month),
            "target_month": target_month
        }

        logger.info(f"Fetched Bitdefender data: {len(raw_data['endpoints_list'])} endpoints, "
                   f"{len(raw_data['network_inventory'])} inventory items")

        return raw_data

    def process_all_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw Bitdefender data into chart and table format

        Args:
            raw_data: Raw data from fetch_all_data()

        Returns:
            Processed data with charts and tables
        """
        logger.info("Processing Bitdefender data...")

        processed = {
            "bitdefender_metrics": {
                "charts": {},
                "tables": {}
            }
        }

        company_details = raw_data.get("company_details", {})
        endpoints_list = raw_data.get("endpoints_list", [])
        network_inventory = raw_data.get("network_inventory", [])
        monthly_usage = raw_data.get("monthly_usage", {})

        # Combine endpoint utilization metrics into single chart
        processed["bitdefender_metrics"]["charts"]["endpoint_utilization_bitdefender"] = {
            "activeEndpoints": self._process_active_endpoints(monthly_usage),
            "managedEndpoints": self._process_managed_endpoints(endpoints_list)
        }

        processed["bitdefender_metrics"]["charts"]["riskScore_bitdefender"] = self._process_risk_score(company_details)
        processed["bitdefender_metrics"]["charts"]["inventory_summary_bitdefender"] = self._process_os_summary(network_inventory)

        processed["bitdefender_metrics"]["tables"]["networkinventory_bitdefender"] = self._process_network_inventory(network_inventory)

        logger.info("Bitdefender data processed successfully")
        return processed

    def _convert_month_to_target_format(self, month_name: Optional[str]) -> str:
        """
        Convert month name to MM/YYYY format

        Args:
            month_name: Month name in format "october_2024" or "november_2025"

        Returns:
            String in MM/YYYY format (e.g., "10/2024", "11/2025")
        """
        if not month_name:
            current_date = datetime.now()
            return current_date.strftime("%m/%Y")

        month_mapping = {
            "january": "01", "february": "02", "march": "03", "april": "04",
            "may": "05", "june": "06", "july": "07", "august": "08",
            "september": "09", "october": "10", "november": "11", "december": "12"
        }

        # Parse new format: "october_2024" or "november_2025"
        try:
            parts = month_name.lower().split('_')
            if len(parts) == 2:
                month_name_part = parts[0]
                year_part = parts[1]
                month_num = month_mapping.get(month_name_part)

                if month_num and len(year_part) == 4:
                    result = f"{month_num}/{year_part}"
                    logger.info(f"Converted month '{month_name}' to Bitdefender format: {result}")
                    return result

            # If parsing fails, log warning and use current month
            logger.warning(f"Invalid month format: {month_name}, expected 'october_2024'. Using current month")
            return datetime.now().strftime("%m/%Y")

        except Exception as e:
            logger.warning(f"Error parsing month '{month_name}': {e}. Using current month")
            return datetime.now().strftime("%m/%Y")

    def _process_risk_score(self, company_details: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and format risk score data"""
        risk_score = company_details.get("riskScore", {}) or {}

        return {
            "value": risk_score.get("value"),
            "impact": risk_score.get("impact"),
            "misconfigurations": risk_score.get("misconfigurations"),
            "appVulnerabilities": risk_score.get("appVulnerabilities"),
            "humanRisks": risk_score.get("humanRisks"),
            "industryModifier": risk_score.get("industryModifier")
        }

    def _process_2fa_status(self, company_details: Dict[str, Any]) -> bool:
        """Extract 2FA enforcement status"""
        return company_details.get("enforce2FA", False)

    def _process_managed_endpoints(self, endpoints_list: List[Dict[str, Any]]) -> int:
        """Count managed endpoints (those with valid 'id' field)"""
        count = sum(1 for endpoint in endpoints_list if endpoint.get("id"))
        return count

    def _process_active_endpoints(self, monthly_usage: Dict[str, Any]) -> int:
        """Extract active endpoints from monthly usage"""
        return monthly_usage.get("endpointMonthlyUsage", 0)

    def _process_os_summary(self, network_inventory: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process OS distribution and machine types

        Returns:
            Dict with nested structure:
            {
                "summary": { windowsWorkstations, windowsServers, macOS, linux },
                "count": { physicalMachines, virtualMachines }
            }
        """
        os_summary = {
            "windowsWorkstations": 0,
            "windowsServers": 0,
            "macOS": 0,
            "linux": 0
        }

        machine_count = {
            "physicalMachines": 0,
            "virtualMachines": 0
        }

        for item in network_inventory:
            details = item.get("details") or {}
            os_version = (details.get("operatingSystemVersion") or "").lower()
            machine_type = details.get("machineType")

            if "windows" in os_version:
                if "server" in os_version:
                    os_summary["windowsServers"] += 1
                else:
                    os_summary["windowsWorkstations"] += 1
            elif "mac" in os_version or "macos" in os_version or "os x" in os_version:
                os_summary["macOS"] += 1
            elif "linux" in os_version:
                os_summary["linux"] += 1

            if machine_type == 1:
                machine_count["physicalMachines"] += 1
            elif machine_type == 2:
                machine_count["virtualMachines"] += 1

        return {
            "summary": os_summary,
            "count": machine_count
        }

    def _process_network_inventory(self, network_inventory: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process network inventory to extract module deployment status

        Returns:
            List of module objects with enable/disable/notInstalled counts
        """
        module_keys = {
            "antimalware": "antimalware",
            "advancedThreatControl": "advancedThreatControl",
            "advancedAntiExploit": "advancedAntiExploit",
            "firewall": "firewall",
            "networkAttackDefense": "networkAttackDefense",
            "deviceControl": "deviceControl",
            "encryption": "encryption",
            "patchManagement": "patchManagement",
            "edrSensor": "edrSensor",
            "powerUser": "powerUser",
            "exchange": "exchange",
            "containerProtection": "containerProtection",
            "integrityMonitoring": "integrityMonitoring",
            "phASR": "phASR"
        }

        summary = {m: {"enabled": 0, "disabled": 0, "notInstalled": 0} for m in module_keys}

        supported_by_platform = {
            "windows": set(module_keys.keys()),
            "linux": {
                "antimalware", "advancedThreatControl", "advancedAntiExploit",
                "networkAttackDefense", "deviceControl", "powerUser"
            },
            "macos": {
                "antimalware", "advancedThreatControl", "advancedAntiExploit",
                "networkAttackDefense", "powerUser"
            }
        }

        company_license_flags = {}
        for item in network_inventory:
            if item.get("type") == 1:
                lic = (item.get("details") or {}).get("licenseInfo") or {}
                if lic:
                    company_license_flags.update(lic)

        license_map = {
            "encryption": ["manageEncryption"],
            "patchManagement": ["managePatchManagement", "managePatchManagementResell"],
            "edrSensor": ["manageHyperDetect", "manageXDRNetwork", "manageEDR"],
            "containerProtection": ["manageContainerProtection"],
            "integrityMonitoring": ["manageIntegrityMonitoring"],
            "phASR": ["managePHASR"],
            "exchange": ["manageEmailSecurity", "manageExchange"],
            "antimalware": [],
            "advancedThreatControl": [],
            "advancedAntiExploit": [],
            "firewall": [],
            "networkAttackDefense": [],
            "deviceControl": [],
            "powerUser": []
        }

        licensed_by_company = {}
        for m in module_keys:
            licensed_by_company[m] = False
            for key in license_map.get(m, []):
                if key in company_license_flags and bool(company_license_flags[key]) is True:
                    licensed_by_company[m] = True
                    break

        endpoints = [item for item in network_inventory if item.get("type") in (5, 6, 7)]
        total_endpoints = len(endpoints)

        licensed = {m: licensed_by_company.get(m, False) for m in module_keys}

        for item in endpoints:
            modules = (item.get("details") or {}).get("modules") or {}
            for m, bd_key in module_keys.items():
                if not licensed[m]:
                    if modules.get(bd_key) is True:
                        licensed[m] = True

        for item in endpoints:
            details = item.get("details") or {}
            modules = details.get("modules") or {}
            platform = self._normalize_platform(item)

            for m, bd_key in module_keys.items():
                if not licensed.get(m, False):
                    continue

                if platform not in supported_by_platform or m not in supported_by_platform[platform]:
                    summary[m]["notInstalled"] += 1
                    continue

                if bd_key not in modules:
                    summary[m]["notInstalled"] += 1
                    continue

                value = modules.get(bd_key)

                if isinstance(value, bool):
                    if value:
                        summary[m]["enabled"] += 1
                    else:
                        summary[m]["disabled"] += 1
                    continue

                if isinstance(value, dict):
                    inst = value.get("installed")
                    state = (value.get("state") or value.get("status") or "").lower()
                    if inst is True or "enable" in state:
                        summary[m]["enabled"] += 1
                    elif inst is False or ("not" in state and "install" in state):
                        summary[m]["notInstalled"] += 1
                    elif "disable" in state:
                        summary[m]["disabled"] += 1
                    else:
                        summary[m]["disabled"] += 1
                    continue

                if isinstance(value, str):
                    s = value.lower()
                    if "not" in s and "install" in s:
                        summary[m]["notInstalled"] += 1
                    elif "disable" in s:
                        summary[m]["disabled"] += 1
                    elif "enable" in s or "true" in s:
                        summary[m]["enabled"] += 1
                    else:
                        summary[m]["disabled"] += 1
                    continue

                summary[m]["disabled"] += 1

        for m in module_keys:
            if not licensed.get(m, False):
                summary[m] = {"enabled": 0, "disabled": 0, "notInstalled": total_endpoints}

        for m in module_keys:
            s = summary[m]
            sum_counts = s["enabled"] + s["disabled"] + s["notInstalled"]
            if sum_counts != total_endpoints:
                s["notInstalled"] += (total_endpoints - sum_counts)

        allowed_modules = {
            "antimalware",
            "advancedThreatControl",
            "advancedAntiExploit",
            "firewall",
            "networkAttackDefense",
            "deviceControl",
            "encryption",
            "patchManagement",
            "edrSensor",
            "powerUser",
            "exchange",
            "containerProtection",
            "integrityMonitoring",
            "phASR"
        }

        filtered_summary = {m: summary[m] for m in allowed_modules}

        # Display name mapping for modules
        display_name_map = {
            "antimalware": "Antimalware",
            "advancedThreatControl": "Advanced Threat Control",
            "advancedAntiExploit": "Advanced Anti-Exploit",
            "firewall": "Firewall",
            "networkAttackDefense": "Network Protection",
            "deviceControl": "Device Control",
            "encryption": "Encryption",
            "patchManagement": "Patch Management",
            "edrSensor": "EDR Sensor",
            "powerUser": "Power User",
            "exchange": "Exchange Protection",
            "containerProtection": "Container Protection",
            "integrityMonitoring": "Integrity Monitoring",
            "phASR": "PHASR"
        }

        network_inventory_list = [
            {
                "Module": module_name,
                "enable": module_data["enabled"],
                "disable": module_data["disabled"],
                "notInstalled": module_data["notInstalled"],
                "displayName": display_name_map.get(module_name, module_name)
            }
            for module_name, module_data in filtered_summary.items()
        ]

        return network_inventory_list

    def _normalize_platform(self, item: Dict[str, Any]) -> str:
        """
        Normalize platform/OS detection

        Returns:
            "windows", "macos", "linux", or "unknown"
        """
        details = item.get("details") or {}
        fields = [
            details.get("osType"),
            details.get("platform"),
            details.get("operatingSystem"),
            details.get("operatingSystemVersion"),
            item.get("os"),
            item.get("platform")
        ]

        joined = " ".join([str(f) for f in fields if f]).lower()

        if "win" in joined or "windows" in joined:
            return "windows"

        mac_keys = ["mac", "darwin", "sequoia", "monterey", "ventura", "sonoma", "big sur"]
        if any(k in joined for k in mac_keys):
            return "macos"

        if "linux" in joined:
            return "linux"

        if "10." in joined or "6." in joined:
            return "windows"

        return "unknown"
