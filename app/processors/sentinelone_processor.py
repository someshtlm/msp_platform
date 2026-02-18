"""
SentinelOne Processor
Processes SentinelOne API data into chart format (11 charts, no tables)
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from collections import defaultdict
from app.clients.sentinelone_client import SentinelOneClient

logger = logging.getLogger(__name__)


class SentinelOneProcessor:
    """Processes SentinelOne data for security reporting"""

    def __init__(self, account_id: int, sentinelone_site_id: str):
        self.account_id = account_id
        self.site_id = sentinelone_site_id

        api_token, base_url = self._get_sentinelone_credentials()
        self.client = SentinelOneClient(api_token, base_url)

        logger.info(f"SentinelOneProcessor initialized for account_id={account_id}, site_id={sentinelone_site_id}")

    def _get_sentinelone_credentials(self):
        """Fetch and decrypt SentinelOne credentials from integration_credentials table"""
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

            sentinelone_creds = decrypted_creds.get('sentinelone', {})
            api_token = sentinelone_creds.get('sentinelone_api_token')
            base_url = sentinelone_creds.get('sentinelone_base_url')

            if not api_token:
                raise ValueError(f"SentinelOne API token not found for account_id={self.account_id}")
            if not base_url:
                raise ValueError(f"SentinelOne base URL not found for account_id={self.account_id}")

            logger.info(f"Successfully retrieved SentinelOne credentials for account_id={self.account_id}")
            return api_token, base_url

        except Exception as e:
            logger.error(f"Failed to retrieve SentinelOne credentials: {e}")
            raise

    def fetch_all_data(self, month_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Fetch all SentinelOne data from API.
        Agents are always live (no date filter).
        Threats are filtered by month.
        """
        logger.info(f"Fetching SentinelOne data for site_id={self.site_id}")

        start_date = None
        end_date = None

        if month_name:
            start_date, end_date = self._convert_month_to_date_range(month_name)
            logger.info(f"Threat date filter: {start_date} to {end_date}")

        raw_data = {
            "agents": self.client.get_all_agents(self.site_id),
            "threats": self.client.get_all_threats(self.site_id, start_date, end_date)
        }

        logger.info(f"Fetched SentinelOne data: {len(raw_data['agents'])} agents, {len(raw_data['threats'])} threats")
        return raw_data

    def process_all_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw SentinelOne data into 11 charts"""
        logger.info("Processing SentinelOne data...")

        agents = raw_data.get("agents", [])
        threats = raw_data.get("threats", [])

        # Initialize counters
        domain_counts = {}
        machine_type_counts = defaultdict(int)
        os_type_counts = defaultdict(int)
        infected_count = 0
        healthy_count = 0
        agent_version_counts = {}
        network_status_counts = defaultdict(int)

        # Threat counters
        confidence_level_counts = defaultdict(int)
        incident_status_counts = defaultdict(int)
        analyst_verdict_counts = defaultdict(int)
        detection_engine_counts = defaultdict(int)
        threat_type_counts = defaultdict(int)

        # Process ALL agents in one loop
        for agent in agents:
            # Domain counts
            domain = agent.get("domain", "").strip().upper()
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            else:
                domain_counts["OTHERS"] = domain_counts.get("OTHERS", 0) + 1

            # Machine type counts
            machine_type = agent.get("machineType", "").lower().strip()
            if machine_type:
                machine_type_counts[machine_type] += 1

            # OS type counts
            os_type = agent.get("osType", "").lower().strip()
            if os_type:
                os_type_counts[os_type] += 1

            # Infected vs healthy
            infected = agent.get("infected", False)
            if infected is True:
                infected_count += 1
            else:
                healthy_count += 1

            # Agent version counts
            agent_version = agent.get("agentVersion", "").strip()
            if agent_version:
                agent_version_counts[agent_version] = agent_version_counts.get(agent_version, 0) + 1

            # Network status counts
            network_status = agent.get("networkStatus", "").lower().strip()
            if network_status:
                network_status_counts[network_status] += 1

        # Process ALL threats in one loop
        for threat in threats:
            threat_info = threat.get("threatInfo", {})

            # Confidence levels (severity)
            confidence_level = threat_info.get("confidenceLevel", "").lower().strip()
            if confidence_level:
                confidence_level_counts[confidence_level] += 1
            else:
                confidence_level_counts["n/a"] += 1

            # Incident statuses
            incident_status = threat_info.get("incidentStatus", "").lower().strip()
            if incident_status:
                incident_status_counts[incident_status] += 1

            # Analyst verdicts
            analyst_verdict = threat_info.get("analystVerdict", "").lower().strip()
            if analyst_verdict:
                analyst_verdict_counts[analyst_verdict] += 1
            else:
                analyst_verdict_counts["undefined"] += 1

            # Detection engines
            detection_engines = threat_info.get("detectionEngines", [])
            for engine in detection_engines:
                engine_title = engine.get("title", "").strip()
                if engine_title:
                    detection_engine_counts[engine_title] += 1

            # Threat types by classification
            classification = threat_info.get("classification", "").strip()
            if classification:
                threat_type_counts[classification] += 1

        # Build the 11 charts
        # Hardcoded domain keys + dynamic overflow
        hardcoded_domains = ["WORKGROUP", "DRF", "PG", "API", "HISCROSS", "DYNAMESH", "RCW", "CORPORATE", "FIDELITY", "KATZ", "OTHERS"]
        secured_devices_by_domain = {d: domain_counts.get(d, 0) for d in hardcoded_domains}
        # Add any dynamic domains not in the hardcoded list
        for domain, count in domain_counts.items():
            if domain not in hardcoded_domains:
                secured_devices_by_domain[domain] = count

        charts = {
            "secured_devices_by_domain": secured_devices_by_domain,
            "secured_devices_by_role": {
                "desktop": machine_type_counts.get("desktop", 0),
                "laptop": machine_type_counts.get("laptop", 0),
                "server": machine_type_counts.get("server", 0),
                "other": machine_type_counts.get("other", 0),
                "kubernetes_node": machine_type_counts.get("kubernetes_node", 0),
                "storage": machine_type_counts.get("storage", 0),
                "kubernetes_pod": machine_type_counts.get("kubernetes_pod", 0),
                "ecs_task": machine_type_counts.get("ecs_task", 0),
                "kubernetes_helper": machine_type_counts.get("kubernetes_helper", 0)
            },
            "secured_devices_by_os": {
                "windows": os_type_counts.get("windows", 0),
                "macos": os_type_counts.get("macos", 0),
                "linux": os_type_counts.get("linux", 0),
                "windows_legacy": os_type_counts.get("windows_legacy", 0)
            },
            "infected_endpoints": {
                "healthy": healthy_count,
                "infected": infected_count
            },
            "agent_version_coverage": agent_version_counts,
            "endpoint_connection_status": {
                "connected": network_status_counts.get("connected", 0),
                "disconnected": network_status_counts.get("disconnected", 0),
                "connecting": network_status_counts.get("connecting", 0),
                "disconnecting": network_status_counts.get("disconnecting", 0)
            },
            "severity_levels_threats": {
                "suspicious": confidence_level_counts.get("suspicious", 0),
                "malicious": confidence_level_counts.get("malicious", 0),
                "n/a": confidence_level_counts.get("n/a", 0)
            },
            "incident_status": {
                "resolved": incident_status_counts.get("resolved", 0),
                "unresolved": incident_status_counts.get("unresolved", 0),
                "in_progress": incident_status_counts.get("in_progress", 0)
            },
            "analyst_verdicts_threats": {
                "false_positive": analyst_verdict_counts.get("false_positive", 0),
                "true_positive": analyst_verdict_counts.get("true_positive", 0),
                "suspicious": analyst_verdict_counts.get("suspicious", 0),
                "undefined": analyst_verdict_counts.get("undefined", 0)
            },
            "threats_by_detection_engine": {
                "sentinelone_cloud": detection_engine_counts.get("SentinelOne Cloud", 0),
                "on-write_static_ai": detection_engine_counts.get("On-Write Static AI", 0),
                "on_write_static_ai_suspicious": detection_engine_counts.get("On-Write Static AI - Suspicious", 0),
                "behavioral_ai": detection_engine_counts.get("Behavioral AI", 0),
                "documents,_scripts": detection_engine_counts.get("Documents, Scripts", 0),
                "user-defined_blocklist": detection_engine_counts.get("User-Defined Blocklist", 0),
                "reputation": detection_engine_counts.get("Reputation", 0),
                "cloud_detection": detection_engine_counts.get("Cloud Detection", 0),
                "anti_exploitation_fileless": detection_engine_counts.get("Anti Exploitation / Fileless", 0),
                "intrusion_detection": detection_engine_counts.get("Intrusion Detection", 0)
            },
            "threats_by_type": {
                "Malware": threat_type_counts.get("Malware", 0),
                "Ransomware": threat_type_counts.get("Ransomware", 0),
                "General": threat_type_counts.get("General", 0),
                "Trojan": threat_type_counts.get("Trojan", 0)
            }
        }

        processed = {
            "sentinelone_metrics": {
                "charts": charts,
                "tables": {}
            }
        }

        logger.info(f"SentinelOne data processed: {len(agents)} agents, {len(threats)} threats, 11 charts")
        return processed

    def _convert_month_to_date_range(self, month_name: str):
        """
        Convert month_name (e.g., 'october_2024') to ISO date range for threat filtering.
        Returns (start_date, end_date) as ISO strings.
        """
        month_mapping = {
            "january": 1, "february": 2, "march": 3, "april": 4,
            "may": 5, "june": 6, "july": 7, "august": 8,
            "september": 9, "october": 10, "november": 11, "december": 12
        }

        try:
            parts = month_name.lower().split('_')
            if len(parts) == 2:
                month_num = month_mapping.get(parts[0])
                year = int(parts[1])

                if month_num:
                    start = datetime(year, month_num, 1)
                    if month_num == 12:
                        end = datetime(year + 1, 1, 1)
                    else:
                        end = datetime(year, month_num + 1, 1)

                    start_date = start.strftime("%Y-%m-%dT%H:%M:%SZ")
                    end_date = end.strftime("%Y-%m-%dT%H:%M:%SZ")
                    logger.info(f"Converted month '{month_name}' to range: {start_date} - {end_date}")
                    return start_date, end_date

            logger.warning(f"Invalid month format: {month_name}, no date filter applied")
            return None, None

        except Exception as e:
            logger.warning(f"Error parsing month '{month_name}': {e}, no date filter applied")
            return None, None
