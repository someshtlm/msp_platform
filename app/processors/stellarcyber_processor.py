# app/processors/stellarcyber_processor.py (PARTIAL)
from collections import Counter, defaultdict
from typing import Dict, Any, List
import logging

from app.clients.stellarcyber_client import StellarCyberClient

logger = logging.getLogger(__name__)


class StellarCyberProcessor:

    def __init__(self, account_id: int, stellarcyber_org_id: str | None = None):
        from app.core.config.supabase import SupabaseCredentialManager

        credential_manager = SupabaseCredentialManager()
        credentials = credential_manager.get_credentials_by_account_id(account_id)

        if not credentials:
            raise ValueError(f"No credentials found for account_id={account_id}")

        stellar_creds = credentials.get("stellarcyber", {})
        token = stellar_creds.get("api_token")
        base_url = stellar_creds.get("base_url")

        if not token or not base_url:
            logger.warning("Stellar Cyber credentials incomplete – integration disabled")
            self.client = None
            return

        self.client = StellarCyberClient(
            base_url=base_url,
            api_token=token
        )

    # ------------------------------------------------------------------
    # CORE METHOD
    # ------------------------------------------------------------------

    def fetch_all_data(self, month_name: str | None = None) -> Dict[str, Any]:
        """
        Fetch raw Stellar Cyber report data.

        This method:
        - discovers required reports
        - fetches raw report data
        - returns unprocessed results
        """

        if not self.client:
            logger.info("Stellar Cyber client not initialized – skipping")
            return {}

        logger.info("Fetching Stellar Cyber report configurations")
        report_configs = self.client.list_report_configs()

        # Normalize report name lookup
        report_lookup = {
            r.get("name", "").lower(): r
            for r in report_configs
            if r.get("id")
        }

        # Logical → matching keywords
        required_reports = {
            "login_location_anomaly": ["login", "location", "anomaly"],
            "login_failures": ["login", "failure"],
            "windows_account_lockout": ["account", "lockout", "windows"],
            "windows_account_changes": ["account", "change", "windows"],
            "plaintext_password_usage": ["plain", "text", "password"]
        }

        results = {}
        counts = {}

        for logical_key, keywords in required_reports.items():
            matched_report = None

            for name, report in report_lookup.items():
                if all(k in name for k in keywords):
                    matched_report = report
                    break

            if not matched_report:
                logger.warning(f"No Stellar Cyber report found for {logical_key}")
                continue

            report_id = matched_report["id"]
            report_name = matched_report.get("name")

            logger.info(f"Fetching Stellar Cyber report: {report_name} ({report_id})")

            try:
                raw_data = self.client.get_report_data(report_id)
            except Exception as e:
                logger.warning(f"/data failed for {report_name}, trying /export: {e}")
                try:
                    raw_data = self.client.export_report(report_id)
                except Exception as ex:
                    logger.error(f"Failed to fetch Stellar Cyber report {report_name}: {ex}")
                    continue

            results[logical_key] = {
                "report_id": report_id,
                "report_name": report_name,
                "raw_data": raw_data
            }

            # Best-effort count
            if isinstance(raw_data, list):
                counts[logical_key] = len(raw_data)
            elif isinstance(raw_data, dict):
                counts[logical_key] = len(raw_data.get("data", []))
            else:
                counts[logical_key] = 0

        logger.info("Stellar Cyber raw data fetch complete")

        return {
            "reports_fetched": results,
            "raw_counts": counts
        }

    # ... __init__ and fetch_all_data already defined ...

    # --------------------------------------------------
    # MAIN THINKING METHOD
    # --------------------------------------------------

    def process_all_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw Stellar Cyber report data into security insights.
        """

        reports = raw_data.get("reports_fetched", {})

        login_anomaly_events = self._extract_events(reports, "login_location_anomaly")
        login_failure_events = self._extract_events(reports, "login_failures")
        plaintext_events = self._extract_events(reports, "plaintext_password_usage")
        lockout_events = self._extract_events(reports, "windows_account_lockout")
        account_change_events = self._extract_events(reports, "windows_account_changes")

        processed = {
            "StellarCyber": {
                "login_location_anomalies": self._login_location_anomalies(login_anomaly_events),
                "top_failures_by_source": self._top_n(login_failure_events, "source_ip", 20),
                "top_failures_by_user": self._top_n(login_failure_events, "user", 20),
                "top_login_failure_types": self._top_n(login_failure_events, "failure_type", 10),
                "plaintext_password_usage": self._top_n(plaintext_events, "source_ip", 20),
                "windows_account_lockouts": self._top_n(lockout_events, "user", 20),
                "windows_account_change_events": self._top_n(account_change_events, "event_type", 10),
                "windows_account_changes_by_target": self._top_n(account_change_events, "target_user", 20),
            }
        }

        logger.info("Stellar Cyber data processed successfully")
        return processed

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------

    def _extract_events(self, reports: Dict[str, Any], key: str) -> List[Dict]:
        """
        Safely extract raw events for a given logical report key.
        """
        report = reports.get(key, {})
        data = report.get("raw_data", [])
        if isinstance(data, dict):
            return data.get("data", [])
        return data if isinstance(data, list) else []

    def _top_n(self, events: List[Dict], field: str, limit: int) -> List[Dict[str, Any]]:
        """
        Generic top-N counter.
        """
        counter = Counter()

        for event in events:
            value = event.get(field)
            if value:
                counter[value] += 1

        return [
            {"value": key, "count": count}
            for key, count in counter.most_common(limit)
        ]

    def _login_location_anomalies(self, events: List[Dict]) -> List[Dict[str, Any]]:
        """
        Detect users logging in from unusual locations.
        """

        user_locations = defaultdict(list)

        for event in events:
            user = event.get("user")
            country = event.get("country")
            if user and country:
                user_locations[user].append(country)

        anomalies = []

        for user, countries in user_locations.items():
            counts = Counter(countries)
            if len(counts) <= 1:
                continue  # no anomaly

            most_common_country = counts.most_common(1)[0][0]
            anomalous = [
                c for c in counts
                if c != most_common_country
            ]

            anomalies.append({
                "user": user,
                "usual_country": most_common_country,
                "anomalous_countries": anomalous,
                "anomaly_count": sum(counts[c] for c in anomalous)
            })

        return sorted(
            anomalies,
            key=lambda x: x["anomaly_count"],
            reverse=True
        )
