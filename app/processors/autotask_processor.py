"""
Autotask Data Processor

This module handles all Autotask data fetching, processing, and analysis.
Extracted from main.py to improve modularity.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
# Add path resolution for local running
import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
security_system_root = os.path.join(current_dir, '..', '..')
if security_system_root not in sys.path:
    sys.path.insert(0, security_system_root)

# Updated imports for new app/ structure
from app.core.config.settings import config_manager
from app.clients.autotask_client import AutotaskClient, AutotaskConfig

logger = logging.getLogger(__name__)


class AutotaskProcessor:
    """Handles all Autotask data operations."""

    def __init__(self, account_id: int = None, credential_id: str = None):
        """
        Initialize AutotaskProcessor with account-based credentials.

        Args:
            account_id: Account ID for fetching credentials from integration_credentials table (NEW)
            credential_id: DEPRECATED - Legacy UUID for old user_credentials table
        """
        # NEW: Load credentials from account_id (integration_credentials table)
        if account_id is not None:
            from app.core.config.supabase import SupabaseCredentialManager

            credential_manager = SupabaseCredentialManager()
            credentials = credential_manager.get_credentials_by_account_id(account_id)

            if not credentials:
                raise ValueError(f"No credentials found for account_id: {account_id}")

            # Extract Autotask credentials from decrypted data
            autotask_creds = credentials.get('autotask', {})

            self.config = AutotaskConfig(
                username=autotask_creds.get('autotask_username'),
                secret=autotask_creds.get('autotask_secret'),
                integration_code=autotask_creds.get('autotask_integration_code'),
                base_url=autotask_creds.get('autotask_base_url')
            )

            logger.info(f"Loaded Autotask credentials from account_id: {account_id}")

        # OLD: Fallback to legacy credential_id method
        elif credential_id is not None:
            logger.warning("Using DEPRECATED credential_id method. Please migrate to account_id.")
            config = config_manager.load_credentials(credential_id)

            self.config = AutotaskConfig(
                username=config['autotask_username'],
                secret=config['autotask_secret'],
                integration_code=config['autotask_integration_code'],
                base_url=config['autotask_base_url']
            )

        else:
            raise ValueError("Either account_id or credential_id must be provided")

    async def fetch_all_data(self, company_id: Optional[int] = None, month_name: str = None) -> Dict[str, Any]:
        """
        Fetch required Autotask data with error handling, requires company_id for filtering.
        Now supports month filtering like NinjaOne, plus special "6 months" option.

        Args:
            company_id: REQUIRED company ID to filter tickets - returns empty data if None
            month_name: Specific month name (e.g., "August", "July"), "6 months" for last 6 months, or None for previous month

        Returns:
            Dictionary containing all required Autotask data (empty if no company_id)
        """
        # Return empty data if no company_id provided
        if company_id is None:
            logger.warning("No Autotask company_id provided - returning empty data")
            return {
                'created_vs_completed': {},
                'monthly_by_issue_type': [],
                'open_by_priority': [],
                'active_tickets': {},
                'slo_metrics': [],
                'tickets_by_contact': []
            }

        data = {}

        # Check if user requested "6 months" data
        if month_name and month_name.strip().lower() == "6 months":
            logger.info("AutoTask: Fetching last 6 months of data")
            return await self._fetch_six_months_data(company_id)

        # Initialize date variables with default values (previous month)
        today = datetime.now()
        first_day_of_current_month = today.replace(day=1)
        end_of_month = first_day_of_current_month - timedelta(days=1)
        start_of_month = end_of_month.replace(day=1)

        # Calculate date range using MonthSelector if month_name is provided
        if month_name:
            try:
                from app.utils.month_selector import MonthSelector
                month_selector = MonthSelector()
                start_timestamp, end_timestamp = month_selector.get_month_timestamps(month_name)

                start_of_month = datetime.fromtimestamp(start_timestamp)
                end_of_month = datetime.fromtimestamp(end_timestamp)

                logger.info(f"AutoTask filtering for month: {month_name}")
                logger.info(f"Date range: {start_of_month.strftime('%Y-%m-%d')} to {end_of_month.strftime('%Y-%m-%d')}")

            except Exception as e:
                logger.warning(f"Failed to calculate month timestamps for {month_name}: {e}")
                # Keep the default previous month values that were already set
                logger.info(
                    f"Falling back to default previous month: {start_of_month.strftime('%Y-%m-%d')} to {end_of_month.strftime('%Y-%m-%d')}")
        else:
            logger.info("AutoTask using default previous month")

        # Dates for API queries
        start_date_str = start_of_month.strftime("%Y-%m-%d")
        end_date_str = end_of_month.strftime("%Y-%m-%d")

        # Year and month for the monthly issue type query
        target_month_year = start_of_month.year
        target_month_number = start_of_month.month

        logger.debug(f"AutoTask ticket metrics for {start_date_str} to {end_date_str}")

        async with AutotaskClient(self.config) as autotask_client:
            try:
                logger.debug("Fetching created vs completed tickets...")
                data['created_vs_completed'] = await autotask_client.get_created_vs_completed_tickets(
                    start_date_str, end_date_str, company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch created vs completed tickets: {e}")
                data['created_vs_completed'] = {}

            try:
                logger.debug("Fetching monthly tickets by issue type...")
                data['monthly_by_issue_type'] = await autotask_client.get_monthly_tickets_by_issue_type(
                    target_month_year, target_month_number, company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch monthly tickets by issue type: {e}")
                data['monthly_by_issue_type'] = []

            try:
                logger.debug("Fetching open tickets by priority...")
                data['open_by_priority'] = await autotask_client.get_open_tickets_by_priority(
                    target_month_year, target_month_number, company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch open tickets by priority: {e}")
                data['open_by_priority'] = []

            try:
                logger.debug("Fetching open tickets by issue/sub-issue type...")
                data['open_by_issue_subissue'] = await autotask_client.get_open_tickets_by_issue_subissue(
                    target_month_year, target_month_number, company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch open tickets by issue/sub-issue type: {e}")
                data['open_by_issue_subissue'] = []

            try:
                logger.debug("Fetching active tickets by priority...")
                data['active_tickets'] = await autotask_client.get_active_tickets_by_priority(
                    top_count=10, company_id=company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch active tickets by priority: {e}")
                data['active_tickets'] = {}

            try:
                logger.debug("Fetching SLO metrics...")
                data['slo_metrics'] = await autotask_client.get_slo_metrics(start_date_str, end_date_str, company_id)
            except Exception as e:
                logger.error(f"Failed to fetch SLO metrics: {e}")
                data['slo_metrics'] = []

            try:
                logger.debug("Fetching tickets created by contact...")
                data['tickets_by_contact'] = await autotask_client.get_tickets_created_by_contact(
                    start_date_str, end_date_str, company_id=company_id
                )
            except Exception as e:
                logger.error(f"Failed to fetch tickets by contact: {e}")
                data['tickets_by_contact'] = []

        return data

    async def _fetch_six_months_data(self, company_id: int) -> Dict[str, Any]:
        """
        Fetch Autotask data for the last 6 months and aggregate it.

        Args:
            company_id: Autotask company ID for filtering

        Returns:
            Aggregated data from last 6 months
        """
        from collections import defaultdict
        from app.utils.month_selector import MonthSelector

        logger.info("=" * 60)
        logger.info("FETCHING LAST 6 MONTHS OF AUTOTASK DATA")
        logger.info("=" * 60)

        # Initialize aggregated data structure
        aggregated_data = {
            'created_vs_completed': {
                'created_count': 0,
                'completed_count': 0,
                'daily_breakdown': {
                    'days': [],
                    'date_labels': [],
                    'daily_created': [],
                    'daily_completed': []
                },
                'company_id': company_id
            },
            'monthly_by_issue_type': [],
            'open_by_priority': [],
            'open_by_issue_subissue': [],
            'active_tickets': {},
            'slo_metrics': [],
            'tickets_by_contact': []
        }

        # Get available months (request 6 months)
        month_selector = MonthSelector()
        available_months = month_selector.get_available_months(count=6)

        # Use all 6 months
        months_to_fetch = available_months

        logger.info(f"Will fetch data for {len(months_to_fetch)} months:")
        for month_info in months_to_fetch:
            logger.info(f"  • {month_info.display_name}")

        # Track issue types and contacts across all months
        issue_type_totals = defaultdict(int)
        contact_ticket_totals = defaultdict(int)
        contact_names = {}  # Map contact_id to name

        # Fetch data for each month
        async with AutotaskClient(self.config) as autotask_client:
            for month_info in months_to_fetch:
                month_name = month_info.month_name
                logger.info(f"\n📅 Processing month: {month_info.display_name}")

                try:
                    # Use pre-calculated timestamps from MonthInfo object
                    start_of_month = datetime.fromtimestamp(month_info.start_timestamp)
                    end_of_month = datetime.fromtimestamp(month_info.end_timestamp)

                    start_date_str = start_of_month.strftime("%Y-%m-%d")
                    end_date_str = end_of_month.strftime("%Y-%m-%d")
                    target_month_year = start_of_month.year
                    target_month_number = start_of_month.month

                    # 1. Created vs Completed tickets
                    try:
                        month_created_completed = await autotask_client.get_created_vs_completed_tickets(
                            start_date_str, end_date_str, company_id
                        )
                        aggregated_data['created_vs_completed']['created_count'] += month_created_completed.get('created_count', 0)
                        aggregated_data['created_vs_completed']['completed_count'] += month_created_completed.get('completed_count', 0)

                        # Aggregate daily breakdown
                        daily = month_created_completed.get('daily_breakdown', {})
                        if daily:
                            aggregated_data['created_vs_completed']['daily_breakdown']['days'].extend(daily.get('days', []))
                            aggregated_data['created_vs_completed']['daily_breakdown']['date_labels'].extend(daily.get('date_labels', []))
                            aggregated_data['created_vs_completed']['daily_breakdown']['daily_created'].extend(daily.get('daily_created', []))
                            aggregated_data['created_vs_completed']['daily_breakdown']['daily_completed'].extend(daily.get('daily_completed', []))

                        logger.info(f"  ✅ Created/Completed: {month_created_completed.get('created_count', 0)}/{month_created_completed.get('completed_count', 0)}")
                    except Exception as e:
                        logger.error(f"  ❌ Failed to fetch created/completed for {month_name}: {e}")

                    # 2. Monthly tickets by issue type
                    try:
                        month_by_issue = await autotask_client.get_monthly_tickets_by_issue_type(
                            target_month_year, target_month_number, company_id
                        )
                        for issue_data in month_by_issue:
                            issue_type = issue_data.get('issue_type', 'Unknown')
                            count = issue_data.get('count', 0)
                            issue_type_totals[issue_type] += count

                        logger.info(f"  ✅ Issue types: {len(month_by_issue)} categories")
                    except Exception as e:
                        logger.error(f"  ❌ Failed to fetch issue types for {month_name}: {e}")

                    # 3. Open tickets by priority (use latest month only)
                    if month_info == months_to_fetch[0]:  # Most recent month
                        try:
                            aggregated_data['open_by_priority'] = await autotask_client.get_open_tickets_by_priority(
                                target_month_year, target_month_number, company_id
                            )
                            logger.info(f"  ✅ Open by priority: {len(aggregated_data['open_by_priority'])} priority levels")
                        except Exception as e:
                            logger.error(f"  ❌ Failed to fetch open by priority: {e}")

                    # 4. Open tickets by issue/subissue (use latest month only)
                    if month_info == months_to_fetch[0]:  # Most recent month
                        try:
                            aggregated_data['open_by_issue_subissue'] = await autotask_client.get_open_tickets_by_issue_subissue(
                                target_month_year, target_month_number, company_id
                            )
                            logger.info(f"  ✅ Open by issue/subissue: {len(aggregated_data['open_by_issue_subissue'])} issue types")
                        except Exception as e:
                            logger.error(f"  ❌ Failed to fetch open by issue/subissue: {e}")

                    # 5. SLO metrics
                    try:
                        month_slo = await autotask_client.get_slo_metrics(start_date_str, end_date_str, company_id)
                        aggregated_data['slo_metrics'].extend(month_slo)
                        logger.info(f"  ✅ SLO metrics: {len(month_slo)} tickets")
                    except Exception as e:
                        logger.error(f"  ❌ Failed to fetch SLO metrics for {month_name}: {e}")

                    # 6. Tickets by contact
                    try:
                        month_contacts = await autotask_client.get_tickets_created_by_contact(
                            start_date_str, end_date_str, company_id=company_id
                        )
                        for contact_data in month_contacts:
                            contact_id = contact_data.get('contact_id')
                            contact_name = contact_data.get('contact_name', 'Unknown')
                            ticket_count = contact_data.get('ticket_count', 0)

                            contact_ticket_totals[contact_id] += ticket_count
                            contact_names[contact_id] = contact_name

                        logger.info(f"  ✅ Contacts: {len(month_contacts)} unique contacts")
                    except Exception as e:
                        logger.error(f"  ❌ Failed to fetch tickets by contact for {month_name}: {e}")

                except Exception as e:
                    logger.error(f"Error processing month {month_name}: {e}")
                    continue

            # 7. Active tickets (fetch once, not month-specific)
            try:
                aggregated_data['active_tickets'] = await autotask_client.get_active_tickets_by_priority(
                    top_count=10, company_id=company_id
                )
                logger.info(f"\n✅ Active tickets: {aggregated_data['active_tickets'].get('summary', {}).get('total_active_tickets', 0)} active")
            except Exception as e:
                logger.error(f"❌ Failed to fetch active tickets: {e}")

        # Build aggregated issue type list
        aggregated_data['monthly_by_issue_type'] = [
            {
                "issue_type": issue_type,
                "count": count,
                "month": "Last 6 months",
                "company_id": company_id
            }
            for issue_type, count in sorted(issue_type_totals.items(), key=lambda x: x[1], reverse=True)
        ]

        # Build aggregated contacts list
        aggregated_data['tickets_by_contact'] = [
            {
                "contact_id": contact_id,
                "contact_name": contact_names.get(contact_id, f"Contact {contact_id}"),
                "ticket_count": count,
                "company_id": company_id
            }
            for contact_id, count in sorted(contact_ticket_totals.items(), key=lambda x: x[1], reverse=True)
        ]

        # Update period information
        aggregated_data['created_vs_completed']['period_start'] = months_to_fetch[-1].display_name  # Oldest
        aggregated_data['created_vs_completed']['period_end'] = months_to_fetch[0].display_name  # Newest

        logger.info("\n" + "=" * 60)
        logger.info("6 MONTHS DATA AGGREGATION COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Total tickets created: {aggregated_data['created_vs_completed']['created_count']}")
        logger.info(f"Total tickets completed: {aggregated_data['created_vs_completed']['completed_count']}")
        logger.info(f"Total issue types tracked: {len(aggregated_data['monthly_by_issue_type'])}")
        logger.info(f"Total contacts tracked: {len(aggregated_data['tickets_by_contact'])}")
        logger.info(f"Total SLO records: {len(aggregated_data['slo_metrics'])}")
        logger.info("=" * 60 + "\n")

        return aggregated_data

    def process_all_data(self, raw_data: Dict[str, Any], company_id: Optional[int] = None) -> Dict[str, Any]:
        """Process all Autotask raw data into final metrics."""
        # Check if we got empty data due to missing company_id
        if not raw_data or all(not v for v in raw_data.values()):
            logger.warning("No Autotask data to process - returning empty metrics")
            return {
                "autotask_metrics": {
                    "ticket_analytics": {
                        "created_vs_completed": {},
                        "monthly_by_issue_type": [],
                        "open_by_priority": [],
                        "open_by_issue_subissue": [],
                        "tickets_by_contact": []
                    },
                    "active_tickets_analysis": {},
                    "slo_performance": [],
                    "summary": {
                        "total_slo_tickets": 0,
                        "resolved_tickets": 0,
                        "resolution_sla_violations": 0,
                        "resolution_sla_percentage": 0.0,
                        "first_response_evaluated": 0,
                        "first_response_violations": 0,
                        "first_response_sla_percentage": 0.0,
                        "active_tickets_count": 0,
                        "critical_tickets": 0
                    }
                }
            }

        slo_list = raw_data.get('slo_metrics', [])

        # DEBUG: Print what we found
        print(f"DEBUG: Processing {len(slo_list)} SLO metrics records")
        if slo_list:
            print(f"DEBUG: First SLO record keys: {list(slo_list[0].keys())}")

        # Calculate SLA metrics using Autotask methodology
        # Check both resolved_date (SLA contract) and completed_date (fallback) for resolved tickets
        resolved_tickets = [t for t in slo_list if t.get('resolved_date') is not None or t.get('completed_date') is not None]
        resolution_violations = len([t for t in resolved_tickets if t.get('sla_met') is False])

        # First Response SLA violations
        first_response_evaluated = [t for t in slo_list if t.get('first_response_met') is not None]
        first_response_violations = len([t for t in first_response_evaluated if t.get('first_response_met') is False])

        print(f"DEBUG: Resolved tickets: {len(resolved_tickets)}, Resolution violations: {resolution_violations}")
        print(
            f"DEBUG: First response evaluated: {len(first_response_evaluated)}, FR violations: {first_response_violations}")

        # Calculate percentages for summary
        resolution_sla_percentage = 0.0
        if resolved_tickets:
            resolution_sla_percentage = ((len(resolved_tickets) - resolution_violations) / len(resolved_tickets)) * 100

        first_response_sla_percentage = 0.0
        if first_response_evaluated:
            first_response_sla_percentage = ((len(first_response_evaluated) - first_response_violations) / len(
                first_response_evaluated)) * 100

        print(
            f"DEBUG: Resolution SLA: {resolution_sla_percentage:.1f}%, First Response SLA: {first_response_sla_percentage:.1f}%")

        return {
            "autotask_metrics": {
                "ticket_analytics": {
                    "created_vs_completed": raw_data.get('created_vs_completed', {}),
                    "monthly_by_issue_type": raw_data.get('monthly_by_issue_type', []),
                    "open_by_priority": raw_data.get('open_by_priority', []),
                    "open_by_issue_subissue": raw_data.get('open_by_issue_subissue', []),
                    "tickets_by_contact": raw_data.get('tickets_by_contact', [])
                },
                "active_tickets_analysis": raw_data.get('active_tickets', {}),
                "slo_performance": slo_list,
                "summary": {
                    "total_slo_tickets": len(slo_list),
                    "resolved_tickets": len(resolved_tickets),
                    "resolution_sla_violations": resolution_violations,
                    "resolution_sla_percentage": round(resolution_sla_percentage, 1),
                    "first_response_evaluated": len(first_response_evaluated),
                    "first_response_violations": first_response_violations,
                    "first_response_sla_percentage": round(first_response_sla_percentage, 1),
                    "active_tickets_count": raw_data.get('active_tickets', {}).get('summary', {}).get(
                        'total_active_tickets', 0),
                    "critical_tickets": raw_data.get('active_tickets', {}).get('summary', {}).get(
                        'critical_priority_tickets', 0)
                }
            }
        }

    async def test_connection(self) -> bool:
        """Test Autotask API connectivity."""
        try:
            async with AutotaskClient(self.config) as client:
                # Try a simple query to test connection - use current year/month for test
                from datetime import datetime
                now = datetime.now()
                test_data = await client.get_open_tickets_by_priority(now.year, now.month)
                return isinstance(test_data, list)
        except Exception as e:
            logger.error(f"Autotask connection test failed: {e}")
            return False