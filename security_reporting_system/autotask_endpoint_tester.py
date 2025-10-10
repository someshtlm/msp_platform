#!/usr/bin/env python3
"""
Standalone Autotask Endpoint Tester
=====================================

This script tests all Autotask endpoints used in the security reporting system
and displays raw API responses. It's completely isolated and won't affect any
existing scripts.

Usage:
    python autotask_endpoint_tester.py

Requirements:
    - Supabase credentials configured in .env file
    - Internet connection to Autotask API
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
import sys
import os

# Add current directory to Python path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('autotask_test.log')
    ]
)
logger = logging.getLogger(__name__)

class AutotaskEndpointTester:
    """Standalone tester for all Autotask endpoints."""

    def __init__(self):
        """Initialize with credentials from Supabase."""
        self.client = None
        self.test_results = {}
        self.load_credentials()

    def load_credentials(self):
        """Load Autotask credentials from Supabase."""
        try:
            from config.config import config_manager

            logger.info("Loading credentials from Supabase...")
            self.config = config_manager.load_credentials()
            logger.info("✅ Credentials loaded successfully")

        except Exception as e:
            logger.error(f"❌ Failed to load credentials: {e}")
            logger.error("Make sure your .env file has SUPABASE_URL, SUPABASE_KEY, and DEFAULT_CREDENTIAL_ID")
            sys.exit(1)

    async def setup_client(self):
        """Setup Autotask client with loaded credentials."""
        try:
            from src.clients.autotask_client import AutotaskClient, AutotaskConfig

            autotask_config = AutotaskConfig(
                username=self.config['autotask_username'],
                secret=self.config['autotask_secret'],
                integration_code=self.config['autotask_integration_code'],
                base_url=self.config['autotask_base_url']
            )

            self.client = AutotaskClient(autotask_config)
            await self.client.__aenter__()

            logger.info("✅ Autotask client initialized successfully")
            logger.info(f"Base URL: {self.config['autotask_base_url']}")
            logger.info(f"Username: {self.config['autotask_username']}")

        except Exception as e:
            logger.error(f"❌ Failed to setup Autotask client: {e}")
            raise

    async def cleanup_client(self):
        """Cleanup Autotask client."""
        if self.client:
            await self.client.__aexit__(None, None, None)
            logger.info("🧹 Autotask client cleaned up")

    def get_test_parameters(self) -> Dict[str, Any]:
        """Get test parameters for API calls."""
        # Use August 2025 for testing (matches main system)
        return {
            'start_date': '2025-04-12',
            'end_date': '2025-10-12',
            'year': 2025,
            'month': 9,
            'company_id': 625
        }

    async def test_endpoint_1_created_vs_completed(self, params: Dict) -> Dict[str, Any]:
        """Test: Daily Tickets Created vs Completed"""
        logger.info("🔍 Testing Endpoint 1: Created vs Completed Tickets")

        try:
            result = await self.client.get_created_vs_completed_tickets(
                start_date=params['start_date'],
                end_date=params['end_date'],
                company_id=params['company_id']
            )

            logger.info(f"✅ Created vs Completed: Success")
            logger.info(f"   - Created tickets: {result.get('created_count', 0)}")
            logger.info(f"   - Completed tickets: {result.get('completed_count', 0)}")
            logger.info(f"   - Daily breakdown days: {len(result.get('daily_breakdown', {}).get('days', []))}")

            return {
                'endpoint': 'get_created_vs_completed_tickets',
                'status': 'success',
                'data': result,
                'summary': {
                    'created_count': result.get('created_count', 0),
                    'completed_count': result.get('completed_count', 0),
                    'has_daily_breakdown': bool(result.get('daily_breakdown'))
                }
            }

        except Exception as e:
            logger.error(f"❌ Created vs Completed failed: {e}")
            return {
                'endpoint': 'get_created_vs_completed_tickets',
                'status': 'error',
                'error': str(e)
            }

    async def test_endpoint_2_monthly_by_issue_type(self, params: Dict) -> Dict[str, Any]:
        """Test: Monthly Tickets by Issue Type"""
        logger.info("🔍 Testing Endpoint 2: Monthly Tickets by Issue Type")

        try:
            result = await self.client.get_monthly_tickets_by_issue_type(
                year=params['year'],
                month=params['month'],
                company_id=params['company_id']
            )

            logger.info(f"✅ Monthly by Issue Type: Success")
            logger.info(f"   - Issue types found: {len(result)}")
            if result:
                logger.info(f"   - Top issue type: {result[0].get('issue_type', 'Unknown')} ({result[0].get('count', 0)} tickets)")

            return {
                'endpoint': 'get_monthly_tickets_by_issue_type',
                'status': 'success',
                'data': result,
                'summary': {
                    'issue_types_count': len(result),
                    'total_tickets': sum(item.get('count', 0) for item in result),
                    'top_issue_type': result[0].get('issue_type') if result else None
                }
            }

        except Exception as e:
            logger.error(f"❌ Monthly by Issue Type failed: {e}")
            return {
                'endpoint': 'get_monthly_tickets_by_issue_type',
                'status': 'error',
                'error': str(e)
            }

    async def test_endpoint_3_open_by_priority(self, params: Dict) -> Dict[str, Any]:
        """Test: Open Tickets by Priority"""
        logger.info("🔍 Testing Endpoint 3: Open Tickets by Priority")

        try:
            # Match original: get_open_tickets_by_priority(year, month, company_id)
            from datetime import datetime
            now = datetime.now()
            result = await self.client.get_open_tickets_by_priority(now.year, now.month, params['company_id'])

            logger.info(f"✅ Open by Priority: Success")
            logger.info(f"   - Priority levels found: {len(result)}")
            total_open = sum(item.get('count', 0) for item in result)
            logger.info(f"   - Total open tickets: {total_open}")

            return {
                'endpoint': 'get_open_tickets_by_priority',
                'status': 'success',
                'data': result,
                'summary': {
                    'priority_levels': len(result),
                    'total_open_tickets': total_open,
                    'highest_priority': result[0].get('priority') if result else None
                }
            }

        except Exception as e:
            logger.error(f"❌ Open by Priority failed: {e}")
            return {
                'endpoint': 'get_open_tickets_by_priority',
                'status': 'error',
                'error': str(e)
            }

    async def test_endpoint_4_active_by_priority(self, params: Dict) -> Dict[str, Any]:
        """Test: Active Tickets by Priority"""
        logger.info("🔍 Testing Endpoint 4: Active Tickets by Priority")

        try:
            # Match original: get_active_tickets_by_priority(top_count=10, company_id=company_id)
            result = await self.client.get_active_tickets_by_priority(
                top_count=10,
                company_id=params['company_id']
            )

            logger.info(f"✅ Active by Priority: Success")
            summary = result.get('summary', {})
            logger.info(f"   - Total active tickets: {summary.get('total_active_tickets', 0)}")
            logger.info(f"   - Overdue tickets: {summary.get('overdue_tickets', 0)}")
            logger.info(f"   - Critical tickets: {summary.get('critical_priority_tickets', 0)}")

            return {
                'endpoint': 'get_active_tickets_by_priority',
                'status': 'success',
                'data': result,
                'summary': {
                    'total_active': summary.get('total_active_tickets', 0),
                    'overdue_count': summary.get('overdue_tickets', 0),
                    'critical_count': summary.get('critical_priority_tickets', 0),
                    'top_tickets_returned': len(result.get('top_priority_tickets', []))
                }
            }

        except Exception as e:
            logger.error(f"❌ Active by Priority failed: {e}")
            return {
                'endpoint': 'get_active_tickets_by_priority',
                'status': 'error',
                'error': str(e)
            }

    async def test_endpoint_5_slo_metrics(self, params: Dict) -> Dict[str, Any]:
        """Test: SLO Metrics"""
        logger.info("🔍 Testing Endpoint 5: SLO Metrics")

        try:
            result = await self.client.get_slo_metrics(
                start_date=params['start_date'],
                end_date=params['end_date'],
                company_id=params['company_id']
            )

            logger.info(f"✅ SLO Metrics: Success")
            logger.info(f"   - SLO records: {len(result)}")

            # Calculate SLA stats
            resolved_tickets = [t for t in result if t.get('completed_date')]
            sla_met_count = len([t for t in resolved_tickets if t.get('sla_met') is True])
            first_response_evaluated = [t for t in result if t.get('first_response_met') is not None]

            logger.info(f"   - Resolved tickets: {len(resolved_tickets)}")
            logger.info(f"   - SLA met: {sla_met_count}")
            logger.info(f"   - First response evaluated: {len(first_response_evaluated)}")

            return {
                'endpoint': 'get_slo_metrics',
                'status': 'success',
                'data': result,
                'summary': {
                    'total_slo_records': len(result),
                    'resolved_tickets': len(resolved_tickets),
                    'sla_met_count': sla_met_count,
                    'first_response_evaluated': len(first_response_evaluated)
                }
            }

        except Exception as e:
            logger.error(f"❌ SLO Metrics failed: {e}")
            return {
                'endpoint': 'get_slo_metrics',
                'status': 'error',
                'error': str(e)
            }

    async def test_endpoint_0_entity_fields(self, params: Dict) -> Dict[str, Any]:
        """Test Tickets Entity Information endpoint to see all available fields."""
        endpoint = "/v1.0/Tickets/entityInformation/fields"
        logger.info(f"Testing: {endpoint}")

        try:
            # Call the entity info method directly
            entity_info = await self.client.get_entity_info("Tickets")

            logger.info(f"✅ Successfully retrieved entity information")

            # Extract field names and picklist fields
            fields_list = entity_info.get('fields', [])
            logger.info(f"📊 Total fields available: {len(fields_list)}")

            # Find issueType and subIssueType fields specifically
            issue_fields = []
            for field in fields_list:
                field_name = field.get('name', '')
                if 'issue' in field_name.lower() or 'sub' in field_name.lower():
                    issue_fields.append({
                        'name': field_name,
                        'label': field.get('label', ''),
                        'dataType': field.get('dataType', ''),
                        'isPickList': field.get('isPickList', False),
                        'picklistParentValueField': field.get('picklistParentValueField', '')
                    })

            logger.info(f"🔍 Found {len(issue_fields)} issue-related fields:")
            for field in issue_fields:
                logger.info(f"   - {field['name']} ({field['dataType']}) - PickList: {field['isPickList']}")

            # Save full entity info to file
            output_file = 'autotask_entity_fields_raw.json'
            with open(output_file, 'w') as f:
                json.dump(entity_info, f, indent=2)
            logger.info(f"💾 Full entity info saved to: {output_file}")

            return {
                'endpoint': endpoint,
                'status': 'success',
                'total_fields': len(fields_list),
                'issue_related_fields': issue_fields,
                'data': entity_info
            }

        except Exception as e:
            logger.error(f"❌ Error: {str(e)}")
            return {
                'endpoint': endpoint,
                'status': 'failed',
                'error': str(e)
            }

    async def test_endpoint_7_raw_tickets_query(self) -> Dict[str, Any]:
        """Test: Raw Tickets Query with hardcoded date range and company_id."""

        endpoint = "/v1.0/Tickets/query"
        logger.info(f"Testing: {endpoint}")

        try:
            # Hardcoded date range and company ID
            start_date = "2025-04-12T00:00:00"
            end_date = "2025-10-12T23:59:59"
            company_id = 625

            filters = [
                {"field": "createDate", "op": "gte", "value": start_date},
                {"field": "createDate", "op": "lte", "value": end_date},
                {"field": "companyID", "op": "eq", "value": company_id}
            ]

            # Fetch tickets with issueType and subIssueType fields
            fields = ['id', 'ticketNumber', 'status', 'issueType', 'subIssueType', 'title', 'createDate']

            logger.info(f"Fetching tickets with filters: {filters}")
            tickets = await self.client.query("Tickets", filters=filters, fields=fields, max_records=100)

            logger.info(f"✅ Retrieved {len(tickets)} tickets")

            # Sample first 5 tickets for inspection
            sample_tickets = tickets[:5] if tickets else []

            logger.info(f"📊 Sample tickets (first 5):")
            for i, ticket in enumerate(sample_tickets, 1):
                logger.info(f"   Ticket {i}:")
                logger.info(f"      ID: {ticket.get('id')}, Number: {ticket.get('ticketNumber')}")
                logger.info(
                    f"      Status: {ticket.get('status')}, IssueType: {ticket.get('issueType')}, SubIssueType: {ticket.get('subIssueType')}")
                logger.info(f"      Title: {ticket.get('title', 'N/A')[:50]}...")

            # Count tickets by issueType and subIssueType
            from collections import Counter
            issue_type_counts = Counter(t.get('issueType') for t in tickets if t.get('issueType') is not None)
            sub_issue_type_counts = Counter(t.get('subIssueType') for t in tickets if t.get('subIssueType') is not None)

            logger.info(f"📈 Issue Type distribution: {dict(issue_type_counts)}")
            logger.info(f"📈 Sub-Issue Type distribution: {dict(sub_issue_type_counts)}")

            # Save to file
            output_file = 'autotask_raw_tickets_query.json'
            with open(output_file, 'w') as f:
                json.dump({
                    'total_tickets': len(tickets),
                    'filters': filters,
                    'fields': fields,
                    'sample_tickets': sample_tickets,
                    'all_tickets': tickets,
                    'issue_type_counts': dict(issue_type_counts),
                    'sub_issue_type_counts': dict(sub_issue_type_counts)
                }, f, indent=2)
            logger.info(f"💾 Raw tickets data saved to: {output_file}")

            return {
                'endpoint': endpoint,
                'status': 'success',
                'total_tickets': len(tickets),
                'issue_type_counts': dict(issue_type_counts),
                'sub_issue_type_counts': dict(sub_issue_type_counts),
                'sample_tickets': sample_tickets
            }

        except Exception as e:
            logger.error(f"❌ Error: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                'endpoint': endpoint,
                'status': 'failed',
                'error': str(e)
            }

    async def test_endpoint_6_tickets_by_contact(self, params: Dict) -> Dict[str, Any]:
        """Test: Tickets Created by Contact"""
        logger.info("🔍 Testing Endpoint 6: Tickets by Contact")

        try:
            # Match original: get_tickets_created_by_contact(start_date_str, end_date_str, company_id=company_id)
            result = await self.client.get_tickets_created_by_contact(
                start_date=params['start_date'],
                end_date=params['end_date'],
                contact_id=None,
                company_id=params['company_id']
            )

            logger.info(f"✅ Tickets by Contact: Success")
            logger.info(f"   - Contacts found: {len(result)}")
            total_tickets = sum(item.get('ticket_count', 0) for item in result)
            logger.info(f"   - Total tickets: {total_tickets}")
            if result:
                logger.info(f"   - Top contact: {result[0].get('contact_name')} ({result[0].get('ticket_count')} tickets)")

            return {
                'endpoint': 'get_tickets_created_by_contact',
                'status': 'success',
                'data': result,
                'summary': {
                    'contacts_count': len(result),
                    'total_tickets': total_tickets,
                    'top_contact': result[0].get('contact_name') if result else None
                }
            }

        except Exception as e:
            logger.error(f"❌ Tickets by Contact failed: {e}")
            return {
                'endpoint': 'get_tickets_created_by_contact',
                'status': 'error',
                'error': str(e)
            }

    async def test_all_endpoints(self):
        """Test all Autotask endpoints and collect results."""
        logger.info("🚀 Starting Autotask Endpoint Testing")
        logger.info("=" * 60)

        await self.setup_client()

        # Get test parameters
        params = self.get_test_parameters()
        logger.info(f"📅 Test Parameters:")
        logger.info(f"   - Date Range: {params['start_date']} to {params['end_date']}")
        logger.info(f"   - Year/Month: {params['year']}/{params['month']}")
        logger.info(f"   - Company ID: {params['company_id'] or 'All companies'}")
        logger.info("")

        # Test all endpoints
        test_functions = [
            self.test_endpoint_0_entity_fields,  # NEW: Test entity fields first
            self.test_endpoint_1_created_vs_completed,
            self.test_endpoint_2_monthly_by_issue_type,
            self.test_endpoint_3_open_by_priority,
            self.test_endpoint_4_active_by_priority,
            self.test_endpoint_5_slo_metrics,
            self.test_endpoint_6_tickets_by_contact,
            self.test_endpoint_7_raw_tickets_query  # NEW: Test raw tickets query
        ]

        for i, test_func in enumerate(test_functions, 1):
            logger.info(f"📋 Test {i}/{len(test_functions)}: {test_func.__name__}")
            result = await test_func(params)
            self.test_results[f"test_{i}"] = result
            logger.info("")

        await self.cleanup_client()

        # Generate summary
        self.generate_summary()

    def generate_summary(self):
        """Generate and save test summary."""
        logger.info("📊 TEST SUMMARY")
        logger.info("=" * 60)

        successful_tests = []
        failed_tests = []

        for test_key, result in self.test_results.items():
            endpoint = result.get('endpoint', 'Unknown')
            status = result.get('status', 'Unknown')

            if status == 'success':
                successful_tests.append(endpoint)
                logger.info(f"✅ {endpoint}: SUCCESS")
                if 'summary' in result:
                    for key, value in result['summary'].items():
                        logger.info(f"      {key}: {value}")
            else:
                failed_tests.append(endpoint)
                logger.info(f"❌ {endpoint}: FAILED")
                logger.info(f"      Error: {result.get('error', 'Unknown error')}")

        logger.info("")
        logger.info(f"📈 OVERALL RESULTS:")
        logger.info(f"   - Successful: {len(successful_tests)}/6")
        logger.info(f"   - Failed: {len(failed_tests)}/6")

        # Save detailed results to file
        output_file = f"autotask_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'test_timestamp': datetime.now().isoformat(),
                    'test_parameters': self.get_test_parameters(),
                    'results': self.test_results,
                    'summary': {
                        'successful_tests': successful_tests,
                        'failed_tests': failed_tests,
                        'success_rate': f"{len(successful_tests)}/6"
                    }
                }, f, indent=2, default=str)

            logger.info(f"💾 Detailed results saved to: {output_file}")

        except Exception as e:
            logger.error(f"❌ Failed to save results file: {e}")

import asyncio
import json

async def main():
    tester = AutotaskEndpointTester()
    await tester.setup_client()

    # Only run endpoint 7 with hardcoded filters
    result = await tester.test_endpoint_7_raw_tickets_query()

    await tester.cleanup_client()

    # Pretty print the result
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    asyncio.run(main())