# organization_service.py
import re
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
# Add path resolution for local running
import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
security_system_root = os.path.join(current_dir, '..', '..')
if security_system_root not in sys.path:
    sys.path.insert(0, security_system_root)

# Smart imports - try absolute first (for msp_endpoints), fallback to relative (for standalone)
try:
    from security_reporting_system.config.supabase_client import SupabaseCredentialManager
except ImportError:
    from config.supabase_client import SupabaseCredentialManager

logger = logging.getLogger(__name__)


class OrganizationMappingService:
    def __init__(self):
        self.supabase_manager = SupabaseCredentialManager()
        self.supabase = self.supabase_manager.supabase

    def normalize_name(self, name: str) -> str:
        """Simple name normalization for matching"""
        if not name:
            return ""

        cleaned = name.lower()
        # Remove common business suffixes
        cleaned = re.sub(r'\s+(inc|llc|ltd|corp|pllc|co)\.?$', '', cleaned)
        # Remove location indicators
        cleaned = re.sub(r'\s+#\d+', '', cleaned)  # Remove "#64325"
        # Remove punctuation and normalize spaces
        cleaned = re.sub(r'[^\w\s]', '', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        return cleaned.strip()

    def find_name_match(self, target_name: str, candidates: List[Dict]) -> Optional[Dict]:
        """Find exact match after normalization"""
        normalized_target = self.normalize_name(target_name)

        for candidate in candidates:
            candidate_name = candidate.get('name') or candidate.get('companyName')
            if self.normalize_name(candidate_name) == normalized_target:
                return candidate
        return None

    def get_mapping_by_ninjaone_id(self, ninjaone_org_id: str) -> Optional[Dict]:
        """Get existing mapping by NinjaOne org ID"""
        try:
            response = self.supabase.table('organization_mapping').select("*").eq('ninjaone_org_id',
                                                                                  ninjaone_org_id).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Error fetching mapping: {e}")
            return None

    def save_mapping(self, mapping: Dict) -> bool:
        """Save or update organization mapping"""
        try:
            # Check if mapping exists
            existing = self.get_mapping_by_ninjaone_id(mapping['ninjaone_org_id'])

            if existing:
                # Update existing
                response = self.supabase.table('organization_mapping').update(mapping).eq('ninjaone_org_id', mapping[
                    'ninjaone_org_id']).execute()
            else:
                # Insert new
                response = self.supabase.table('organization_mapping').insert(mapping).execute()

            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Error saving mapping: {e}")
            return False

    def create_mapping_for_org(self, ninja_org: Dict, autotask_companies: List[Dict],
                               connectsecure_companies: List[Dict]) -> Dict:
        """Create mapping for a single NinjaOne organization using source_id technique"""
        # USE NINJAONE NAME as the primary organization_name
        mapping = {
            'ninjaone_org_id': str(ninja_org['id']),
            'organization_name': ninja_org['name'],  # Always use NinjaOne name
            'autotask_company_id': None,
            'connectsecure_company_id': None,
            'last_synced': datetime.now().isoformat()
        }

        # STEP 1: Find ConnectSecure match by name
        cs_match = self.find_name_match(ninja_org['name'], connectsecure_companies)

        if cs_match:
            mapping['connectsecure_company_id'] = cs_match['id']

            # STEP 2: Use source_id to find Autotask match (MOST RELIABLE)
            source_id = cs_match.get('source_id')
            if source_id:
                # Look for Autotask company with matching ID
                autotask_match = next(
                    (company for company in autotask_companies if str(company['id']) == source_id),
                    None
                )
                if autotask_match:
                    mapping['autotask_company_id'] = autotask_match['id']
                    logger.info(f"SOURCE_ID mapping: {ninja_org['name']} → Autotask ID {source_id}")
                    return mapping

        # STEP 3: Fallback - try direct name matching for Autotask
        if not mapping['autotask_company_id']:
            autotask_match = self.find_name_match(ninja_org['name'], autotask_companies)
            if autotask_match:
                mapping['autotask_company_id'] = autotask_match['id']
                logger.info(f" NAME mapping: {ninja_org['name']} → Autotask")

        # STEP 4: If no ConnectSecure found yet, try direct name match
        if not mapping['connectsecure_company_id']:
            cs_direct_match = self.find_name_match(ninja_org['name'], connectsecure_companies)
            if cs_direct_match:
                mapping['connectsecure_company_id'] = cs_direct_match['id']
                logger.info(f"NAME mapping: {ninja_org['name']} → ConnectSecure")

        return mapping


    def sync_all_organizations(self, ninja_orgs: List[Dict], autotask_companies: List[Dict],
                               connectsecure_companies: List[Dict]) -> Dict:
        """Sync all organizations and create mappings"""
        results = {
            'total_processed': 0,
            'new_mappings': 0,
            'updated_mappings': 0,
            'errors': 0,
            'source_id_matches': 0,
            'name_only_matches': 0,
            'ninjaone_only': 0
        }
        # Handle case where API calls returned exceptions instead of lists
        if not isinstance(ninja_orgs, list):
            logger.error(f"ninja_orgs is not a list: {type(ninja_orgs)}")
            ninja_orgs = []

        if not isinstance(autotask_companies, list):
            logger.error(f"autotask_companies is not a list: {type(autotask_companies)}")
            autotask_companies = []

        if not isinstance(connectsecure_companies, list):
            logger.error(f"connectsecure_companies is not a list: {type(connectsecure_companies)}")
            connectsecure_companies = []

        for ninja_org in ninja_orgs:
            try:
                mapping = self.create_mapping_for_org(ninja_org, autotask_companies, connectsecure_companies)

                # Track mapping types
                if mapping['autotask_company_id'] and mapping['connectsecure_company_id']:
                    results['source_id_matches'] += 1
                elif mapping['autotask_company_id'] or mapping['connectsecure_company_id']:
                    results['name_only_matches'] += 1
                else:
                    results['ninjaone_only'] += 1

                existing = self.get_mapping_by_ninjaone_id(mapping['ninjaone_org_id'])

                if self.save_mapping(mapping):
                    if existing:
                        results['updated_mappings'] += 1
                    else:
                        results['new_mappings'] += 1
                else:
                    results['errors'] += 1

                results['total_processed'] += 1

            except Exception as e:
                logger.error(f"Error processing org {ninja_org.get('name')}: {e}")
                results['errors'] += 1

        return results

    def get_all_mappings(self) -> List[Dict]:
        """Get all organization mappings"""
        try:
            response = self.supabase.table('organization_mapping').select("*").execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching all mappings: {e}")
            return []