# test_organization_sync.py
import asyncio
import logging
import sys
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.services.organization_sync import OrganizationSyncService
from src.services.organization_service import OrganizationMappingService

# Setup logging to see what's happening
logging.basicConfig(level=logging.INFO)


async def test_fetch_apis():
    """Test fetching data from each API individually"""
    print("=== Testing API Connections ===")

    sync_service = OrganizationSyncService()

    # Test NinjaOne
    print("\n1. Testing NinjaOne...")
    try:
        ninja_orgs = await sync_service.fetch_ninjaone_organizations()
        print(f"NinjaOne: {len(ninja_orgs)} organizations")
        if ninja_orgs:
            print(f"   Sample: {ninja_orgs[0]['name']} (ID: {ninja_orgs[0]['id']})")
    except Exception as e:
        print(f"NinjaOne failed: {e}")

    # Test Autotask
    print("\n2. Testing Autotask...")
    try:
        autotask_companies = await sync_service.fetch_autotask_companies()
        print(f"Autotask: {len(autotask_companies)} companies")
        if autotask_companies:
            print(f"   Sample: {autotask_companies[0]['companyName']} (ID: {autotask_companies[0]['id']})")
    except Exception as e:
        print(f"Autotask failed: {e}")

    # Test ConnectSecure
    print("\n3. Testing ConnectSecure...")
    try:
        cs_companies = await sync_service.fetch_connectsecure_companies()
        print(f"ConnectSecure: {len(cs_companies)} companies")
        if cs_companies:
            print(f"   Sample: {cs_companies[0]['name']} (ID: {cs_companies[0]['id']})")
    except Exception as e:
        print(f"ConnectSecure failed: {e}")


async def test_name_matching():
    """Test the name matching logic"""
    print("\n=== Testing Name Matching ===")

    mapping_service = OrganizationMappingService()

    # Test normalization
    test_names = [
        "TeamLogic IT #64325 of East Austin, TX",
        "Texas International Education Consortium",
        "Boulder Canyon Family Dentistry, LLC"
    ]

    for name in test_names:
        normalized = mapping_service.normalize_name(name)
        print(f"'{name}' → '{normalized}'")


async def test_full_sync():
    """Test the complete sync process"""
    print("\n=== Testing Full Sync ===")

    sync_service = OrganizationSyncService()
    result = await sync_service.sync_organizations()

    if result['success']:
        print("Sync completed successfully!")
        print(f"Results: {result['results']}")
        print(f"Summary: {result['summary']}")
    else:
        print(f"Sync failed: {result['error']}")


async def test_single_org_sync():
    """Test syncing a single organization"""
    print("\n=== Testing Single Org Sync ===")

    # Use a known NinjaOne org ID (you'll need to replace this)
    test_org_id = "41"  # or whatever ID exists in your NinjaOne

    sync_service = OrganizationSyncService()
    result = await sync_service.sync_single_organization(test_org_id)

    if result['success']:
        print(f"Single org sync successful!")
        print(f"Mapping: {result['mapping']}")
    else:
        print(f"Single org sync failed: {result['error']}")


def test_database_operations():
    """Test database save/retrieve operations"""
    print("\n=== Testing Database Operations ===")

    mapping_service = OrganizationMappingService()

    # Test saving a dummy mapping
    test_mapping = {
        'ninjaone_org_id': 'test_123',
        'organization_name': 'Test Company',
        'autotask_company_id': 456,
        'connectsecure_company_id': 789,
        'last_synced': '2024-01-01T00:00:00'
    }

    # Save test mapping
    if mapping_service.save_mapping(test_mapping):
        print("Test mapping saved successfully")

        # Try to retrieve it
        retrieved = mapping_service.get_mapping_by_ninjaone_id('test_123')
        if retrieved:
            print(f"Test mapping retrieved: {retrieved['organization_name']}")

            # Clean up - delete test mapping
            mapping_service.supabase.table('organization_mapping').delete().eq('ninjaone_org_id', 'test_123').execute()
            print("Test mapping cleaned up")
        else:
            print("Failed to retrieve test mapping")
    else:
        print("Failed to save test mapping")


async def main():
    """Run all tests"""
    print("Starting Organization Sync Tests...\n")

    # Test 1: Database operations (no API calls)
    test_database_operations()

    # Test 2: Individual API connections
    await test_fetch_apis()

    # Test 3: Name matching logic
    await test_name_matching()

    # Test 4: Single org sync
    #await test_single_org_sync()

    # Test 5: Full sync (comment out initially to avoid creating too much data)
    await test_full_sync()

    print("\nTesting completed!")


if __name__ == "__main__":
    asyncio.run(main())