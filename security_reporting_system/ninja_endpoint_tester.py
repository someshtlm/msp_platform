import base64
import time
import json
import requests
import os
from datetime import datetime
from typing import Optional, Dict, List, Any

# NinjaOne Configuration
NINJA_INSTANCE_URL = "https://teamlogicitneaustin.rmmservice.com"
NINJA_BASE_URL = NINJA_INSTANCE_URL.rstrip("/")
NINJA_AUTH_URL = f"{NINJA_BASE_URL}/oauth/token"

NINJA_ENDPOINTS = {
    # "OS-Patch-Installs": "/v2/queries/os-patch-installs?df=org%3D41&installedAfter=2025-07-01&installedBefore=2025-07-31&status=INSTALLED",#installedAfterinstalledBefore
    # "Software-Patch-Installs": "/v2/queries/software-patch-installs?df=org=41&installedAfter=2025-07-01&installedBefore=2025-07-31" #installedAfterinstalledBefore
    # "devices": "/v2/devices?df=org%3D41%20AND%20created%20after%202025-08-01%20AND%20created%20before%202025-08-31"#uses created after and created before
    # "Alerts": "/v2/alerts"
    # "activities": "/v2/activities"
    # "scripts": "/v2/automation/scripts"
    # "Organizations": "/v2/organizations"
    # "Policies": "/v2/policies"
    # "Tasks": "/v2/tasks"
# /v2/queries/os-patch-installs?df=org%3D41%26status%3DFAILED&installedBefore=2025-08-31&installedAfter=2025-08-01'
    #  "test":    "/v2/queries/os-patches?df=org%3D41" #no query for montly filtering
     # "test": "/v2/queries/os-patch-installs?org%3D41%20"
    # "test":  "/v2/devices-detailed?df=org=41&createdafter=&createdbefore=2025-07-31"
    #         "test": "/v2/queries/os-patch-installs?df=org=41" #
    #  "test": "/v2/devices-detailed?df=org%3D41"
    #                   "test":  "/v2/queries/software-patch-installs?df=org=41&installedAfter=2025-08-01&installedBefore=2025-08-31"
    #     "test": "/v2/queries/os-patch-installs?df=org=41&installedAfter=2025-08-01&installedBefore=2025-08-31"
    # "test": "/v2/queries/os-patch-installs?df=org=41&installedAfter=2025-08-01&installedBefore=2025-08-31"
    # "test": "/v2/devices-detailed?df=org=54",
     "test": "/v2/queries/os-patch-installs?df=org=41&installedAfter=2025-10-01&installedBefore=2025-10-31"
    #    "test":     "/v2/queries/software-patch-installs?df=org=41&installedAfter=2025-08-01&installedBefore=2025-08-31"
    #  "test": "/v2/queries/software-patches?df=org=41&installedAfter=2025-08-01&installedBefore=2025-08-31"
    #          "test": "/v2/queries/software-patches?df=org=41"
}


# Global variables for token management
_ninja_token: Optional[str] = None
_ninja_token_expiry: float = 0.0


def get_ninjaone_token() -> str:
    """Get NinjaOne API token using OAuth 2.0 client credentials flow."""
    global _ninja_token, _ninja_token_expiry

    # Return existing token if still valid
    if _ninja_token and time.time() < _ninja_token_expiry:
        print("✅ Using existing valid token")
        return _ninja_token

    print("🔐 Requesting new NinjaOne API token...")

    # OAuth 2.0 Client Credentials Flow
    auth_string = f"{NINJA_CLIENT_ID}:{NINJA_CLIENT_SECRET}"
    auth_b64 = base64.b64encode(auth_string.encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    data = {
        "grant_type": "client_credentials",
        "scope": "monitoring management"  # Add 'control' if remote access needed
    }

    try:
        resp = requests.post(NINJA_AUTH_URL, headers=headers, data=data, timeout=30)
        print(f"   → Status: {resp.status_code}")

        if resp.status_code == 200:
            payload = resp.json()

            token = payload.get("access_token")
            expires_in = payload.get("expires_in", 3600)
            token_type = payload.get("token_type", "Bearer")

            if token:
                _ninja_token = token
                _ninja_token_expiry = time.time() + expires_in - 300  # 5 min buffer
                print(f"   ✅ Successfully authenticated!")
                print(f"   🔑 Token type: {token_type}")
                print(f"   🔑 Token: {token[:20]}...")
                print(f"   ⏰ Expires in: {expires_in} seconds")
                return _ninja_token
            else:
                raise RuntimeError("Token response missing access_token")
        else:
            error_detail = ""
            try:
                error_response = resp.json()
                error_detail = f": {error_response.get('error_description', error_response.get('error', ''))}"
            except:
                error_detail = f": {resp.text}"
            raise RuntimeError(f"Authentication failed with status {resp.status_code}{error_detail}")

    except requests.RequestException as e:
        raise RuntimeError(f"Authentication request failed: {e}")


def make_authenticated_request(endpoint: str, params: Optional[Dict] = None, method: str = "GET") -> Optional[Dict]:
    """Make an authenticated request to NinjaOne API."""
    if not _ninja_token:
        raise RuntimeError("Not authenticated. Call get_ninjaone_token() first.")

    headers = {
        'Authorization': f'Bearer {_ninja_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    url = f"{NINJA_BASE_URL}{endpoint}"

    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, params=params, timeout=30)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=params, timeout=30)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        response.raise_for_status()
        return response.json()

    except requests.RequestException as e:
        print(f"❌ Request failed for {endpoint}: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Status code: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"   Error detail: {error_detail}")
            except:
                print(f"   Response text: {e.response.text[:200]}...")
        return None


def fetch_paginated_data(endpoint: str, limit: int = 50) -> List[Dict]:
    """Fetch paginated data from NinjaOne API endpoints using multiple pagination strategies."""
    if not _ninja_token:
        raise RuntimeError("Not authenticated.")

    headers = {
        'Authorization': f'Bearer {_ninja_token}',
        'Accept': 'application/json'
    }

    url = f"{NINJA_BASE_URL}{endpoint}"
    all_items = []

    print(f"   🔄 Fetching paginated data from {endpoint}")

    # Strategy 1: Try cursor-based pagination (after/before)
    try:
        print(f"   🧪 Trying cursor-based pagination...")
        cursor_items = _fetch_cursor_paginated(url, headers, limit)
        if cursor_items:
            all_items.extend(cursor_items)
            print(f"   ✅ Cursor pagination successful: {len(cursor_items)} items")
            return all_items
    except Exception as e:
        print(f"   ⚠️  Cursor pagination failed: {e}")

    # Strategy 2: Try offset-based pagination (limit/offset)
    try:
        print(f"   🧪 Trying offset-based pagination...")
        offset_items = _fetch_offset_paginated(url, headers, limit)
        if offset_items:
            all_items.extend(offset_items)
            print(f"   ✅ Offset pagination successful: {len(offset_items)} items")
            return all_items
    except Exception as e:
        print(f"   ⚠️  Offset pagination failed: {e}")

    # Strategy 3: Try page-based pagination (page/pageSize)
    try:
        print(f"   🧪 Trying page-based pagination...")
        page_items = _fetch_page_paginated(url, headers, limit)
        if page_items:
            all_items.extend(page_items)
            print(f"   ✅ Page pagination successful: {len(page_items)} items")
            return all_items
    except Exception as e:
        print(f"   ⚠️  Page pagination failed: {e}")

    # Strategy 4: Try simple limit-only pagination
    try:
        print(f"   🧪 Trying simple limit pagination...")
        simple_items = _fetch_simple_paginated(url, headers, limit)
        if simple_items:
            all_items.extend(simple_items)
            print(f"   ✅ Simple pagination successful: {len(simple_items)} items")
            return all_items
    except Exception as e:
        print(f"   ⚠️  Simple pagination failed: {e}")

    print(f"   ❌ All pagination strategies failed")
    return all_items


def _fetch_cursor_paginated(url: str, headers: Dict, limit: int) -> List[Dict]:
    """Try cursor-based pagination with 'after' parameter."""
    all_items = []
    after_cursor = None
    page = 1

    while True:
        params = {'limit': limit}
        if after_cursor:
            params['after'] = after_cursor

        print(f"   📄 Cursor page {page} (limit={limit}, after={after_cursor})")

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        current_batch, next_cursor = _extract_data_and_cursor(data)

        if not current_batch:
            break

        all_items.extend(current_batch)
        print(f"   📥 Got {len(current_batch)} items, total: {len(all_items)}")

        if not next_cursor or len(current_batch) < limit:
            break

        after_cursor = next_cursor
        page += 1

        if page > 1000:
            print(f"   ⚠️  Reached maximum page limit")
            break

    return all_items


def _fetch_offset_paginated(url: str, headers: Dict, limit: int) -> List[Dict]:
    """Try offset-based pagination with 'limit' and 'offset' parameters."""
    all_items = []
    offset = 0
    page = 1

    while True:
        params = {
            'limit': limit,
            'offset': offset
        }

        print(f"   📄 Offset page {page} (limit={limit}, offset={offset})")

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        current_batch, _ = _extract_data_and_cursor(data)

        if not current_batch:
            break

        all_items.extend(current_batch)
        print(f"   📥 Got {len(current_batch)} items, total: {len(all_items)}")

        if len(current_batch) < limit:
            break

        offset += limit
        page += 1

        if page > 1000:
            print(f"   ⚠️  Reached maximum page limit")
            break

    return all_items


def _fetch_page_paginated(url: str, headers: Dict, limit: int) -> List[Dict]:
    """Try page-based pagination with 'page' and 'pageSize' parameters."""
    all_items = []
    page = 1

    while True:
        params = {
            'pageSize': limit,
            'page': page
        }

        print(f"   📄 Page-based page {page} (pageSize={limit})")

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        current_batch, _ = _extract_data_and_cursor(data)

        if not current_batch:
            break

        all_items.extend(current_batch)
        print(f"   📥 Got {len(current_batch)} items, total: {len(all_items)}")

        if len(current_batch) < limit:
            break

        page += 1

        if page > 1000:
            print(f"   ⚠️  Reached maximum page limit")
            break

    return all_items


def _fetch_simple_paginated(url: str, headers: Dict, limit: int) -> List[Dict]:
    """Try simple pagination with just 'limit' parameter."""
    params = {'limit': limit}

    print(f"   📄 Simple request (limit={limit})")

    response = requests.get(url, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    data = response.json()


    current_batch, _ = _extract_data_and_cursor(data)

    if current_batch:
        print(f"   📥 Got {len(current_batch)} items")

    return current_batch


def _extract_data_and_cursor(data: Any) -> tuple[List[Dict], Optional[str]]:
    """Extract data items and next cursor from API response."""
    current_batch = []
    next_cursor = None

    if isinstance(data, list):
        current_batch = data
    elif isinstance(data, dict):
        # Look for data in common response patterns
        for data_key in ['data', 'results', 'items', 'devices', 'organizations']:
            if data_key in data and isinstance(data[data_key], list):
                current_batch = data[data_key]
                break

        # If no common data key found, look for any list
        if not current_batch:
            for key, value in data.items():
                if isinstance(value, list) and len(value) > 0:
                    current_batch = value
                    break

        # Look for cursor/pagination info
        for cursor_key in ['next_cursor', 'nextCursor', 'after', 'next', 'nextPageToken']:
            if cursor_key in data:
                next_cursor = data[cursor_key]
                break

    return current_batch, next_cursor


def analyze_response_structure(data: Any, endpoint_name: str) -> Dict[str, Any]:
    """Analyze the structure of API response data."""
    analysis = {
        "endpoint": endpoint_name,
        "data_type": type(data).__name__,
        "timestamp": datetime.now().isoformat()
    }

    if isinstance(data, dict):
        analysis["keys"] = list(data.keys())
        analysis["total_keys"] = len(data.keys())

        # Check for common pagination/response patterns
        if "data" in data:
            analysis["has_data_key"] = True
            analysis["data_type_in_data"] = type(data["data"]).__name__
            if isinstance(data["data"], list):
                analysis["data_count"] = len(data["data"])
                if data["data"]:
                    analysis["sample_data_item_keys"] = list(data["data"][0].keys()) if isinstance(data["data"][0],
                                                                                                   dict) else None

        if "nextPageToken" in data:
            analysis["has_pagination"] = True
            analysis["next_page_token"] = data["nextPageToken"]

        if "totalCount" in data:
            analysis["total_count"] = data["totalCount"]

        # Look for other interesting fields
        for key in ["results", "items", "count", "hasMore"]:
            if key in data:
                analysis[f"has_{key}"] = data[key]

    elif isinstance(data, list):
        analysis["list_length"] = len(data)
        if data and isinstance(data[0], dict):
            analysis["sample_item_keys"] = list(data[0].keys())

    return analysis


def save_raw_data(endpoint_name: str, data: Any, analysis: Dict[str, Any]) -> str:
    """Save raw data and analysis to files."""
    # Create output directory
    output_dir = "ninjaone_raw_data"
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Save raw data
    data_filename = os.path.join(output_dir, f"{endpoint_name}_raw_data_{timestamp}.json")
    with open(data_filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    # Save analysis
    analysis_filename = os.path.join(output_dir, f"{endpoint_name}_analysis_{timestamp}.json")
    with open(analysis_filename, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)

    print(f"   💾 Saved to: {data_filename}")
    print(f"   📊 Analysis: {analysis_filename}")

    return data_filename


def fetch_endpoint_data(endpoint_name: str, endpoint_path: str, use_pagination: bool = True) -> Dict[str, Any]:
    """
    Fetch raw data from a specific NinjaOne endpoint.
    """
    print(f"\n🎯 Fetching data from: {endpoint_name}")
    print(f"   📍 Endpoint: {endpoint_path}")

    try:
        if use_pagination and not '{' in endpoint_path:  # Skip pagination for parameterized endpoints
            # Try paginated approach first
            data = fetch_paginated_data(endpoint_path)
            if not data:
                print("   🔄 Pagination returned no data, trying direct request...")
                data = make_authenticated_request(endpoint_path)
        else:
            # Direct request (for endpoints that need parameters or don't support pagination)
            data = make_authenticated_request(endpoint_path)

        if data is not None:
            print(f"   ✅ Successfully fetched data from {endpoint_name}")

            # Analyze response structure
            analysis = analyze_response_structure(data, endpoint_name)

            # Save raw data
            filename = save_raw_data(endpoint_name, data, analysis)

            # Print summary
            print(f"   📊 Data type: {analysis['data_type']}")
            if analysis['data_type'] == 'dict':
                print(f"   📝 Keys: {analysis['keys']}")
                if 'data_count' in analysis:
                    print(f"   📈 Data items: {analysis['data_count']}")
            elif analysis['data_type'] == 'list':
                print(f"   📈 List length: {analysis['list_length']}")

            return {
                "success": True,
                "data": data,
                "analysis": analysis,
                "filename": filename
            }
        else:
            print(f"   ❌ Failed to fetch data from {endpoint_name}")
            return {
                "success": False,
                "error": "No data received",
                "data": None,
                "analysis": None,
                "filename": None
            }

    except Exception as e:
        print(f"   ❌ Error fetching {endpoint_name}: {e}")
        return {
            "success": False,
            "error": str(e),
            "data": None,
            "analysis": None,
            "filename": None
        }


def fetch_all_endpoints() -> Dict[str, Dict[str, Any]]:
    """
    Fetch raw data from all endpoints in NINJA_ENDPOINTS.
    """
    print("🚀 Fetching raw data from all NinjaOne endpoints...")

    # Authenticate first
    try:
        get_ninjaone_token()
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return {}

    results = {}
    successful_endpoints = 0

    for endpoint_name, endpoint_path in NINJA_ENDPOINTS.items():
        # Skip parameterized endpoints for now (they need specific device IDs)
        if '{' in endpoint_path:
            print(f"\n🚫 Skipping parameterized endpoint: {endpoint_name}")
            print(f"   📍 Path: {endpoint_path} (requires parameters)")
            results[endpoint_name] = {
                "success": False,
                "error": "Parameterized endpoint - requires specific IDs",
                "data": None,
                "analysis": None,
                "filename": None
            }
            continue

        result = fetch_endpoint_data(endpoint_name, endpoint_path)
        results[endpoint_name] = result

        if result["success"]:
            successful_endpoints += 1

    print(f"\n📊 SUMMARY:")
    print(f"   Total endpoints tested: {len(NINJA_ENDPOINTS)}")
    print(f"   Successful: {successful_endpoints}")
    print(f"   Failed: {len(NINJA_ENDPOINTS) - successful_endpoints}")
    print(
        f"   Skipped (parameterized): {sum(1 for r in results.values() if 'Parameterized endpoint' in r.get('error', ''))}")

    return results


def generate_summary_report(results: Dict[str, Dict[str, Any]]) -> None:
    """Generate a summary report of all fetched data."""
    print("\n" + "=" * 80)
    print("📋 NINJAONE API DATA SUMMARY REPORT")
    print("=" * 80)

    output_dir = "ninjaone_raw_data"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_filename = f"{output_dir}/summary_report_{timestamp}.json"

    summary_data = {
        "timestamp": datetime.now().isoformat(),
        "instance_url": NINJA_INSTANCE_URL,
        "base_url": NINJA_BASE_URL,
        "total_endpoints": len(NINJA_ENDPOINTS),
        "successful_endpoints": sum(1 for r in results.values() if r["success"]),
        "failed_endpoints": sum(1 for r in results.values() if not r["success"]),
        "endpoints": {}
    }

    for endpoint_name, result in results.items():
        endpoint_path = NINJA_ENDPOINTS[endpoint_name]

        if result["success"]:
            print(f"\n✅ {endpoint_name.upper()}")
            print(f"   📍 Path: {endpoint_path}")
            print(f"   📊 Type: {result['analysis']['data_type']}")

            analysis = result["analysis"]
            if analysis["data_type"] == "dict":
                print(f"   📝 Keys: {', '.join(analysis['keys'])}")
                if 'data_count' in analysis:
                    print(f"   📈 Items: {analysis['data_count']}")
                if 'has_pagination' in analysis:
                    print(f"   📄 Has pagination: {analysis['has_pagination']}")
            elif analysis["data_type"] == "list":
                print(f"   📈 Items: {analysis['list_length']}")
                if 'sample_item_keys' in analysis and analysis['sample_item_keys']:
                    print(f"   🔑 Sample keys: {', '.join(analysis['sample_item_keys'][:5])}...")

            print(f"   💾 File: {result['filename']}")

            # Add to summary
            summary_data["endpoints"][endpoint_name] = {
                "path": endpoint_path,
                "success": True,
                "analysis": analysis,
                "filename": result["filename"]
            }
        else:
            print(f"\n❌ {endpoint_name.upper()}")
            print(f"   📍 Path: {endpoint_path}")
            print(f"   ❌ Error: {result['error']}")

            summary_data["endpoints"][endpoint_name] = {
                "path": endpoint_path,
                "success": False,
                "error": result["error"]
            }

    # Save summary report
    with open(summary_filename, 'w', encoding='utf-8') as f:
        json.dump(summary_data, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n📋 Summary report saved to: {summary_filename}")

    # Print file locations
    print(f"\n📁 All files saved in directory: {output_dir}/")
    print("   Each endpoint has:")
    print("   • *_raw_data_*.json - Complete API response")
    print("   • *_analysis_*.json - Response structure analysis")


def main():
    """Main function to fetch raw data from all NinjaOne endpoints."""
    print("=" * 80)
    print("🥷 NinjaOne API Raw Data Fetcher")
    print("=" * 80)
    print(f"📅 Timestamp: {datetime.now().isoformat()}")
    print(f"🏢 Instance: {NINJA_INSTANCE_URL}")
    print(f"🎯 Target: {NINJA_BASE_URL}")
    print(f"📋 Endpoints to test: {len(NINJA_ENDPOINTS)}")

    # Check credentials
    if NINJA_CLIENT_ID == "your-client-id-here" or NINJA_CLIENT_SECRET == "your-client-secret-here":
        print("\n❌ CONFIGURATION ERROR:")
        print("   Please update NINJA_CLIENT_ID and NINJA_CLIENT_SECRET with your actual credentials")
        print("   You can get these from Administration > Apps > API > Client App IDs in your NinjaOne portal")
        return

    try:
        # Fetch data from all endpoints
        results = fetch_all_endpoints()

        # Generate summary report
        generate_summary_report(results)

        print("\n" + "=" * 80)
        print("✅ RAW DATA COLLECTION COMPLETED")
        print("=" * 80)
        print("🎉 All available data has been fetched and saved!")
        print("📁 Check the 'ninjaone_raw_data' directory for all files.")
        print("📊 Review the summary report for an overview of available data.")

    except Exception as e:
        print(f"\n💥 Script execution failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()