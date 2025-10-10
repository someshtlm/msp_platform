"""
Processors Module

This module contains data processors for different API services.
Each processor handles data fetching, processing, and analysis for its respective service.

"""

from .ninjaone_processor import NinjaOneProcessor
from .autotask_processor import AutotaskProcessor
from .connectsecure_processor import ConnectSecureProcessor

__all__ = [
    'NinjaOneProcessor',
    'AutotaskProcessor',
    'ConnectSecureProcessor',
]

__version__ = '2.0.0'
__author__ = 'TeamLogic IT'

# Processor metadata for documentation and debugging
PROCESSOR_INFO = {
    'NinjaOneProcessor': {
        'description': 'Handles NinjaOne RMM data including patch management and device inventory',
        'api_type': 'synchronous',
        'auth_method': 'OAuth 2.0 Client Credentials',
        'data_types': ['devices', 'patches', 'alerts', 'compliance'],
        'test_method': 'get_organization_info'
    },
    'AutotaskProcessor': {
        'description': 'Handles Autotask PSA data including tickets and SLA metrics',
        'api_type': 'asynchronous',
        'auth_method': 'API Key with Zone Discovery',
        'data_types': ['tickets', 'sla_metrics', 'contacts', 'priorities'],
        'test_method': 'get_open_tickets_by_priority'
    },
    'ConnectSecureProcessor': {
        'description': 'Handles ConnectSecure security data including vulnerabilities and risk scores',
        'api_type': 'asynchronous',
        'auth_method': 'Client-Auth-Token with Bearer',
        'data_types': ['vulnerabilities', 'assets', 'risk_scores', 'compliance', 'incidents'],
        'test_method': 'get_devices'
    }
}

def get_processor_info(processor_name: str = None):
    """
    Get information about available processors.

    Args:
        processor_name: Optional specific processor to get info for

    Returns:
        Dict with processor information
    """
    if processor_name:
        return PROCESSOR_INFO.get(processor_name, {})
    return PROCESSOR_INFO

def list_processors():
    """Get list of available processor names."""
    return list(__all__)

def get_processor_capabilities():
    """Get summary of all processor capabilities."""
    capabilities = {
        'total_processors': len(__all__),
        'sync_processors': [name for name, info in PROCESSOR_INFO.items()
                          if info.get('api_type') == 'synchronous'],
        'async_processors': [name for name, info in PROCESSOR_INFO.items()
                           if info.get('api_type') == 'asynchronous'],
        'data_types': set()
    }

    # Collect all unique data types
    for info in PROCESSOR_INFO.values():
        capabilities['data_types'].update(info.get('data_types', []))

    capabilities['data_types'] = sorted(list(capabilities['data_types']))
    return capabilities