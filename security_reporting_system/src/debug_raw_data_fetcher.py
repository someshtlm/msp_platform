import asyncio
from src.clients.stellar_cyber_client import StellarCyberClient


async def test_list_report_configs():
    client = StellarCyberClient()
    result = await client.list_report_configs(cust_id="all-tenants")

    print("=== Stellar Cyber Report Configs ===")
    print(result)


if __name__ == "__main__":
    asyncio.run(test_list_report_configs())
