from config import validate_config
from azure_scanner import get_resources


validate_config()

resources = get_resources()

print("\nAzure resources:\n")

for resource in resources:
    print(
        f"{resource['name']} | "
        f"{resource['type']} | "
        f"{resource['location']}"
    )