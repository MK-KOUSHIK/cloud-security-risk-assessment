from azure.mgmt.resource.resources import ResourceManagementClient

from backend.azure_auth import get_azure_credential
from backend.config import AZURE_SUBSCRIPTION_ID


def get_resources():
    credential = get_azure_credential()

    client = ResourceManagementClient(
        credential,
        AZURE_SUBSCRIPTION_ID
    )

    resources = client.resources.list()

    result = []

    for resource in resources:
        result.append({
            "name": resource.name,
            "type": resource.type,
            "location": resource.location,
            "id": resource.id,
        })

    return result