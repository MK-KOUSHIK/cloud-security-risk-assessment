from azure.mgmt.storage import StorageManagementClient

from backend.azure_auth import get_azure_credential
from backend.config import AZURE_SUBSCRIPTION_ID


RESOURCE_GROUP_NAME = "cloud-risk-assessment-rg"
STORAGE_ACCOUNT_NAME = "cloudriskstorage01"


def get_storage_security_config():
    credential = get_azure_credential()

    client = StorageManagementClient(
        credential,
        AZURE_SUBSCRIPTION_ID
    )

    account = client.storage_accounts.get_properties(
        resource_group_name=RESOURCE_GROUP_NAME,
        account_name=STORAGE_ACCOUNT_NAME
    )

    return {
        "name": account.name,
        "location": account.location,
        "https_only": account.enable_https_traffic_only,
        "public_blob_access": account.allow_blob_public_access,
        "minimum_tls_version": account.minimum_tls_version,
    }