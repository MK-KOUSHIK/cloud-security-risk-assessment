from azure.mgmt.storage import StorageManagementClient

from backend.azure_auth import get_azure_credential
from backend.config import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_RESOURCE_GROUP,
    AZURE_STORAGE_ACCOUNT,
)


def get_storage_security_config(resource_group_name=None, account_name=None):
    rg_name = resource_group_name or AZURE_RESOURCE_GROUP
    target_account = account_name or AZURE_STORAGE_ACCOUNT

    credential = get_azure_credential()

    client = StorageManagementClient(
        credential,
        AZURE_SUBSCRIPTION_ID
    )

    account = client.storage_accounts.get_properties(
        resource_group_name=rg_name,
        account_name=target_account
    )

    nrs = getattr(account, "network_rule_set", None)
    if nrs is not None:
        if hasattr(nrs, "default_action"):
            default_action = str(nrs.default_action)
        elif isinstance(nrs, dict):
            default_action = str(
                nrs.get("default_action") or nrs.get("defaultAction") or ""
            )
        else:
            default_action = str(nrs)
    else:
        default_action = None

    pna = getattr(account, "public_network_access", None)
    public_network_access = str(pna) if pna is not None else None

    allow_shared_key = getattr(account, "allow_shared_key_access", None)

    return {
        "name": account.name,
        "location": account.location,
        "https_only": account.enable_https_traffic_only,
        "public_blob_access": account.allow_blob_public_access,
        "minimum_tls_version": account.minimum_tls_version,
        "allow_shared_key_access": allow_shared_key,
        "default_network_action": default_action,
        "public_network_access": public_network_access,
    }