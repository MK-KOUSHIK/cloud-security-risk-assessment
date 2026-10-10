from azure.mgmt.network import NetworkManagementClient

from backend.azure_auth import get_azure_credential
from backend.config import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_RESOURCE_GROUP,
    AZURE_NSG_NAME,
)


def get_nsg_security_config(resource_group_name=None, nsg_name=None):
    rg_name = resource_group_name or AZURE_RESOURCE_GROUP
    target_nsg = nsg_name or AZURE_NSG_NAME

    credential = get_azure_credential()

    client = NetworkManagementClient(
        credential,
        AZURE_SUBSCRIPTION_ID
    )

    nsg = client.network_security_groups.get(
        rg_name,
        target_nsg
    )

    rules = []

    for rule in nsg.security_rules:
        rules.append({
            "name": rule.name,
            "direction": rule.direction,
            "access": rule.access,
            "protocol": rule.protocol,
            "source": (
                rule.source_address_prefix
                or getattr(rule, "source_address_prefixes", None)
            ),
            "source_port": (
                rule.source_port_range
                or getattr(rule, "source_port_ranges", None)
            ),
            "destination": (
                rule.destination_address_prefix
                or getattr(rule, "destination_address_prefixes", None)
            ),
            "destination_port": (
                rule.destination_port_range
                or getattr(rule, "destination_port_ranges", None)
            ),
            "priority": rule.priority,
        })

    return {
        "name": nsg.name,
        "location": nsg.location,
        "rules": rules,
    }