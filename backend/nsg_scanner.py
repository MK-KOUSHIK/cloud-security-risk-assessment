from azure.mgmt.network import NetworkManagementClient

from backend.azure_auth import get_azure_credential
from backend.config import AZURE_SUBSCRIPTION_ID


RESOURCE_GROUP_NAME = "cloud-risk-assessment-rg"
NSG_NAME = "cloud-risk-nsg"


def get_nsg_security_config():
    credential = get_azure_credential()

    client = NetworkManagementClient(
        credential,
        AZURE_SUBSCRIPTION_ID
    )

    nsg = client.network_security_groups.get(
        RESOURCE_GROUP_NAME,
        NSG_NAME
    )

    rules = []

    for rule in nsg.security_rules:
        rules.append({
            "name": rule.name,
            "direction": rule.direction,
            "access": rule.access,
            "protocol": rule.protocol,
            "source": rule.source_address_prefix,
            "source_port": rule.source_port_range,
            "destination": rule.destination_address_prefix,
            "destination_port": rule.destination_port_range,
            "priority": rule.priority,
        })

    return {
        "name": nsg.name,
        "location": nsg.location,
        "rules": rules,
    }