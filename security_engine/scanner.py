from backend.storage_scanner import get_storage_security_config
from backend.nsg_scanner import get_nsg_security_config

from security_engine.security_rules import (
    check_storage_security,
    check_nsg_security,
)
from security_engine.risk_score import calculate_risk_score


def run_security_scan():
    all_findings = []

    # Scan Storage Account
    storage_config = get_storage_security_config()
    storage_findings = check_storage_security(storage_config)

    for finding in storage_findings:
        finding["resource_name"] = storage_config["name"]
        finding["resource_type"] = "Microsoft.Storage/storageAccounts"
        all_findings.append(finding)

    # Scan NSG
    nsg_config = get_nsg_security_config()
    nsg_findings = check_nsg_security(nsg_config)

    for finding in nsg_findings:
        finding["resource_name"] = nsg_config["name"]
        finding["resource_type"] = (
            "Microsoft.Network/networkSecurityGroups"
        )
        all_findings.append(finding)

    risk = calculate_risk_score(all_findings)

    return {
        "findings": all_findings,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
    }