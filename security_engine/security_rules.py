def check_storage_security(storage_config):
    findings = []

    # Check HTTPS-only traffic
    if not storage_config["https_only"]:
        findings.append({
            "rule_id": "STORAGE-001",
            "severity": "HIGH",
            "title": "HTTPS-only traffic is disabled",
            "description": "The storage account allows non-HTTPS traffic.",
            "recommendation": "Enable secure transfer required."
        })
    else:
        findings.append({
            "rule_id": "STORAGE-001",
            "severity": "PASS",
            "title": "HTTPS-only traffic enabled",
            "description": "The storage account requires HTTPS traffic.",
            "recommendation": "No action required."
        })

    # Check public blob access
    if storage_config["public_blob_access"]:
        findings.append({
            "rule_id": "STORAGE-002",
            "severity": "HIGH",
            "title": "Public blob access is enabled",
            "description": "The storage account permits public blob access.",
            "recommendation": "Disable public blob access unless it is explicitly required."
        })
    else:
        findings.append({
            "rule_id": "STORAGE-002",
            "severity": "PASS",
            "title": "Public blob access disabled",
            "description": "The storage account does not allow public blob access.",
            "recommendation": "No action required."
        })

    # Check TLS version
    tls_version = str(storage_config["minimum_tls_version"])

    if "TLS1_2" not in tls_version:
        findings.append({
            "rule_id": "STORAGE-003",
            "severity": "MEDIUM",
            "title": "Weak minimum TLS version",
            "description": f"The storage account uses {tls_version}.",
            "recommendation": "Require TLS 1.2 or newer."
        })
    else:
        findings.append({
            "rule_id": "STORAGE-003",
            "severity": "PASS",
            "title": "TLS 1.2 is enforced",
            "description": "The storage account requires TLS 1.2.",
            "recommendation": "No action required."
        })

    return findings


def check_nsg_security(nsg_config):
    findings = []

    for rule in nsg_config["rules"]:
        if (
            rule["direction"] == "Inbound"
            and rule["access"] == "Allow"
            and rule["source"] == "*"
            and rule["destination_port"] in ["22", "3389"]
        ):
            port = rule["destination_port"]

            service = "SSH" if port == "22" else "RDP"

            findings.append({
                "rule_id": f"NSG-{port}-001",
                "severity": "HIGH",
                "title": f"{service} exposed to the Internet",
                "description": (
                    f"Inbound {service} traffic is allowed from any source."
                ),
                "recommendation": (
                    f"Restrict {service} access to trusted IP addresses "
                    "or remove the rule if it is not required."
                )
            })

    if not findings:
        findings.append({
            "rule_id": "NSG-001",
            "severity": "PASS",
            "title": "No obvious SSH/RDP exposure detected",
            "description": (
                "No custom inbound rule was found exposing SSH or RDP "
                "to all Internet sources."
            ),
            "recommendation": "No action required."
        })

    return findings