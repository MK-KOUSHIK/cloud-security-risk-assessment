from security_rules import (
    check_storage_security,
    check_nsg_security,
)


storage_config = {
    "https_only": True,
    "public_blob_access": False,
    "minimum_tls_version": "MinimumTlsVersion.TLS1_2",
}

nsg_config = {
    "rules": []
}


storage_findings = check_storage_security(storage_config)
nsg_findings = check_nsg_security(nsg_config)

print("\nStorage findings:")

for finding in storage_findings:
    print(
        f"{finding['rule_id']} | "
        f"{finding['severity']} | "
        f"{finding['title']}"
    )

print("\nNSG findings:")

for finding in nsg_findings:
    print(
        f"{finding['rule_id']} | "
        f"{finding['severity']} | "
        f"{finding['title']}"
    )