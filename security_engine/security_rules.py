DATABASE_PORTS = {
    "1433": "MS SQL",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
}

UNRESTRICTED_SOURCES = {"*", "internet", "0.0.0.0/0", "any"}


def check_storage_security(storage_config):
    findings = []

    # 1. Check HTTPS-only traffic (STORAGE-001)
    if not storage_config.get("https_only"):
        findings.append({
            "rule_id": "STORAGE-001",
            "severity": "HIGH",
            "title": "HTTPS-only traffic is disabled",
            "description": "The storage account allows non-HTTPS traffic.",
            "recommendation": "Enable secure transfer required.",
        })
    else:
        findings.append({
            "rule_id": "STORAGE-001",
            "severity": "PASS",
            "title": "HTTPS-only traffic enabled",
            "description": "The storage account requires HTTPS traffic.",
            "recommendation": "No action required.",
        })

    # 2. Check public blob access (STORAGE-002)
    if storage_config.get("public_blob_access"):
        findings.append({
            "rule_id": "STORAGE-002",
            "severity": "HIGH",
            "title": "Public blob access is enabled",
            "description": "The storage account permits public blob access.",
            "recommendation": "Disable public blob access unless it is explicitly required.",
        })
    else:
        findings.append({
            "rule_id": "STORAGE-002",
            "severity": "PASS",
            "title": "Public blob access disabled",
            "description": "The storage account does not allow public blob access.",
            "recommendation": "No action required.",
        })

    # 3. Check TLS version (STORAGE-003)
    tls_version = str(storage_config.get("minimum_tls_version", ""))
    if "TLS1_2" not in tls_version and "TLS1_3" not in tls_version:
        findings.append({
            "rule_id": "STORAGE-003",
            "severity": "MEDIUM",
            "title": "Weak minimum TLS version",
            "description": f"The storage account uses {tls_version}.",
            "recommendation": "Require TLS 1.2 or newer.",
        })
    else:
        findings.append({
            "rule_id": "STORAGE-003",
            "severity": "PASS",
            "title": "TLS 1.2 is enforced",
            "description": "The storage account requires TLS 1.2.",
            "recommendation": "No action required.",
        })

    # 4. Check Shared Key authentication (STORAGE-004)
    allow_shared_key = storage_config.get("allow_shared_key_access")
    if allow_shared_key is None:
        findings.append({
            "rule_id": "STORAGE-004",
            "severity": "MEDIUM",
            "title": "Shared Key access status cannot be determined",
            "description": "The storage account configuration did not report the allow_shared_key_access property.",
            "recommendation": "Verify storage account configuration and enforce Microsoft Entra ID authentication.",
        })
    elif allow_shared_key is True:
        findings.append({
            "rule_id": "STORAGE-004",
            "severity": "MEDIUM",
            "title": "Shared Key access is enabled",
            "description": "The storage account permits authentication using account access keys rather than enforcing Microsoft Entra ID (Azure AD) RBAC.",
            "recommendation": "Disable shared key access and require Microsoft Entra ID authentication with RBAC roles.",
        })
    else:
        findings.append({
            "rule_id": "STORAGE-004",
            "severity": "PASS",
            "title": "Shared Key access is disabled",
            "description": "The storage account requires Microsoft Entra ID (Azure AD) authentication.",
            "recommendation": "No action required.",
        })

    # 5. Check storage firewall default action (STORAGE-005)
    default_network_action = storage_config.get("default_network_action")
    public_network_access = storage_config.get("public_network_access")
    pna_upper = str(public_network_access or "").upper()
    is_public_disabled = "DISABLED" in pna_upper

    if default_network_action is None:
        findings.append({
            "rule_id": "STORAGE-005",
            "severity": "HIGH",
            "title": "Storage firewall default action cannot be determined",
            "description": "Network rule set default action is not configured or unavailable.",
            "recommendation": "Configure network firewall rules for the storage account.",
        })
    elif "ALLOW" in str(default_network_action).upper():
        if is_public_disabled:
            findings.append({
                "rule_id": "STORAGE-005",
                "severity": "LOW",
                "title": "Storage firewall default action is Allow while public access is disabled",
                "description": (
                    f"The storage account firewall default action is set to {default_network_action}, "
                    f"while public network access is set to {public_network_access}. The account is not actively exposed "
                    "to the public Internet, but this setting is worth reviewing to maintain defense-in-depth "
                    "and avoid exposure if public network access is ever re-enabled."
                ),
                "recommendation": (
                    "Set the firewall default action to Deny to maintain defense-in-depth "
                    "and prevent accidental exposure if public network access is re-enabled."
                ),
            })
        else:
            findings.append({
                "rule_id": "STORAGE-005",
                "severity": "HIGH",
                "title": "Storage firewall default action allows all networks",
                "description": (
                    f"Public network access is configured as {public_network_access} and the firewall default action is set to {default_network_action}, "
                    "permitting traffic from all internet networks by default."
                ),
                "recommendation": (
                    "Configure the storage firewall default action to Deny and allow only "
                    "trusted virtual networks or IP ranges."
                ),
            })
    else:
        findings.append({
            "rule_id": "STORAGE-005",
            "severity": "PASS",
            "title": "Storage firewall default action is restricted",
            "description": "The storage account firewall denies traffic by default unless explicitly allowed.",
            "recommendation": "No action required.",
        })

    # 6. Check public network access (STORAGE-006)
    if public_network_access is None:
        findings.append({
            "rule_id": "STORAGE-006",
            "severity": "MEDIUM",
            "title": "Public network access status cannot be determined",
            "description": "Public network access configuration was not reported or is unavailable.",
            "recommendation": "Verify public network access settings on the storage account.",
        })
    elif "ENABLED" in pna_upper:
        findings.append({
            "rule_id": "STORAGE-006",
            "severity": "MEDIUM",
            "title": "Public network access is enabled",
            "description": (
                f"The storage account public network access is set to {public_network_access}, "
                "allowing endpoints to resolve publicly over the Internet rather than being restricted to Private Endpoints."
            ),
            "recommendation": "Disable public network access and connect using Azure Private Endpoints.",
        })
    elif is_public_disabled:
        findings.append({
            "rule_id": "STORAGE-006",
            "severity": "PASS",
            "title": "Public network access is disabled",
            "description": (
                f"Public network endpoints are disabled for the storage account ({public_network_access})."
            ),
            "recommendation": "No action required.",
        })
    else:
        findings.append({
            "rule_id": "STORAGE-006",
            "severity": "MEDIUM",
            "title": f"Public network access is set to {public_network_access}",
            "description": "Public network access is not set to Disabled.",
            "recommendation": "Disable public network access unless required.",
        })

    return findings


def _is_unrestricted_source(source):
    if not source:
        return False
    if isinstance(source, (list, tuple, set)):
        return any(_is_unrestricted_source(s) for s in source)
    return str(source).strip().lower() in UNRESTRICTED_SOURCES


def _extract_ports(dest_port):
    if not dest_port:
        return []
    if isinstance(dest_port, (list, tuple, set)):
        ports = []
        for p in dest_port:
            ports.extend(_extract_ports(p))
        return list(dict.fromkeys(ports))

    p_str = str(dest_port).strip()
    if "," in p_str:
        return [part.strip() for part in p_str.split(",") if part.strip()]
    return [p_str]


def check_nsg_security(nsg_config):
    findings = []

    ssh_exposed = False
    rdp_exposed = False
    http_exposed = False
    wildcard_exposed = False
    db_exposed = {}

    for rule in nsg_config.get("rules", []):
        direction = str(rule.get("direction", "")).strip().lower()
        access = str(rule.get("access", "")).strip().lower()

        if direction == "inbound" and access == "allow":
            source = rule.get("source") or rule.get("source_address_prefix")
            if _is_unrestricted_source(source):
                dest_port = (
                    rule.get("destination_port")
                    or rule.get("destination_port_range")
                    or rule.get("destination_port_ranges")
                )
                ports = _extract_ports(dest_port)

                if "*" in ports:
                    wildcard_exposed = True
                if "22" in ports:
                    ssh_exposed = True
                if "3389" in ports:
                    rdp_exposed = True
                if "80" in ports:
                    http_exposed = True

                for p, service in DATABASE_PORTS.items():
                    if p in ports:
                        db_exposed[p] = service

    # 1. Management Exposure (SSH & RDP)
    if ssh_exposed:
        findings.append({
            "rule_id": "NSG-22-001",
            "severity": "HIGH",
            "title": "SSH exposed to the Internet",
            "description": "Inbound SSH traffic is allowed from any source.",
            "recommendation": "Restrict SSH access to trusted IP addresses or remove the rule if it is not required.",
        })
    if rdp_exposed:
        findings.append({
            "rule_id": "NSG-3389-001",
            "severity": "HIGH",
            "title": "RDP exposed to the Internet",
            "description": "Inbound RDP traffic is allowed from any source.",
            "recommendation": "Restrict RDP access to trusted IP addresses or remove the rule if it is not required.",
        })
    if not ssh_exposed and not rdp_exposed:
        findings.append({
            "rule_id": "NSG-001",
            "severity": "PASS",
            "title": "No obvious SSH/RDP exposure detected",
            "description": "No custom inbound rule was found exposing SSH or RDP to all Internet sources.",
            "recommendation": "No action required.",
        })

    # 2. Unencrypted HTTP Exposure (Port 80)
    if http_exposed:
        findings.append({
            "rule_id": "NSG-80-001",
            "severity": "MEDIUM",
            "title": "Unencrypted HTTP (Port 80) exposed to the Internet",
            "description": "Inbound cleartext HTTP traffic is allowed from unrestricted internet sources.",
            "recommendation": "Restrict port 80 access and enforce HTTPS (port 443) with TLS encryption.",
        })
    else:
        findings.append({
            "rule_id": "NSG-80-001",
            "severity": "PASS",
            "title": "No unencrypted HTTP exposure detected",
            "description": "Inbound HTTP (port 80) is not exposed to unrestricted internet sources.",
            "recommendation": "No action required.",
        })

    # 3. Database Services Exposure
    if db_exposed:
        for port, service in db_exposed.items():
            findings.append({
                "rule_id": f"NSG-{port}-001",
                "severity": "HIGH",
                "title": f"Database service ({service}) exposed to the Internet",
                "description": f"Inbound {service} (port {port}) database traffic is allowed from unrestricted internet sources.",
                "recommendation": "Restrict database access to internal virtual networks or private endpoints; never expose database listeners directly to the Internet.",
            })
    else:
        findings.append({
            "rule_id": "NSG-DB-001",
            "severity": "PASS",
            "title": "No database exposure detected",
            "description": "Standard database ports (1433, 3306, 5432, 27017, 6379) are not exposed to unrestricted internet sources.",
            "recommendation": "No action required.",
        })

    # 4. Wildcard Destination Port Exposure (*)
    if wildcard_exposed:
        findings.append({
            "rule_id": "NSG-ALL-001",
            "severity": "HIGH",
            "title": "All destination ports (*) exposed to the Internet",
            "description": "An inbound rule permits unrestricted access to all destination ports (*), completely bypassing perimeter port filtering.",
            "recommendation": "Replace the wildcard destination port rule with specific, least-privilege port rules restricted to trusted IP addresses.",
        })
    else:
        findings.append({
            "rule_id": "NSG-ALL-001",
            "severity": "PASS",
            "title": "No wildcard port exposure detected",
            "description": "No inbound rule exposes all destination ports (*) to unrestricted internet sources.",
            "recommendation": "No action required.",
        })

    return findings