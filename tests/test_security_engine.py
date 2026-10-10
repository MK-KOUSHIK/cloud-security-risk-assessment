import unittest

from security_engine.security_rules import (
    check_storage_security,
    check_nsg_security,
)
from security_engine.risk_score import calculate_risk_score


class TestStorageSecurityRules(unittest.TestCase):
    """Test suite for Azure Storage Account security rules (STORAGE-001 to STORAGE-006)."""

    def test_secure_storage_configuration(self):
        """Verify that a fully hardened storage configuration passes all 6 checks."""
        config = {
            "name": "securestorage01",
            "location": "eastus",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)

        self.assertEqual(len(findings), 6)
        for finding in findings:
            self.assertEqual(finding["severity"], "PASS")

        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("STORAGE-001", rule_ids)
        self.assertIn("STORAGE-002", rule_ids)
        self.assertIn("STORAGE-003", rule_ids)
        self.assertIn("STORAGE-004", rule_ids)
        self.assertIn("STORAGE-005", rule_ids)
        self.assertIn("STORAGE-006", rule_ids)

    def test_insecure_storage_https_disabled(self):
        """STORAGE-001: Disabled HTTPS traffic triggers a HIGH finding."""
        config = {
            "name": "insecurestorage01",
            "https_only": False,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-001"]["severity"], "HIGH")
        self.assertEqual(
            finding_map["STORAGE-001"]["title"],
            "HTTPS-only traffic is disabled",
        )
        self.assertEqual(finding_map["STORAGE-002"]["severity"], "PASS")

    def test_insecure_storage_public_blob_access(self):
        """STORAGE-002: Enabled public blob access triggers a HIGH finding."""
        config = {
            "name": "publicstorage01",
            "https_only": True,
            "public_blob_access": True,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-002"]["severity"], "HIGH")
        self.assertEqual(
            finding_map["STORAGE-002"]["title"],
            "Public blob access is enabled",
        )

    def test_insecure_storage_tls_version_below_1_2(self):
        """STORAGE-003: TLS versions below TLS 1.2 trigger a MEDIUM finding."""
        for weak_tls in ["TLS1_0", "TLS1_1"]:
            with self.subTest(weak_tls=weak_tls):
                config = {
                    "name": "weaktlsstorage01",
                    "https_only": True,
                    "public_blob_access": False,
                    "minimum_tls_version": weak_tls,
                    "allow_shared_key_access": False,
                    "default_network_action": "Deny",
                    "public_network_access": "Disabled",
                }
                findings = check_storage_security(config)
                finding_map = {f["rule_id"]: f for f in findings}

                self.assertEqual(finding_map["STORAGE-003"]["severity"], "MEDIUM")
                self.assertEqual(
                    finding_map["STORAGE-003"]["title"],
                    "Weak minimum TLS version",
                )

    def test_storage_tls_1_3_passes(self):
        """STORAGE-003 Edge Case: Modern TLS 1.3 passes check."""
        config = {
            "name": "moderntlsstorage01",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_3",
            "allow_shared_key_access": False,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}
        self.assertEqual(finding_map["STORAGE-003"]["severity"], "PASS")

    def test_storage_shared_key_access_enabled(self):
        """STORAGE-004: Enabled shared key access triggers a MEDIUM finding."""
        config = {
            "name": "sharedkeystorage01",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": True,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-004"]["severity"], "MEDIUM")
        self.assertEqual(
            finding_map["STORAGE-004"]["title"],
            "Shared Key access is enabled",
        )

    def test_storage_shared_key_access_missing_property(self):
        """STORAGE-004 Edge Case: None/missing property is reported as undetermined."""
        config = {
            "name": "unknownkeystorage01",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": None,
            "default_network_action": "Deny",
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-004"]["severity"], "MEDIUM")
        self.assertIn("cannot be determined", finding_map["STORAGE-004"]["title"])

    def test_storage_firewall_allow_with_public_access_enabled(self):
        """STORAGE-005 + STORAGE-006: When public access is Enabled and firewall is Allow, report permissive HIGH finding."""
        for allow_val in ["Allow", "DefaultAction.ALLOW", "allow"]:
            for pna_val in ["Enabled", "PublicNetworkAccess.ENABLED", "enabled"]:
                with self.subTest(allow_val=allow_val, pna_val=pna_val):
                    config = {
                        "name": "openfirewallstorage01",
                        "https_only": True,
                        "public_blob_access": False,
                        "minimum_tls_version": "TLS1_2",
                        "allow_shared_key_access": False,
                        "default_network_action": allow_val,
                        "public_network_access": pna_val,
                    }
                    findings = check_storage_security(config)
                    finding_map = {f["rule_id"]: f for f in findings}

                    # STORAGE-005: HIGH severity because public network is reachable and firewall allows all
                    self.assertEqual(finding_map["STORAGE-005"]["severity"], "HIGH")
                    self.assertEqual(
                        finding_map["STORAGE-005"]["title"],
                        "Storage firewall default action allows all networks",
                    )
                    self.assertIn(str(allow_val), finding_map["STORAGE-005"]["description"])
                    self.assertIn(str(pna_val), finding_map["STORAGE-005"]["description"])

                    # STORAGE-006: public network access is also flagged
                    self.assertEqual(finding_map["STORAGE-006"]["severity"], "MEDIUM")
                    self.assertEqual(
                        finding_map["STORAGE-006"]["title"],
                        "Public network access is enabled",
                    )

                    # Unrelated findings must remain unaffected
                    self.assertEqual(finding_map["STORAGE-001"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-002"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-003"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-004"]["severity"], "PASS")

    def test_storage_firewall_allow_with_public_access_disabled(self):
        """STORAGE-005 + STORAGE-006: When public access is Disabled and firewall is Allow, do not describe as publicly exposed (LOW finding)."""
        for allow_val in ["Allow", "DefaultAction.ALLOW", "allow"]:
            for pna_val in ["Disabled", "PublicNetworkAccess.DISABLED", "disabled"]:
                with self.subTest(allow_val=allow_val, pna_val=pna_val):
                    config = {
                        "name": "internalfirewallstorage01",
                        "https_only": True,
                        "public_blob_access": False,
                        "minimum_tls_version": "TLS1_2",
                        "allow_shared_key_access": False,
                        "default_network_action": allow_val,
                        "public_network_access": pna_val,
                    }
                    findings = check_storage_security(config)
                    finding_map = {f["rule_id"]: f for f in findings}

                    # STORAGE-005: LOW severity defense-in-depth review, NOT described as publicly exposed
                    self.assertEqual(finding_map["STORAGE-005"]["severity"], "LOW")
                    self.assertEqual(
                        finding_map["STORAGE-005"]["title"],
                        "Storage firewall default action is Allow while public access is disabled",
                    )
                    self.assertIn(str(allow_val), finding_map["STORAGE-005"]["description"])
                    self.assertIn(str(pna_val), finding_map["STORAGE-005"]["description"])
                    self.assertIn("not actively exposed", finding_map["STORAGE-005"]["description"])
                    self.assertIn("defense-in-depth", finding_map["STORAGE-005"]["description"])

                    # STORAGE-006: PASS because public network access is disabled
                    self.assertEqual(finding_map["STORAGE-006"]["severity"], "PASS")
                    self.assertEqual(
                        finding_map["STORAGE-006"]["title"],
                        "Public network access is disabled",
                    )

                    # Unrelated findings must remain unaffected
                    self.assertEqual(finding_map["STORAGE-001"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-002"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-003"]["severity"], "PASS")
                    self.assertEqual(finding_map["STORAGE-004"]["severity"], "PASS")

    def test_storage_firewall_default_action_missing(self):
        """STORAGE-005 Edge Case: Missing firewall default action is handled explicitly."""
        config = {
            "name": "nofirewallstorage01",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "default_network_action": None,
            "public_network_access": "Disabled",
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-005"]["severity"], "HIGH")
        self.assertIn("cannot be determined", finding_map["STORAGE-005"]["title"])

    def test_storage_public_network_access_enabled(self):
        """STORAGE-006: Public network access enabled triggers a MEDIUM finding."""
        for pna_val in ["Enabled", "PublicNetworkAccess.ENABLED", "enabled"]:
            with self.subTest(pna_val=pna_val):
                config = {
                    "name": "pnastorage01",
                    "https_only": True,
                    "public_blob_access": False,
                    "minimum_tls_version": "TLS1_2",
                    "allow_shared_key_access": False,
                    "default_network_action": "Deny",
                    "public_network_access": pna_val,
                }
                findings = check_storage_security(config)
                finding_map = {f["rule_id"]: f for f in findings}

                self.assertEqual(finding_map["STORAGE-006"]["severity"], "MEDIUM")
                self.assertEqual(
                    finding_map["STORAGE-006"]["title"],
                    "Public network access is enabled",
                )

    def test_storage_public_network_access_missing(self):
        """STORAGE-006 Edge Case: Missing public network access property handled explicitly."""
        config = {
            "name": "unknownpnastorage01",
            "https_only": True,
            "public_blob_access": False,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "default_network_action": "Deny",
            "public_network_access": None,
        }
        findings = check_storage_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["STORAGE-006"]["severity"], "MEDIUM")
        self.assertIn("cannot be determined", finding_map["STORAGE-006"]["title"])


class TestNSGSecurityRules(unittest.TestCase):
    """Test suite for Network Security Group rules detection (NSG-001, NSG-80, NSG-DB, NSG-ALL)."""

    def test_secure_nsg_empty_rules(self):
        """Verify that an NSG with no custom rules passes all 4 network controls."""
        config = {
            "name": "secure-nsg-01",
            "location": "eastus",
            "rules": [],
        }
        findings = check_nsg_security(config)

        self.assertEqual(len(findings), 4)
        for finding in findings:
            self.assertEqual(finding["severity"], "PASS")

        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("NSG-001", rule_ids)
        self.assertIn("NSG-80-001", rule_ids)
        self.assertIn("NSG-DB-001", rule_ids)
        self.assertIn("NSG-ALL-001", rule_ids)

    def test_secure_nsg_restricted_rules(self):
        """Verify that private IP sources, Deny rules, and Outbound rules evaluate to PASS."""
        config = {
            "name": "restricted-nsg-01",
            "location": "eastus",
            "rules": [
                {
                    "name": "allow-ssh-from-vpn",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": "10.0.0.5/32",
                    "destination_port": "22",
                },
                {
                    "name": "deny-rdp-any",
                    "direction": "Inbound",
                    "access": "Deny",
                    "protocol": "Tcp",
                    "source": "*",
                    "destination_port": "3389",
                },
                {
                    "name": "outbound-ssh-any",
                    "direction": "Outbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": "*",
                    "destination_port": "22",
                },
                {
                    "name": "allow-http-internal",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": "172.16.0.0/12",
                    "destination_port": "80",
                },
            ],
        }
        findings = check_nsg_security(config)

        self.assertEqual(len(findings), 4)
        for f in findings:
            self.assertEqual(f["severity"], "PASS")

    def test_nsg_internet_exposed_ssh(self):
        """Verify unrestricted inbound SSH detection across wildcard and Internet source representations."""
        for unrestricted_source in ["*", "Internet", "internet", "0.0.0.0/0", "any"]:
            with self.subTest(source=unrestricted_source):
                config = {
                    "name": "exposed-ssh-nsg",
                    "rules": [
                        {
                            "name": "allow-ssh-internet",
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "source": unrestricted_source,
                            "destination_port": "22",
                        }
                    ],
                }
                findings = check_nsg_security(config)
                finding_map = {f["rule_id"]: f for f in findings}

                self.assertIn("NSG-22-001", finding_map)
                self.assertEqual(finding_map["NSG-22-001"]["severity"], "HIGH")
                self.assertEqual(
                    finding_map["NSG-22-001"]["title"],
                    "SSH exposed to the Internet",
                )
                self.assertEqual(finding_map["NSG-80-001"]["severity"], "PASS")
                self.assertEqual(finding_map["NSG-DB-001"]["severity"], "PASS")
                self.assertEqual(finding_map["NSG-ALL-001"]["severity"], "PASS")

    def test_nsg_internet_exposed_rdp(self):
        """Verify unrestricted inbound RDP detection across wildcard and Internet source representations."""
        for unrestricted_source in ["*", "Internet", "internet", "0.0.0.0/0", "any"]:
            with self.subTest(source=unrestricted_source):
                config = {
                    "name": "exposed-rdp-nsg",
                    "rules": [
                        {
                            "name": "allow-rdp-internet",
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "source": unrestricted_source,
                            "destination_port": "3389",
                        }
                    ],
                }
                findings = check_nsg_security(config)
                finding_map = {f["rule_id"]: f for f in findings}

                self.assertIn("NSG-3389-001", finding_map)
                self.assertEqual(finding_map["NSG-3389-001"]["severity"], "HIGH")
                self.assertEqual(
                    finding_map["NSG-3389-001"]["title"],
                    "RDP exposed to the Internet",
                )

    def test_nsg_internet_exposed_http(self):
        """NSG-80-001: Inbound HTTP (port 80) open to Internet triggers a MEDIUM finding."""
        config = {
            "name": "exposed-http-nsg",
            "rules": [
                {
                    "name": "allow-http-public",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": "Internet",
                    "destination_port": "80",
                }
            ],
        }
        findings = check_nsg_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["NSG-80-001"]["severity"], "MEDIUM")
        self.assertEqual(
            finding_map["NSG-80-001"]["title"],
            "Unencrypted HTTP (Port 80) exposed to the Internet",
        )
        self.assertEqual(finding_map["NSG-001"]["severity"], "PASS")
        self.assertEqual(finding_map["NSG-DB-001"]["severity"], "PASS")

    def test_nsg_internet_exposed_databases(self):
        """NSG-DB-001: Inbound database listeners open to Internet trigger HIGH findings."""
        test_dbs = [
            ("1433", "MS SQL"),
            ("3306", "MySQL"),
            ("5432", "PostgreSQL"),
            ("27017", "MongoDB"),
            ("6379", "Redis"),
        ]
        for port, service in test_dbs:
            with self.subTest(port=port, service=service):
                config = {
                    "name": f"exposed-db-{port}-nsg",
                    "rules": [
                        {
                            "name": f"allow-{service}-public",
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "source": "*",
                            "destination_port": port,
                        }
                    ],
                }
                findings = check_nsg_security(config)
                finding_map = {f["rule_id"]: f for f in findings}

                rule_id = f"NSG-{port}-001"
                self.assertIn(rule_id, finding_map)
                self.assertEqual(finding_map[rule_id]["severity"], "HIGH")
                self.assertIn(service, finding_map[rule_id]["title"])

    def test_nsg_wildcard_destination_port_exposure(self):
        """NSG-ALL-001: Wildcard destination port (*) triggers a dedicated HIGH finding without redundant sub-port alerts."""
        config = {
            "name": "open-all-ports-nsg",
            "rules": [
                {
                    "name": "allow-any-any",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "source": "*",
                    "destination_port": "*",
                }
            ],
        }
        findings = check_nsg_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertIn("NSG-ALL-001", finding_map)
        self.assertEqual(finding_map["NSG-ALL-001"]["severity"], "HIGH")
        self.assertEqual(
            finding_map["NSG-ALL-001"]["title"],
            "All destination ports (*) exposed to the Internet",
        )
        # Should not flood duplicate redundant port alerts
        rule_ids = [f["rule_id"] for f in findings]
        self.assertNotIn("NSG-22-001", rule_ids)
        self.assertNotIn("NSG-3389-001", rule_ids)
        self.assertNotIn("NSG-1433-001", rule_ids)

    def test_nsg_multi_port_and_list_rules(self):
        """Edge Case: Rules with port list or comma-separated values are parsed properly."""
        config = {
            "name": "multi-port-nsg",
            "rules": [
                {
                    "name": "allow-web-and-sql",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": ["192.168.1.1", "Internet"],
                    "destination_port": ["80", "1433"],
                }
            ],
        }
        findings = check_nsg_security(config)
        finding_map = {f["rule_id"]: f for f in findings}

        self.assertEqual(finding_map["NSG-80-001"]["severity"], "MEDIUM")
        self.assertEqual(finding_map["NSG-1433-001"]["severity"], "HIGH")


class TestRiskScoreCalculation(unittest.TestCase):
    """Test suite for risk score calculation and severity levels."""

    def test_all_pass_findings(self):
        findings = [
            {"rule_id": f"STORAGE-00{i}", "severity": "PASS"} for i in range(1, 7)
        ] + [
            {"rule_id": "NSG-001", "severity": "PASS"},
            {"rule_id": "NSG-80-001", "severity": "PASS"},
            {"rule_id": "NSG-DB-001", "severity": "PASS"},
            {"rule_id": "NSG-ALL-001", "severity": "PASS"},
        ]
        result = calculate_risk_score(findings)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "LOW")

    def test_low_and_medium_findings(self):
        # 1 LOW (5 pts) -> LOW (< 20)
        result_low = calculate_risk_score([{"severity": "LOW"}])
        self.assertEqual(result_low["score"], 5)
        self.assertEqual(result_low["level"], "LOW")

        # 1 MEDIUM (15 pts) -> LOW (< 20)
        result_med = calculate_risk_score([{"severity": "MEDIUM"}])
        self.assertEqual(result_med["score"], 15)
        self.assertEqual(result_med["level"], "LOW")

        # 1 MEDIUM (15) + 1 LOW (5) = 20 pts -> MEDIUM (>= 20)
        result_med_low = calculate_risk_score([
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ])
        self.assertEqual(result_med_low["score"], 20)
        self.assertEqual(result_med_low["level"], "MEDIUM")

    def test_high_findings(self):
        # 1 HIGH (25) -> MEDIUM (>= 20, < 40)
        result_high = calculate_risk_score([{"severity": "HIGH"}])
        self.assertEqual(result_high["score"], 25)
        self.assertEqual(result_high["level"], "MEDIUM")

        # 1 HIGH (25) + 1 MEDIUM (15) = 40 pts -> HIGH (>= 40)
        result_high_med = calculate_risk_score([
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ])
        self.assertEqual(result_high_med["score"], 40)
        self.assertEqual(result_high_med["level"], "HIGH")

    def test_critical_score_and_capping(self):
        # 3 HIGH (75 pts) -> CRITICAL (>= 70)
        result_critical = calculate_risk_score([
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ])
        self.assertEqual(result_critical["score"], 75)
        self.assertEqual(result_critical["level"], "CRITICAL")

        # 5 HIGH (125 pts) -> capped at 100, CRITICAL
        result_capped = calculate_risk_score([
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
        ])
        self.assertEqual(result_capped["score"], 100)
        self.assertEqual(result_capped["level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
