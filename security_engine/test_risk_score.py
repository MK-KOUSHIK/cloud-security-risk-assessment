from security_engine.risk_score import calculate_risk_score


test_findings = [
    {
        "rule_id": "STORAGE-001",
        "severity": "PASS",
    },
    {
        "rule_id": "STORAGE-002",
        "severity": "HIGH",
    },
    {
        "rule_id": "STORAGE-003",
        "severity": "PASS",
    },
    {
        "rule_id": "NSG-001",
        "severity": "MEDIUM",
    },
]


result = calculate_risk_score(test_findings)

print("\n===== RISK SCORE TEST =====")
print(f"Score: {result['score']}/100")
print(f"Level: {result['level']}")