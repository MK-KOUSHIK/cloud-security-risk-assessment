from security_engine.scanner import run_security_scan


result = run_security_scan()

print("\n===== CLOUD SECURITY SCAN =====\n")

print(f"Risk Score: {result['risk_score']}/100")
print(f"Risk Level: {result['risk_level']}")

print("\nFindings:")

for finding in result["findings"]:
    print(
        f"[{finding['severity']}] "
        f"{finding['rule_id']} | "
        f"{finding['resource_name']} | "
        f"{finding['title']}"
    )

print("\n===== SCAN COMPLETE =====")