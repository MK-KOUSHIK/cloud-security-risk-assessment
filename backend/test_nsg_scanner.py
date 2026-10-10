from nsg_scanner import get_nsg_security_config


config = get_nsg_security_config()

print("\nNSG security configuration:\n")

print(f"Name: {config['name']}")
print(f"Location: {config['location']}")

print("\nSecurity rules:")

if not config["rules"]:
    print("No custom security rules configured.")
else:
    for rule in config["rules"]:
        print(
            f"\nName: {rule['name']}"
            f"\nDirection: {rule['direction']}"
            f"\nAccess: {rule['access']}"
            f"\nProtocol: {rule['protocol']}"
            f"\nSource: {rule['source']}"
            f"\nSource Port: {rule['source_port']}"
            f"\nDestination: {rule['destination']}"
            f"\nDestination Port: {rule['destination_port']}"
            f"\nPriority: {rule['priority']}"
        )