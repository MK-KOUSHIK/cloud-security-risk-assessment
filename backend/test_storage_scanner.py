from storage_scanner import get_storage_security_config


config = get_storage_security_config()

print("\nStorage security configuration:\n")

for key, value in config.items():
    print(f"{key}: {value}")