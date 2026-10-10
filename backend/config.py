import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

load_dotenv(ENV_FILE)

AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

AZURE_RESOURCE_GROUP = (
    os.getenv("AZURE_RESOURCE_GROUP")
    or os.getenv("AZURE_RESOURCE_GROUP_NAME")
)
AZURE_STORAGE_ACCOUNT = (
    os.getenv("AZURE_STORAGE_ACCOUNT")
    or os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
)
AZURE_NSG_NAME = os.getenv("AZURE_NSG_NAME")


def validate_config():
    required = {
        "AZURE_TENANT_ID": AZURE_TENANT_ID,
        "AZURE_CLIENT_ID": AZURE_CLIENT_ID,
        "AZURE_CLIENT_SECRET": AZURE_CLIENT_SECRET,
        "AZURE_SUBSCRIPTION_ID": AZURE_SUBSCRIPTION_ID,
        "AZURE_RESOURCE_GROUP": AZURE_RESOURCE_GROUP,
        "AZURE_STORAGE_ACCOUNT": AZURE_STORAGE_ACCOUNT,
        "AZURE_NSG_NAME": AZURE_NSG_NAME,
    }

    missing = [key for key, value in required.items() if not value]

    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}"
        )