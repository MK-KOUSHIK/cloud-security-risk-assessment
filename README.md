# Cloud Security Risk Assessment Tool

A web-based cloud security assessment tool that evaluates Microsoft Azure resource configurations, identifies potential security risks, calculates a risk score, and provides remediation recommendations.

## Overview

Cloud misconfigurations can expose sensitive data and services to unauthorized access. Manually reviewing cloud security settings can be time-consuming and difficult.

The **Cloud Security Risk Assessment Tool** automates selected security checks for Azure Storage Accounts and Network Security Groups (NSGs). It retrieves actual resource configurations through Azure APIs, evaluates them against predefined security rules, and displays the results through a web dashboard.

This project was developed as a college Cloud Technologies microproject to demonstrate cloud integration, security assessment, API development, and web application development.

## Key Features

- **Azure integration:** Connects to Azure using Microsoft Entra ID application credentials.
- **Live configuration scanning:** Retrieves supported Azure resource configuration through Azure SDKs.
- **Storage security checks:** Evaluates HTTPS-only traffic, public blob access, TLS version, Shared Key access, firewall settings, and public network access.
- **Network security checks:** Identifies potentially unrestricted inbound SSH, RDP, HTTP, database ports, and wildcard destination ports.
- **Risk scoring:** Calculates a rule-based score from 0 to 100 and assigns an overall risk level.
- **Security findings:** Displays finding severity, explanations, affected resources, and remediation recommendations.
- **Interactive dashboard:** Presents scan results in a React-based web interface.
- **Automated tests:** Includes unit tests for security rules and risk score calculations.

## Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, Vite, JavaScript, CSS |
| Backend | Python, FastAPI |
| Cloud platform | Microsoft Azure |
| Authentication | Microsoft Entra ID, Azure Identity SDK |
| Azure integration | Azure Resource Manager, Storage and Network management SDKs |
| Testing | Python `unittest` |
| Version control | Git and GitHub |

## Architecture

```text
User
 |
 v
React Web Dashboard
 |
 | HTTP requests
 v
FastAPI Backend
 |
 v
Microsoft Entra ID Authentication
 |
 v
Azure Management APIs
 |
 v
Azure Storage Account and NSG
 |
 v
Security Rules Engine
 |
 v
Risk Score and Findings
 |
 v
Dashboard Results and Recommendations
```

## Security Assessment Controls

The current prototype evaluates 10 security controls.

### Azure Storage

1. HTTPS-only traffic enforcement.
2. Public blob access.
3. Minimum TLS version.
4. Shared Key authentication access.
5. Storage firewall default action.
6. Public network access.

### Network Security Groups

7. SSH and RDP exposure.
8. Unrestricted inbound HTTP traffic.
9. Unrestricted inbound database ports.
10. Unrestricted inbound wildcard destination ports.

The rules identify potential configuration risks; they do not prove that a resource has been exploited or that every possible security issue has been detected.

## Risk Scoring

The prototype uses a rule-based scoring model:

| Finding severity | Points |
|---|---:|
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| PASS | 0 |

The points are summed and capped at 100.

| Total score | Risk level |
|---|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

The score is an illustrative assessment metric based on the configured rules, not a guarantee of exploitability or a formal compliance certification.

## Project Structure

```text
cloud-security-risk-assessment/
├── backend/
│   ├── main.py
│   ├── azure_auth.py
│   ├── azure_scanner.py
│   ├── config.py
│   ├── storage_scanner.py
│   ├── nsg_scanner.py
│   ├── requirements.txt
│   └── .env                 # Local only; never commit
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── security_engine/
│   ├── security_rules.py
│   ├── risk_score.py
│   ├── scanner.py
│   ├── test_real_scan.py
│   ├── test_risk_score.py
│   └── test_security_rules.py
├── tests/
│   ├── __init__.py
│   └── test_security_engine.py
├── .gitignore
└── README.md
```

## Prerequisites

Install or configure the following:

- Python 3.12 or a compatible supported Python version.
- Node.js and npm.
- A Microsoft Azure subscription.
- An Azure resource group containing the resources to assess.
- An Entra ID app registration with a client secret.
- Azure RBAC Reader access for the application at the intended assessment scope.
- Git, if cloning the repository.

The Azure subscription and resource group must be accessible to the application identity.

## Azure Configuration

### 1. Register the application

In the Azure portal:

1. Open **Microsoft Entra ID → App registrations**.
2. Create or select the assessment application.
3. Record its tenant ID and client ID.
4. Create a client secret and store it securely.
5. Assign the application the **Reader** role at the intended resource-group scope.

Use the minimum permissions needed for the assessment. Reader access is intended for reading configuration and does not grant permission to change resource settings.

### 2. Configure environment variables

Create `backend/.env` locally. Do not commit this file.

```env
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-application-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id

AZURE_RESOURCE_GROUP=your-resource-group
AZURE_STORAGE_ACCOUNT=your-storage-account-name
AZURE_NSG_NAME=your-network-security-group-name
```

Replace the example values with the actual values for your Azure environment. The resource names must refer to resources accessible to the application identity.

The application must load and validate these settings before scanning. Never put Azure client secrets in frontend code, public configuration, or Git.

## Installation and Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/MK-KOUSHIK/cloud-security-risk-assessment.git
cd cloud-security-risk-assessment
```

### 2. Set up the backend

Create a Python virtual environment:

```bash
python -m venv backend/venv
```

Activate it on Windows PowerShell:

```powershell
backend\venv\Scripts\Activate.ps1
```

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Create and configure `backend/.env` as described above.

### 3. Start the backend

From the repository root, with the virtual environment activated:

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The backend should be available at:

- API: `http://127.0.0.1:8000`
- Health endpoint: `http://127.0.0.1:8000/health`

You can open the interactive API documentation, if enabled, at `http://127.0.0.1:8000/docs`.

### 4. Set up the frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local dashboard:

**http://localhost:5173**

Keep both development servers running while using the application.

### 5. Run an assessment

1. Confirm that the backend and frontend are running.
2. Confirm that the Azure credentials and target resource settings are correct.
3. Open the dashboard.
4. Start a scan using the dashboard's scan button.
5. Review the risk score, findings, severity levels, and recommendations.

The scan requires internet connectivity and valid Azure authentication. Results depend on the actual configuration of the selected resources.

## Testing

From the repository root, run the automated test suite:

```powershell
backend\venv\Scripts\python.exe -m unittest discover -s tests -v
```

The current test suite contains 24 unit tests covering security rules, network exposure detection, missing configuration properties, and risk scoring.

To build the frontend for production:

```bash
cd frontend
npm run build
```

A successful build creates the frontend output in `frontend/dist/`.

## Security and Limitations

- The current prototype assesses supported Storage Account and NSG settings; it does not audit every Azure service.
- Findings depend on the configuration properties retrieved by the Azure SDK and the implemented rules.
- The risk score is a simplified rule-based estimate.
- A PASS result means the implemented check passed; it does not mean the entire cloud environment is secure.
- The current setup uses configured Azure credentials and resource targets. It is not yet a complete multi-tenant customer onboarding platform.
- The local development server is not a permanently hosted public website.
- The application is a college project prototype, not a replacement for a professional cloud security platform or a formal compliance audit.

## Cost Considerations

Local development, unit testing, and frontend builds do not require creating additional Azure resources.

Azure management API requests generally do not have a separate per-request charge, but subscription costs may apply to other services or future hosting. Check current Azure pricing before deploying paid infrastructure.

## Future Enhancements

- Add support for additional Azure resource types.
- Provide secure customer onboarding and subscription selection.
- Add downloadable assessment reports.
- Track assessment history and configuration changes.
- Add more security rules aligned with established cloud security guidance.
- Deploy the application with secure backend hosting and managed identity where supported.

## Project Status

The core prototype has been implemented and merged into the `main` branch on GitHub. The current version includes Azure configuration scanning, 10 security controls, a risk scoring engine, a React dashboard, and 24 passing unit tests.

## Authors

Developed by a student team as a college Cloud Technologies microproject.

**Repository:** https://github.com/MK-KOUSHIK/cloud-security-risk-assessment
