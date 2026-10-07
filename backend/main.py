from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from security_engine.scanner import run_security_scan


app = FastAPI(
    title="Cloud Security Risk Assessment Tool",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "cloud-security-risk-assessment"
    }


@app.post("/scan")
def scan_environment():
    try:
        result = run_security_scan()

        return {
            "status": "completed",
            "summary": {
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "total_findings": len(result["findings"]),
                "passed_checks": sum(
                    1
                    for finding in result["findings"]
                    if finding["severity"] == "PASS"
                ),
            },
            "findings": result["findings"],
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Security scan failed: {str(error)}"
        )