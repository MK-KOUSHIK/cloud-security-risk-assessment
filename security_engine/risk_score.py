SEVERITY_POINTS = {
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5,
    "PASS": 0,
}


def calculate_risk_score(findings):
    total_points = 0

    for finding in findings:
        severity = finding["severity"]
        total_points += SEVERITY_POINTS.get(severity, 0)

    # Keep the score between 0 and 100
    score = min(total_points, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
    }