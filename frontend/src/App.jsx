import { useState } from "react";
import "./App.css";

function App() {
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanTime, setScanTime] = useState(null);

  const runScan = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
      });

      if (!response.ok) {
        throw new Error("Security scan failed");
      }

      const data = await response.json();

      setScanResult(data);
      setScanTime(new Date());
    } catch (err) {
      setError(
        "Unable to connect to the backend. Make sure FastAPI is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const getRiskClass = (level) => {
    if (level === "CRITICAL") return "critical";
    if (level === "HIGH") return "high";
    if (level === "MEDIUM") return "medium";
    return "low";
  };

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <div className="brand">CLOUDGUARD</div>
          <div className="subtitle">
            Azure Cloud Security Risk Assessment
          </div>
        </div>

        <button
          className="scan-button"
          onClick={runScan}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Scan Azure Environment"}
        </button>
      </header>

      <main className="container">
        <section className="hero">
          <div>
            <p className="eyebrow">SECURITY ASSESSMENT</p>
            <h1>Azure Environment Security</h1>
            <p>
              Analyze Azure resource configurations and identify common
              security risks.
            </p>
          </div>

          <div className="azure-status">
            <span className="status-dot"></span>
            Azure Connected
          </div>
        </section>

        {error && <div className="error">{error}</div>}

        {!scanResult && !loading && (
          <section className="welcome">
            <div className="welcome-icon">✓</div>
            <h2>Ready for security assessment</h2>
            <p>
              Start a scan to inspect your Azure resources and calculate the
              current security risk score.
            </p>
          </section>
        )}

        {loading && (
          <section className="welcome">
            <div className="spinner"></div>
            <h2>Scanning Azure environment...</h2>
            <p>
              Discovering resources and evaluating security configurations.
            </p>
          </section>
        )}

        {scanResult && (
          <>
            <section className="metrics">
              <div className="metric-card risk-card">
                <span className="metric-label">Risk Score</span>
                <strong>{scanResult.summary.risk_score}/100</strong>
                <small>Overall assessment</small>
              </div>

              <div className="metric-card">
                <span className="metric-label">Risk Level</span>
                <strong
                  className={getRiskClass(scanResult.summary.risk_level)}
                >
                  {scanResult.summary.risk_level}
                </strong>
                <small>Current environment</small>
              </div>

              <div className="metric-card">
                <span className="metric-label">Total Findings</span>
                <strong>{scanResult.summary.total_findings}</strong>
                <small>Security checks</small>
              </div>

              <div className="metric-card">
                <span className="metric-label">Checks Passed</span>
                <strong>{scanResult.summary.passed_checks}</strong>
                <small>Successful controls</small>
              </div>
            </section>

            <section className="scan-info">
              <div>
                <strong>Azure Environment</strong>
                <span>Resource configuration assessment</span>
              </div>

              {scanTime && (
                <div className="scan-time">
                  Last scanned: {scanTime.toLocaleString()}
                </div>
              )}
            </section>

            <section className="findings-section">
              <div className="section-header">
                <div>
                  <p className="eyebrow">ASSESSMENT RESULTS</p>
                  <h2>Security Findings</h2>
                </div>

                <button
                  className="secondary-button"
                  onClick={runScan}
                  disabled={loading}
                >
                  Scan Again
                </button>
              </div>

              <div className="findings-list">
                {scanResult.findings.map((finding) => (
                  <div
                    className={`finding ${finding.severity.toLowerCase()}`}
                    key={finding.rule_id}
                  >
                    <div className="finding-icon">
                      {finding.severity === "PASS" ? "✓" : "!"}
                    </div>

                    <div className="finding-content">
                      <div className="finding-title-row">
                        <h3>{finding.title}</h3>
                        <span className="severity">
                          {finding.severity}
                        </span>
                      </div>

                      <div className="resource">
                        Resource: <strong>{finding.resource_name}</strong>
                      </div>

                      <p>{finding.description}</p>

                      <div className="recommendation">
                        <strong>Recommendation:</strong>{" "}
                        {finding.recommendation}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
      </main>

      <footer>
        Cloud Security Risk Assessment Tool · Azure Security Project
      </footer>
    </div>
  );
}

export default App;