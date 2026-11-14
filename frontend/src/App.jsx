import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css"; // Imports our new dark theme

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchHistory = async () => {
    try {
      const res = await axios.get("http://localhost:3000/api/history");
      setHistory(res.data);
    } catch (err) {
      console.error("Failed to fetch history");
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const analyzeUrl = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3000/api/triage", { url });
      setResult(res.data);
      fetchHistory();
    } catch (err) {
      console.error("Error analyzing URL");
    }
    setLoading(false);
  };

  return (
    <div className="dashboard-container">
      <header className="header">
        <h1>SOC Threat Triage</h1>
        <p>Enterprise AI Heuristics & Global Threat Intelligence</p>
      </header>

      <form className="search-box" onSubmit={analyzeUrl}>
        <input
          className="search-input"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to analyze (e.g., http://ianfette.org)..."
          required
        />
        <button className="scan-btn" type="submit" disabled={loading}>
          {loading ? "Scanning..." : "Analyze Threat"}
        </button>
      </form>

      {result && (
        <div className="results-grid">
          <div
            className={`threat-card ${result.ai_risk_score === 1 ? "malicious" : "safe"}`}
          >
            <h3>Local AI Engine (Random Forest)</h3>
            <div
              className={`status-text ${result.ai_risk_score === 1 ? "malicious" : "safe"}`}
            >
              {result.ai_risk_score === 1 ? "🚨 MALICIOUS" : "✅ SAFE"}
            </div>
            <div className="feature-data">
              {JSON.stringify(result.ai_features)}
            </div>
          </div>

          <div
            className={`threat-card ${result.vt_malicious_flags > 0 ? "warning" : "safe"}`}
          >
            <h3>VirusTotal Global Intel</h3>
            <div
              className={`status-text ${result.vt_malicious_flags > 0 ? "warning" : "safe"}`}
            >
              {result.vt_malicious_flags > 0
                ? `⚠️ ${result.vt_malicious_flags} VENDORS FLAGGED`
                : "✅ CLEAN"}
            </div>
            <div className="feature-data">
              Aggregated from 70+ security vendors globally.
            </div>
          </div>
        </div>
      )}

      <div className="history-section">
        <h3>Recent Scan Audit Trail</h3>
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Target URL</th>
              <th>Heuristic (AI)</th>
              <th>Global Intel (VT)</th>
            </tr>
          </thead>
          <tbody>
            {history.map((scan) => (
              <tr key={scan._id}>
                <td>{new Date(scan.timestamp).toLocaleString()}</td>
                <td style={{ color: "#94a3b8" }}>{scan.url}</td>
                <td>
                  <span
                    className={`badge ${scan.ai_risk_score === 1 ? "malicious" : "safe"}`}
                  >
                    {scan.ai_risk_score === 1 ? "Phishing" : "Safe"}
                  </span>
                </td>
                <td>
                  <span
                    className={`badge ${scan.vt_malicious_flags > 0 ? "warning" : "safe"}`}
                  >
                    {scan.vt_malicious_flags > 0
                      ? `${scan.vt_malicious_flags} Flags`
                      : "Clean"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
