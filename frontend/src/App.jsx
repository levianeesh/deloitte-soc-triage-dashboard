import React, { useState, useEffect } from "react";
import axios from "axios";
import Navbar from "./components/Navbar";
import MetricsHud from "./components/MetricsHud";
import TriageScanner from "./components/TriageScanner";
import ThreatResult from "./components/ThreatResult";
import AuditTrail from "./components/AuditTrail";
import ThreatAnalytics from "./components/ThreatAnalytics";
import Playbooks from "./components/Playbooks";
import ContainmentModal from "./components/ContainmentModal";
import { extractUrlFeatures } from "./utils/heuristics";
import { INITIAL_AUDIT_LOGS } from "./utils/mockData";
import "./App.css";

export default function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState(() => {
    const saved = localStorage.getItem("deloitte_soc_history");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        return INITIAL_AUDIT_LOGS;
      }
    }
    return INITIAL_AUDIT_LOGS;
  });
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("triage");
  const [backendStatus, setBackendStatus] = useState("checking");
  const [useLiveBackend, setUseLiveBackend] = useState(true);
  const [notification, setNotification] = useState(null);

  // Containment modal state
  const [modalState, setModalState] = useState({
    isOpen: false,
    type: "firewall",
    url: "",
    threatScore: 85
  });

  // Sync history to localStorage
  useEffect(() => {
    localStorage.setItem("deloitte_soc_history", JSON.stringify(history));
  }, [history]);

  const showNotification = (msg, type = "info") => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  // Check backend health and fetch history
  const fetchHistory = async () => {
    if (!useLiveBackend) {
      setBackendStatus("offline");
      return;
    }

    try {
      const res = await axios.get("http://localhost:3000/api/history", { timeout: 3000 });
      if (Array.isArray(res.data) && res.data.length > 0) {
        // Merge with initial logs, avoiding duplicates
        setHistory(prev => {
          const ids = new Set(res.data.map(item => item._id));
          const uniquePrev = prev.filter(p => !ids.has(p._id));
          return [...res.data, ...uniquePrev];
        });
      }
      setBackendStatus("online");
    } catch (err) {
      setBackendStatus("offline");
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [useLiveBackend]);

  // Main URL Triage Handler
  const analyzeUrl = async (e) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);

    if (useLiveBackend) {
      try {
        // Attempt real Node.js gateway triage
        const res = await axios.post("http://localhost:3000/api/triage", { url }, { timeout: 4000 });
        
        // Enrich backend response with heuristic metadata if missing
        const clientHeuristics = extractUrlFeatures(url);
        const enrichedResult = {
          ...res.data,
          threatScore: clientHeuristics.threatScore,
          matchedKeywords: clientHeuristics.matchedKeywords,
          ai_features: res.data.ai_features || clientHeuristics.ai_features
        };

        setResult(enrichedResult);
        setBackendStatus("online");

        // Add to audit trail
        const newEntry = {
          _id: `live-${Date.now()}`,
          url: url,
          ai_risk_score: enrichedResult.ai_risk_score,
          vt_malicious_flags: enrichedResult.vt_malicious_flags,
          threatScore: enrichedResult.threatScore,
          timestamp: new Date().toISOString(),
          analyst: "A. Levi (L2 Live)"
        };
        setHistory(prev => [newEntry, ...prev]);

        showNotification("Target triaged successfully via Node Gateway & VirusTotal API", "success");
      } catch (err) {
        // Graceful fallback to client-side heuristics
        setBackendStatus("offline");
        const clientFeatures = extractUrlFeatures(url);
        setResult(clientFeatures);

        const newEntry = {
          _id: `sim-${Date.now()}`,
          url: url,
          ai_risk_score: clientFeatures.ai_risk_score,
          vt_malicious_flags: clientFeatures.vt_malicious_flags,
          threatScore: clientFeatures.threatScore,
          timestamp: new Date().toISOString(),
          analyst: "A. Levi (Local AI Engine)"
        };
        setHistory(prev => [newEntry, ...prev]);

        showNotification("Node Gateway offline: Analyzed via Client-Side Random Forest Heuristic Engine", "warning");
      }
    } else {
      // Standalone simulation mode
      const clientFeatures = extractUrlFeatures(url);
      setResult(clientFeatures);

      const newEntry = {
        _id: `sim-${Date.now()}`,
        url: url,
        ai_risk_score: clientFeatures.ai_risk_score,
        vt_malicious_flags: clientFeatures.vt_malicious_flags,
        threatScore: clientFeatures.threatScore,
        timestamp: new Date().toISOString(),
        analyst: "A. Levi (Standalone AI)"
      };
      setHistory(prev => [newEntry, ...prev]);

      showNotification("Heuristic triage executed via Local AI Engine", "success");
    }

    setLoading(false);
  };

  const handleOpenContainment = (type, targetUrl, threatScore) => {
    setModalState({
      isOpen: true,
      type: type || 'firewall',
      url: targetUrl || url,
      threatScore: threatScore || 85
    });
  };

  const handleSelectRecord = (record) => {
    const enriched = extractUrlFeatures(record.url);
    setResult({
      ...record,
      ai_features: record.ai_features || enriched.ai_features,
      threatScore: record.threatScore || enriched.threatScore,
      matchedKeywords: enriched.matchedKeywords
    });
    setUrl(record.url);
    setActiveTab("triage");
    showNotification(`Loaded forensic record for: ${record.url}`, "info");
  };

  return (
    <div className="app-layout">
      {/* Top Professional Header */}
      <Navbar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab}
        backendStatus={backendStatus}
        useLiveBackend={useLiveBackend}
        setUseLiveBackend={setUseLiveBackend}
        onRefresh={fetchHistory}
      />

      {/* Floating System Notification Toast */}
      {notification && (
        <div className={`notification-toast ${notification.type}`}>
          <span className="toast-dot"></span>
          <span>{notification.msg}</span>
        </div>
      )}

      {/* Main Content Area */}
      <main className="main-viewport">
        {/* Real-time KPI Telemetry Bar */}
        <MetricsHud auditLogs={history} />

        {/* Tab 1: Live Interactive Triage Console */}
        {activeTab === "triage" && (
          <div className="tab-pane animate-fade-in">
            <TriageScanner 
              url={url} 
              setUrl={setUrl} 
              onAnalyze={analyzeUrl} 
              loading={loading} 
            />

            {result && (
              <ThreatResult 
                result={result} 
                onOpenContainment={handleOpenContainment}
              />
            )}
          </div>
        )}

        {/* Tab 2: Audit Trail & Incident Ledger */}
        {activeTab === "audit" && (
          <div className="tab-pane animate-fade-in">
            <AuditTrail 
              history={history} 
              onSelectRecord={handleSelectRecord} 
            />
          </div>
        )}

        {/* Tab 3: Threat Analytics & Heuristic Weights */}
        {activeTab === "analytics" && (
          <div className="tab-pane animate-fade-in">
            <ThreatAnalytics auditLogs={history} />
          </div>
        )}

        {/* Tab 4: Containment Playbooks */}
        {activeTab === "playbooks" && (
          <div className="tab-pane animate-fade-in">
            <Playbooks />
          </div>
        )}
      </main>

      {/* Automated Incident Containment Modal */}
      <ContainmentModal
        isOpen={modalState.isOpen}
        onClose={() => setModalState(prev => ({ ...prev, isOpen: false }))}
        modalType={modalState.type}
        targetUrl={modalState.url}
        threatScore={modalState.threatScore}
      />

      {/* Enterprise Footer */}
      <footer className="footer-bar">
        <div className="footer-content">
          <div className="footer-brand">
            <span className="deloitte-wordmark">Deloitte.</span>
            <span>Cyber Threat Intelligence & Incident Response Engineering</span>
          </div>
          <div className="footer-meta">
            <span>PLATFORM: SOC-TRIAGE v3.2</span>
            <span>•</span>
            <span>CLASSIFICATION: CONFIDENTIAL // INTERNAL SOC USE ONLY</span>
            <span>•</span>
            <span>© 2026 Deloitte Cyber Risk Services</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
