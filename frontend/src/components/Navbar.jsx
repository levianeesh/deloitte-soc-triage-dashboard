import React, { useState, useEffect } from 'react';
import { Shield, Radio, Terminal, User, Clock, Wifi, RefreshCw } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, backendStatus, useLiveBackend, setUseLiveBackend, onRefresh }) {
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatUtc = (d) => {
    return d.toISOString().substring(11, 19) + ' UTC';
  };

  return (
    <header className="navbar-container">
      {/* Top Banner with Deloitte Brand */}
      <div className="navbar-inner">
        <div className="brand-group">
          <div className="deloitte-brand">
            <span className="brand-text">Deloitte</span>
            <span className="brand-dot"></span>
          </div>
          <div className="brand-divider"></div>
          <div className="brand-details">
            <div className="portal-title">
              <Shield className="portal-icon" size={17} />
              <span>SOC THREAT TRIAGE PLATFORM</span>
              <span className="badge-class">RESTRICTED // SOC-L2</span>
            </div>
            <div className="portal-sub">Automated Machine Learning Heuristics & Threat Feed Correlation</div>
          </div>
        </div>

        {/* Live System Telemetry Status */}
        <div className="system-telemetry">
          <div className="telemetry-pill">
            <span className="pill-dot green"></span>
            <span className="pill-label">AI ENGINE:</span>
            <span className="pill-val">RF-v2.4 ACTIVE</span>
          </div>

          <div className="telemetry-pill">
            <span className="pill-dot cyan"></span>
            <span className="pill-label">FEED:</span>
            <span className="pill-val">VIRUSTOTAL v3</span>
          </div>

          <button 
            className={`telemetry-pill backend-pill ${useLiveBackend ? (backendStatus === 'online' ? 'online' : 'offline') : 'simulated'}`}
            onClick={() => setUseLiveBackend(!useLiveBackend)}
            title="Click to toggle between Live Node Gateway (port 3000) and Local Standalone Triage Engine"
          >
            <Wifi size={13} className="telemetry-icon" />
            <span className="pill-label">GATEWAY:</span>
            <span className="pill-val">
              {useLiveBackend 
                ? (backendStatus === 'online' ? 'LIVE (PORT 3000)' : 'UNREACHABLE (RETRY)') 
                : 'SIMULATION MODE'}
            </span>
          </button>

          <div className="clock-badge">
            <Clock size={13} />
            <span className="utc-time">{formatUtc(currentTime)}</span>
          </div>

          <div className="analyst-badge">
            <div className="analyst-avatar">AL</div>
            <div className="analyst-meta">
              <span className="analyst-name">A. Levi</span>
              <span className="analyst-role">Lead SOC Triage</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="nav-tabs-bar">
        <div className="nav-tabs">
          <button 
            className={`nav-tab-btn ${activeTab === 'triage' ? 'active' : ''}`}
            onClick={() => setActiveTab('triage')}
          >
            <Terminal size={15} />
            <span>Interactive Threat Triage</span>
            {activeTab === 'triage' && <span className="tab-indicator"></span>}
          </button>

          <button 
            className={`nav-tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <Radio size={15} />
            <span>Audit Trail & Incident Ledger</span>
            {activeTab === 'audit' && <span className="tab-indicator"></span>}
          </button>

          <button 
            className={`nav-tab-btn ${activeTab === 'analytics' ? 'active' : ''}`}
            onClick={() => setActiveTab('analytics')}
          >
            <Shield size={15} />
            <span>Threat Intelligence & Heuristics</span>
            {activeTab === 'analytics' && <span className="tab-indicator"></span>}
          </button>

          <button 
            className={`nav-tab-btn ${activeTab === 'playbooks' ? 'active' : ''}`}
            onClick={() => setActiveTab('playbooks')}
          >
            <User size={15} />
            <span>Containment Playbooks</span>
            {activeTab === 'playbooks' && <span className="tab-indicator"></span>}
          </button>
        </div>

        <button 
          className="refresh-btn" 
          onClick={onRefresh}
          title="Refresh Feed & Audit Trail"
        >
          <RefreshCw size={14} />
          <span>Sync Feed</span>
        </button>
      </div>
    </header>
  );
}
