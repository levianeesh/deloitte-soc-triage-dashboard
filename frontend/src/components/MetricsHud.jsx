import React from 'react';
import { ShieldAlert, Activity, CheckCircle2, Zap, AlertTriangle } from 'lucide-react';

export default function MetricsHud({ auditLogs }) {
  const total = auditLogs.length;
  const maliciousCount = auditLogs.filter(item => item.ai_risk_score === 1 || item.threatScore >= 60).length;
  const cleanCount = total - maliciousCount;
  const maliciousPct = total > 0 ? Math.round((maliciousCount / total) * 100) : 0;

  return (
    <div className="metrics-hud-grid">
      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-title">TOTAL AUDIT INGESTION</span>
          <div className="metric-icon-box blue">
            <Activity size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-number">{total}</span>
          <span className="metric-subtext">Active IoC logs recorded</span>
        </div>
        <div className="metric-progress-bar">
          <div className="progress-fill blue" style={{ width: '100%' }}></div>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-title">CONFIRMED PHISHING / THREATS</span>
          <div className="metric-icon-box red">
            <ShieldAlert size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-number text-danger">{maliciousCount}</span>
          <span className="metric-tag danger">{maliciousPct}% of target URLs</span>
        </div>
        <div className="metric-progress-bar">
          <div className="progress-fill red" style={{ width: `${maliciousPct}%` }}></div>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-title">BENIGN / VERIFIED CLEAN</span>
          <div className="metric-icon-box green">
            <CheckCircle2 size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-number text-safe">{cleanCount}</span>
          <span className="metric-tag safe">{100 - maliciousPct}% Whitelisted</span>
        </div>
        <div className="metric-progress-bar">
          <div className="progress-fill green" style={{ width: `${100 - maliciousPct}%` }}></div>
        </div>
      </div>

      <div className="metric-card">
        <div className="metric-header">
          <span className="metric-title">MEAN TIME TO TRIAGE (MTTT)</span>
          <div className="metric-icon-box cyan">
            <Zap size={18} />
          </div>
        </div>
        <div className="metric-value-row">
          <span className="metric-number text-cyan">138<span className="metric-unit">ms</span></span>
          <span className="metric-tag live">Real-time AI Inference</span>
        </div>
        <div className="metric-status-row">
          <span className="defcon-badge">
            <AlertTriangle size={12} />
            <span>THREAT POSTURE: ELEVATED (DEFCON 3)</span>
          </span>
        </div>
      </div>
    </div>
  );
}
