import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Cpu, 
  Globe, 
  Layers, 
  Copy, 
  Check, 
  Download, 
  ExternalLink, 
  Lock, 
  Radio, 
  Terminal,
  FileText,
  AlertOctagon,
  Shield
} from 'lucide-react';
import { getMitreAttackMapping } from '../utils/heuristics';

export default function ThreatResult({ result, onOpenContainment }) {
  const [copiedIoc, setCopiedIoc] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  if (!result) return null;

  const isMalicious = result.ai_risk_score === 1 || result.vt_malicious_flags > 0;
  const isHighRisk = result.ai_risk_score === 1 && result.vt_malicious_flags > 5;
  const threatScore = result.threatScore || (result.ai_risk_score === 1 ? Math.min(95, 65 + result.vt_malicious_flags * 1.5) : Math.max(5, result.vt_malicious_flags * 8));

  // Determine severity tier
  let severityTier = 'safe';
  let severityLabel = 'BENIGN // VERIFIED SAFE';
  let severityColor = 'var(--deloitte-safe)';

  if (threatScore >= 75) {
    severityTier = 'critical';
    severityLabel = 'CRITICAL RISK // CONFIRMED MALICIOUS PHISHING';
    severityColor = 'var(--deloitte-danger)';
  } else if (threatScore >= 45 || result.vt_malicious_flags > 0) {
    severityTier = 'warning';
    severityLabel = 'SUSPICIOUS // POTENTIAL THREAT FLAGGED';
    severityColor = 'var(--deloitte-warning)';
  }

  // Parse feature attributes safely
  const features = result.ai_features || {};
  const lengthVal = features["Length"] ?? result.url?.length ?? 0;
  const hasAt = features["Has '@'"] ?? (result.url?.includes('@') ? 1 : 0);
  const hasIp = features["Has IP"] ?? (/\d+\.\d+\.\d+\.\d+/.test(result.url) ? 1 : 0);
  const dotCount = features["Dot Count"] ?? ((result.url?.match(/\./g) || []).length);
  const suspiciousWordCount = features["Suspicious Words"] ?? (result.matchedKeywords?.length > 0 ? 1 : 0);

  // MITRE ATT&CK Mapping
  const mitreTactics = getMitreAttackMapping({
    ai_risk_score: result.ai_risk_score,
    threatScore,
    indicators: {
      hasAtSymbol: hasAt === 1,
      hasIp: hasIp === 1,
      isHighRiskTld: result.url?.endsWith('.xyz') || result.url?.endsWith('.cfd') || result.url?.endsWith('.club'),
      excessiveDots: dotCount >= 4,
      hasMultipleSubdomains: dotCount >= 3
    }
  });

  const handleCopyIoc = () => {
    navigator.clipboard.writeText(result.url);
    setCopiedIoc(true);
    setTimeout(() => setCopiedIoc(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleDownloadReport = () => {
    const reportData = {
      deloitte_soc_incident_report: {
        timestamp: new Date().toISOString(),
        target_url: result.url,
        composite_risk_score: threatScore,
        ai_heuristic_verdict: result.ai_risk_score === 1 ? 'MALICIOUS' : 'SAFE',
        ai_feature_telemetry: features,
        virustotal_vendor_flags: result.vt_malicious_flags,
        mitre_attack_techniques: mitreTactics,
        analyst: "A. Levi (Tier-2 SOC Lead)"
      }
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u;
    a.download = `deloitte-soc-triage-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(u);
  };

  return (
    <div className="threat-dossier-container">
      {/* Top Threat Banner */}
      <div className={`threat-verdict-banner ${severityTier}`}>
        <div className="verdict-score-radial">
          <div className="score-circle">
            <span className="score-number">{Math.round(threatScore)}</span>
            <span className="score-max">/100</span>
          </div>
          <span className="score-subtext">THREAT SCORE</span>
        </div>

        <div className="verdict-info-col">
          <div className="verdict-status-row">
            {severityTier === 'critical' && <AlertOctagon className="status-banner-icon danger" size={24} />}
            {severityTier === 'warning' && <AlertTriangle className="status-banner-icon warning" size={24} />}
            {severityTier === 'safe' && <ShieldCheck className="status-banner-icon safe" size={24} />}
            <span className="verdict-headline">{severityLabel}</span>
          </div>

          <p className="verdict-summary">
            {severityTier === 'critical'
              ? `Target URL exhibits critical malicious heuristics including high lexical risk and suspicious indicators. Immediate SOC containment recommended.`
              : severityTier === 'warning'
              ? `Elevated risk parameters detected. Target flagged by threat intelligence feeds or suspicious domain hierarchy. Proceed with caution.`
              : `Heuristic inspection confirms clean target parameters. Zero deceptive lexical tokens, valid host structure, and reputable origin.`}
          </p>

          <div className="verdict-target-row">
            <span className="target-label">ANALYZED TARGET:</span>
            <code className="target-code">{result.url}</code>
            <button className="copy-btn-inline" onClick={handleCopyIoc} title="Copy IoC to clipboard">
              {copiedIoc ? <Check size={13} className="text-safe" /> : <Copy size={13} />}
              <span>{copiedIoc ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>

        {/* Action Toolbar */}
        <div className="verdict-actions-col">
          <button 
            className="action-btn-primary danger"
            onClick={() => onOpenContainment('firewall', result.url, threatScore)}
          >
            <ShieldAlert size={15} />
            <span>CONTAIN THREAT</span>
          </button>

          <button 
            className="action-btn-secondary"
            onClick={handleDownloadReport}
          >
            <Download size={14} />
            <span>Export Dossier</span>
          </button>
        </div>
      </div>

      {/* Dual Correlation Engines Grid */}
      <div className="dual-engines-grid">
        {/* Engine 1: Local AI Heuristic Model */}
        <div className={`engine-card ${result.ai_risk_score === 1 ? 'border-danger' : 'border-safe'}`}>
          <div className="engine-card-header">
            <div className="engine-title-group">
              <Cpu size={18} className="engine-icon" />
              <div>
                <h3>LOCAL AI HEURISTIC ENGINE</h3>
                <span className="engine-sub">Scikit-Learn Random Forest Classifier (v2.4)</span>
              </div>
            </div>
            <span className={`engine-badge ${result.ai_risk_score === 1 ? 'malicious' : 'safe'}`}>
              {result.ai_risk_score === 1 ? '🚨 PREDICTED: MALICIOUS' : '✅ PREDICTED: SAFE'}
            </span>
          </div>

          {/* Heuristic Feature Breakdown Meters */}
          <div className="heuristic-metrics-list">
            {/* Feature 1: URL Length */}
            <div className="feature-meter-row">
              <div className="meter-label-col">
                <span className="meter-name">URL Length & Entropy</span>
                <span className="meter-val">{lengthVal} characters</span>
              </div>
              <div className="meter-bar-track">
                <div 
                  className={`meter-bar-fill ${lengthVal > 75 ? 'danger' : lengthVal > 45 ? 'warning' : 'safe'}`}
                  style={{ width: `${Math.min(100, (lengthVal / 120) * 100)}%` }}
                ></div>
              </div>
              <span className="meter-annotation">
                {lengthVal > 75 ? '⚠️ Elevated length increases evasion probability' : 'Normal length distribution'}
              </span>
            </div>

            {/* Feature 2: @ Delimiter Obfuscation */}
            <div className="feature-meter-row">
              <div className="meter-label-col">
                <span className="meter-name">User-Info '@' Delimiter Obfuscation</span>
                <span className={`meter-badge ${hasAt === 1 ? 'danger' : 'safe'}`}>
                  {hasAt === 1 ? 'DETECTED (HIGH RISK)' : 'NONE DETECTED'}
                </span>
              </div>
              <div className="meter-bar-track">
                <div 
                  className={`meter-bar-fill ${hasAt === 1 ? 'danger' : 'safe'}`}
                  style={{ width: hasAt === 1 ? '100%' : '5%' }}
                ></div>
              </div>
              <span className="meter-annotation">
                {hasAt === 1 ? '🚨 Used by attackers to obscure real destination host' : 'Standard RFC-3986 format'}
              </span>
            </div>

            {/* Feature 3: Raw IP Host Address */}
            <div className="feature-meter-row">
              <div className="meter-label-col">
                <span className="meter-name">Raw Direct IP Host Address</span>
                <span className={`meter-badge ${hasIp === 1 ? 'danger' : 'safe'}`}>
                  {hasIp === 1 ? 'DETECTED (IPv4 HOST)' : 'DOMAIN NAME HOST'}
                </span>
              </div>
              <div className="meter-bar-track">
                <div 
                  className={`meter-bar-fill ${hasIp === 1 ? 'danger' : 'safe'}`}
                  style={{ width: hasIp === 1 ? '100%' : '5%' }}
                ></div>
              </div>
              <span className="meter-annotation">
                {hasIp === 1 ? '⚠️ Direct IP host bypasses DNS reputation filters' : 'Standard DNS domain resolution'}
              </span>
            </div>

            {/* Feature 4: Dot Count Hierarchy */}
            <div className="feature-meter-row">
              <div className="meter-label-col">
                <span className="meter-name">Subdomain Dot Depth</span>
                <span className="meter-val">{dotCount} dots</span>
              </div>
              <div className="meter-bar-track">
                <div 
                  className={`meter-bar-fill ${dotCount >= 4 ? 'danger' : dotCount >= 2 ? 'warning' : 'safe'}`}
                  style={{ width: `${Math.min(100, (dotCount / 6) * 100)}%` }}
                ></div>
              </div>
              <span className="meter-annotation">
                {dotCount >= 4 ? '🚨 Deep nested subdomain spoofing detected' : 'Standard domain hierarchy'}
              </span>
            </div>

            {/* Feature 5: Suspicious Lexical Words */}
            <div className="feature-meter-row">
              <div className="meter-label-col">
                <span className="meter-name">Suspicious Phishing Lexical Tokens</span>
                <span className={`meter-badge ${suspiciousWordCount === 1 ? 'danger' : 'safe'}`}>
                  {suspiciousWordCount === 1 ? 'KEYWORD MATCH' : 'CLEAN'}
                </span>
              </div>
              <div className="lexical-tokens-tags">
                {['login', 'verify', 'update', 'secure', 'account'].map(token => {
                  const matched = result.url?.toLowerCase().includes(token);
                  return (
                    <span key={token} className={`token-chip ${matched ? 'matched' : 'unmatched'}`}>
                      {token} {matched && '✓'}
                    </span>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Engine 2: VirusTotal Global Threat Intelligence */}
        <div className={`engine-card ${result.vt_malicious_flags > 0 ? 'border-warning' : 'border-safe'}`}>
          <div className="engine-card-header">
            <div className="engine-title-group">
              <Globe size={18} className="engine-icon" />
              <div>
                <h3>VIRUSTOTAL GLOBAL THREAT INTEL</h3>
                <span className="engine-sub">Correlated across 72+ Cyber Security Vendors</span>
              </div>
            </div>
            <span className={`engine-badge ${result.vt_malicious_flags > 0 ? 'warning' : 'safe'}`}>
              {result.vt_malicious_flags > 0 ? `⚠️ ${result.vt_malicious_flags} VENDORS FLAGGED` : '✅ 0 FLAGS (CLEAN)'}
            </span>
          </div>

          <div className="vt-intel-body">
            <div className="vt-ratio-display">
              <div className="vt-counter-box">
                <span className={`vt-count-num ${result.vt_malicious_flags > 0 ? 'text-warning' : 'text-safe'}`}>
                  {result.vt_malicious_flags}
                </span>
                <span className="vt-total-vendors">/ 72</span>
              </div>
              <div className="vt-verdict-summary">
                <span className="vt-headline">
                  {result.vt_malicious_flags > 5 
                    ? 'High-Confidence Malicious Threat' 
                    : result.vt_malicious_flags > 0 
                    ? 'Suspicious Detection Consensus' 
                    : 'Clean Reputation on Global Feeds'}
                </span>
                <span className="vt-detail">
                  Aggregated telemetry from CrowdStrike, Fortinet, Sophos, Kaspersky, Bitdefender, and Google Safebrowsing.
                </span>
              </div>
            </div>

            {/* Vendor Consensus Bar */}
            <div className="vt-consensus-bar">
              <div className="consensus-track">
                <div 
                  className={`consensus-fill ${result.vt_malicious_flags > 0 ? 'danger' : 'safe'}`}
                  style={{ width: `${Math.min(100, Math.max(3, (result.vt_malicious_flags / 72) * 100))}%` }}
                ></div>
              </div>
              <div className="consensus-labels">
                <span>0 Engines (Safe)</span>
                <span>36 Engines (50%)</span>
                <span>72 Engines (Consensus)</span>
              </div>
            </div>

            {/* Threat Categories Tags */}
            <div className="threat-categories-box">
              <span className="cat-title">IDENTIFIED THREAT TAGS:</span>
              <div className="cat-tags">
                {result.vt_malicious_flags > 0 ? (
                  <>
                    <span className="cat-tag danger">Phishing / Credential Harvester</span>
                    <span className="cat-tag danger">Deceptive Site</span>
                    <span className="cat-tag warning">Reputation Risk</span>
                  </>
                ) : (
                  <>
                    <span className="cat-tag safe">Benign Domain</span>
                    <span className="cat-tag safe">Legitimate Web Application</span>
                  </>
                )}
              </div>
            </div>

            {/* IoC Actions Box */}
            <div className="ioc-quick-box">
              <span className="ioc-label">RAW JSON TELEMETRY:</span>
              <button className="copy-json-btn" onClick={handleCopyJson}>
                {copiedJson ? <Check size={13} className="text-safe" /> : <Copy size={13} />}
                <span>{copiedJson ? 'Telemetry Copied' : 'Copy Full AI & VT JSON'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Mapping Table */}
      <div className="mitre-section-card">
        <div className="mitre-header">
          <div className="mitre-title-group">
            <Layers size={18} className="mitre-icon" />
            <div>
              <h3>MITRE ATT&CK® ENTERPRISE MAPPING</h3>
              <span className="mitre-sub">Tactics and techniques correlated to target heuristics</span>
            </div>
          </div>
          <span className="mitre-tag">Framework v14.1</span>
        </div>

        <div className="mitre-table-wrapper">
          <table className="mitre-table">
            <thead>
              <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>ATT&CK Tactic</th>
                <th>Severity</th>
                <th>Adversary Behavior Analysis</th>
              </tr>
            </thead>
            <tbody>
              {mitreTactics.map((tac, idx) => (
                <tr key={idx}>
                  <td>
                    <code className="mitre-id-badge">{tac.id}</code>
                  </td>
                  <td className="tech-name">
                    <strong>{tac.name}</strong>
                  </td>
                  <td>
                    <span className="tactic-pill">{tac.tactic}</span>
                  </td>
                  <td>
                    <span className={`severity-badge ${tac.severity.toLowerCase()}`}>
                      {tac.severity}
                    </span>
                  </td>
                  <td className="mitre-desc">{tac.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Response Playbook Quick Bar */}
      <div className="playbook-action-banner">
        <div className="playbook-banner-left">
          <Shield className="playbook-icon" size={20} />
          <div>
            <h4>SOC Analyst Recommended Playbooks</h4>
            <p>Rapid mitigation rules ready for automated firewall provisioning and email gateway search</p>
          </div>
        </div>
        <div className="playbook-btn-group">
          <button 
            className="playbook-btn"
            onClick={() => onOpenContainment('firewall', result.url, threatScore)}
          >
            Generate Firewall ACL
          </button>
          <button 
            className="playbook-btn"
            onClick={() => onOpenContainment('email', result.url, threatScore)}
          >
            Email Gateway Purge
          </button>
          <button 
            className="playbook-btn"
            onClick={() => onOpenContainment('ticket', result.url, threatScore)}
          >
            Dispatch SecOps Ticket
          </button>
        </div>
      </div>
    </div>
  );
}
