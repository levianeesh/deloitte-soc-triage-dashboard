import React, { useState } from 'react';
import { Search, Globe, AlertTriangle, ShieldCheck, ArrowRight, CornerDownLeft, Sparkles, X } from 'lucide-react';
import { PRESET_SCENARIOS } from '../utils/mockData';

export default function TriageScanner({ url, setUrl, onAnalyze, loading }) {
  const [protocol, setProtocol] = useState('auto');

  const handlePresetClick = (presetUrl) => {
    setUrl(presetUrl);
  };

  const handleClear = () => {
    setUrl('');
  };

  // Preview extraction while user types
  const parsedHost = (() => {
    if (!url.trim()) return null;
    try {
      const formatted = /^https?:\/\//i.test(url) ? url : 'http://' + url;
      const u = new URL(formatted);
      return {
        protocol: u.protocol,
        hostname: u.hostname,
        pathname: u.pathname,
        port: u.port || (u.protocol === 'https:' ? '443' : '80')
      };
    } catch {
      return null;
    }
  })();

  return (
    <div className="triage-scanner-card">
      <div className="scanner-header">
        <div className="scanner-title-group">
          <div className="pulse-indicator"></div>
          <h2>Target IoC & URL Investigation Console</h2>
        </div>
        <div className="scanner-badge">AI Heuristic + VirusTotal Correlation</div>
      </div>

      <p className="scanner-instruction">
        Submit any suspicious hyperlink, phishing email target, or suspicious network stager. The Deloitte AI Engine will analyze lexical entropy, obfuscation markers, and global threat databases.
      </p>

      {/* Main Search Input Form */}
      <form className="scanner-form" onSubmit={onAnalyze}>
        <div className="input-field-wrapper">
          <div className="input-protocol-badge">
            <Globe size={15} />
            <span>URI</span>
          </div>

          <input
            type="text"
            className="main-url-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter target URL to triage (e.g., http://secure-update-login-paypal.com.account-verify.xyz/@auth)..."
            required
            autoComplete="off"
            spellCheck="false"
          />

          {url && (
            <button 
              type="button" 
              className="clear-input-btn"
              onClick={handleClear}
              title="Clear input"
            >
              <X size={15} />
            </button>
          )}
        </div>

        <button 
          className={`analyze-action-btn ${loading ? 'loading' : ''}`}
          type="submit" 
          disabled={loading || !url.trim()}
        >
          {loading ? (
            <>
              <div className="spinner"></div>
              <span>TRIAGING TARGET...</span>
            </>
          ) : (
            <>
              <Sparkles size={16} />
              <span>EXECUTE TRIAGE</span>
              <CornerDownLeft size={14} className="enter-icon" />
            </>
          )}
        </button>
      </form>

      {/* Live URL Parsing Inspector Preview */}
      {parsedHost && (
        <div className="live-parser-preview">
          <span className="preview-label">PARSED IOC:</span>
          <span className="preview-chip">Host: <strong>{parsedHost.hostname}</strong></span>
          <span className="preview-chip">Port: <strong>{parsedHost.port}</strong></span>
          <span className="preview-chip">Scheme: <strong>{parsedHost.protocol}</strong></span>
          <span className="preview-chip">Path: <strong>{parsedHost.pathname || '/'}</strong></span>
        </div>
      )}

      {/* Preset Investigation Scenarios */}
      <div className="preset-scenarios-section">
        <div className="preset-header">
          <span className="preset-label">1-CLICK SAMPLE THREAT SCENARIOS FOR EVALUATION:</span>
        </div>
        <div className="preset-pills-list">
          {PRESET_SCENARIOS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className={`preset-pill ${preset.severity} ${url === preset.url ? 'active' : ''}`}
              onClick={() => handlePresetClick(preset.url)}
              title={preset.description}
            >
              <span className="preset-tag-type">{preset.badge}</span>
              <span className="preset-title">{preset.title}</span>
              <ArrowRight size={13} className="preset-arrow" />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
