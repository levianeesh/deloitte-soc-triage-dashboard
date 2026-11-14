import React, { useState } from 'react';
import { Search, Filter, Download, ExternalLink, ShieldAlert, CheckCircle2, AlertTriangle, Copy, Check, Eye } from 'lucide-react';

export default function AuditTrail({ history, onSelectRecord }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [copiedId, setCopiedId] = useState(null);

  // Filter records
  const filteredHistory = history.filter(scan => {
    const matchesSearch = 
      (scan.url || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (scan._id || '').toLowerCase().includes(searchTerm.toLowerCase());

    if (!matchesSearch) return false;

    if (filterType === 'MALICIOUS') {
      return scan.ai_risk_score === 1 || scan.vt_malicious_flags > 5;
    }
    if (filterType === 'WARNING') {
      return scan.vt_malicious_flags > 0 && scan.vt_malicious_flags <= 5;
    }
    if (filterType === 'SAFE') {
      return scan.ai_risk_score === 0 && scan.vt_malicious_flags === 0;
    }
    return true;
  });

  const handleCopyUrl = (id, url, e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(url);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleExportCsv = () => {
    const headers = ["Timestamp", "Target URL", "AI Heuristic Verdict", "VT Malicious Flags", "Composite Score", "Analyst"];
    const rows = filteredHistory.map(item => [
      item.timestamp,
      `"${item.url}"`,
      item.ai_risk_score === 1 ? "MALICIOUS" : "SAFE",
      item.vt_malicious_flags || 0,
      item.threatScore || (item.ai_risk_score === 1 ? 88 : 5),
      item.analyst || "SOC Auto"
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `deloitte-soc-audit-trail-${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const formatRelativeTime = (isoDate) => {
    if (!isoDate) return 'Just now';
    const diffMs = Date.now() - new Date(isoDate).getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHrs = Math.floor(diffMin / 60);

    if (diffMin < 1) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHrs < 24) return `${diffHrs}h ago`;
    return new Date(isoDate).toLocaleDateString();
  };

  return (
    <div className="audit-trail-card">
      <div className="audit-header">
        <div className="audit-title-group">
          <h2>SOC Threat Triage Audit Trail & Incident Ledger</h2>
          <span className="audit-count-badge">{filteredHistory.length} Recorded Entries</span>
        </div>

        <div className="audit-actions-group">
          <button className="export-csv-btn" onClick={handleExportCsv} title="Export current view to CSV">
            <Download size={14} />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="audit-controls-bar">
        <div className="audit-search-wrapper">
          <Search size={15} className="search-icon" />
          <input
            type="text"
            className="audit-search-input"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by target URL, host, or IoC token..."
          />
        </div>

        <div className="filter-pill-group">
          <button 
            className={`filter-btn ${filterType === 'ALL' ? 'active' : ''}`}
            onClick={() => setFilterType('ALL')}
          >
            All Logs ({history.length})
          </button>
          <button 
            className={`filter-btn danger ${filterType === 'MALICIOUS' ? 'active' : ''}`}
            onClick={() => setFilterType('MALICIOUS')}
          >
            🚨 Malicious ({history.filter(h => h.ai_risk_score === 1 || h.vt_malicious_flags > 5).length})
          </button>
          <button 
            className={`filter-btn warning ${filterType === 'WARNING' ? 'active' : ''}`}
            onClick={() => setFilterType('WARNING')}
          >
            ⚠️ Warnings ({history.filter(h => h.vt_malicious_flags > 0 && h.vt_malicious_flags <= 5).length})
          </button>
          <button 
            className={`filter-btn safe ${filterType === 'SAFE' ? 'active' : ''}`}
            onClick={() => setFilterType('SAFE')}
          >
            ✅ Safe ({history.filter(h => h.ai_risk_score === 0 && h.vt_malicious_flags === 0).length})
          </button>
        </div>
      </div>

      {/* Audit Table */}
      <div className="table-responsive-wrapper">
        <table className="soc-table">
          <thead>
            <tr>
              <th style={{ width: '150px' }}>TIMESTAMP</th>
              <th>TARGET INDICATOR (URL / IOC)</th>
              <th style={{ width: '160px' }}>AI HEURISTIC (RF)</th>
              <th style={{ width: '160px' }}>GLOBAL INTEL (VT)</th>
              <th style={{ width: '140px' }}>RISK SCORE</th>
              <th style={{ width: '110px', textAlign: 'center' }}>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {filteredHistory.length === 0 ? (
              <tr>
                <td colSpan="6" className="empty-table-cell">
                  <div className="empty-state">
                    <Filter size={24} className="empty-icon" />
                    <p>No audit trail records match the specified search or filter.</p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredHistory.map((scan) => {
                const isMalicious = scan.ai_risk_score === 1 || scan.vt_malicious_flags > 5;
                const score = scan.threatScore || (scan.ai_risk_score === 1 ? 88 : scan.vt_malicious_flags > 0 ? 55 : 5);

                return (
                  <tr 
                    key={scan._id || scan.url + scan.timestamp} 
                    className="table-row-hover"
                    onClick={() => onSelectRecord(scan)}
                  >
                    <td>
                      <div className="time-col">
                        <span className="rel-time">{formatRelativeTime(scan.timestamp)}</span>
                        <span className="abs-time">{new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                      </div>
                    </td>

                    <td>
                      <div className="url-cell">
                        <span className="url-text" title={scan.url}>{scan.url}</span>
                        <button 
                          className="table-copy-btn" 
                          onClick={(e) => handleCopyUrl(scan._id, scan.url, e)}
                          title="Copy URL"
                        >
                          {copiedId === scan._id ? <Check size={12} className="text-safe" /> : <Copy size={12} />}
                        </button>
                      </div>
                    </td>

                    <td>
                      <span className={`badge ${scan.ai_risk_score === 1 ? 'malicious' : 'safe'}`}>
                        {scan.ai_risk_score === 1 ? '🚨 Phishing Alert' : '✅ Verified Safe'}
                      </span>
                    </td>

                    <td>
                      <span className={`badge ${scan.vt_malicious_flags > 0 ? (scan.vt_malicious_flags > 5 ? 'malicious' : 'warning') : 'safe'}`}>
                        {scan.vt_malicious_flags > 0
                          ? `⚠️ ${scan.vt_malicious_flags} Flags`
                          : '✅ Clean (0/72)'}
                      </span>
                    </td>

                    <td>
                      <div className="score-pill-wrapper">
                        <div 
                          className={`score-pill ${score >= 70 ? 'danger' : score >= 40 ? 'warning' : 'safe'}`}
                        >
                          {score}/100
                        </div>
                      </div>
                    </td>

                    <td style={{ textAlign: 'center' }}>
                      <button 
                        className="inspect-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectRecord(scan);
                        }}
                        title="Inspect Incident Dossier"
                      >
                        <Eye size={14} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
