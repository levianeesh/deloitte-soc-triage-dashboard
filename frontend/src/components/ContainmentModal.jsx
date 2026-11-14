import React, { useState } from 'react';
import { X, ShieldAlert, Terminal, Mail, FileText, CheckCircle2, Copy, Check, Send } from 'lucide-react';
import { generateContainmentRules } from '../utils/heuristics';

export default function ContainmentModal({ isOpen, onClose, modalType, targetUrl, threatScore }) {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState(modalType || 'firewall');
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployed, setDeployed] = useState(false);
  const [copied, setCopied] = useState(false);

  // Extract hostname
  let hostname = 'target-host.xyz';
  try {
    const formatted = /^https?:\/\//i.test(targetUrl) ? targetUrl : 'http://' + targetUrl;
    hostname = new URL(formatted).hostname;
  } catch {
    hostname = targetUrl.split('/')[0] || 'target-host.xyz';
  }

  const rules = generateContainmentRules(targetUrl, hostname, threatScore || 85);

  const getCode = () => {
    if (activeTab === 'firewall') return rules.paloAltoRule;
    if (activeTab === 'email') return rules.exchangePowerShell;
    if (activeTab === 'ticket') return JSON.stringify(rules.serviceNowTicket, null, 2);
    if (activeTab === 'splunk') return rules.splunkSpl;
    return rules.iptablesRule;
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(getCode());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDeploy = () => {
    setIsDeploying(true);
    setTimeout(() => {
      setIsDeploying(false);
      setDeployed(true);
      setTimeout(() => setDeployed(false), 4000);
    }, 1200);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="containment-modal" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div className="modal-title-group">
            <ShieldAlert className="text-danger" size={22} />
            <div>
              <h3>AUTOMATED INCIDENT CONTAINMENT RUNNER</h3>
              <span className="modal-target-host">Target Host: <code>{hostname}</code></span>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Modal Tabs */}
        <div className="modal-tabs">
          <button 
            className={`modal-tab-btn ${activeTab === 'firewall' ? 'active' : ''}`}
            onClick={() => setActiveTab('firewall')}
          >
            <Terminal size={14} />
            <span>Palo Alto / Firewall</span>
          </button>

          <button 
            className={`modal-tab-btn ${activeTab === 'email' ? 'active' : ''}`}
            onClick={() => setActiveTab('email')}
          >
            <Mail size={14} />
            <span>Exchange Online Purge</span>
          </button>

          <button 
            className={`modal-tab-btn ${activeTab === 'ticket' ? 'active' : ''}`}
            onClick={() => setActiveTab('ticket')}
          >
            <FileText size={14} />
            <span>ServiceNow Incident</span>
          </button>

          <button 
            className={`modal-tab-btn ${activeTab === 'splunk' ? 'active' : ''}`}
            onClick={() => setActiveTab('splunk')}
          >
            <span>Splunk SPL Hunt</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          <div className="code-container">
            <div className="code-header">
              <span className="code-lang">
                {activeTab === 'firewall' && 'PAN-OS CLI (Command Line Interface)'}
                {activeTab === 'email' && 'PowerShell ExchangeOnlineManagement'}
                {activeTab === 'ticket' && 'ServiceNow REST API JSON Payload'}
                {activeTab === 'splunk' && 'Splunk Search Processing Language'}
              </span>
              <button className="copy-code-btn" onClick={handleCopy}>
                {copied ? <Check size={13} className="text-safe" /> : <Copy size={13} />}
                <span>{copied ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>
            <pre className="modal-code-block"><code>{getCode()}</code></pre>
          </div>

          {deployed && (
            <div className="containment-success-alert">
              <CheckCircle2 size={18} className="text-safe" />
              <div>
                <strong>Containment Automation Triggered!</strong>
                <p>Policy change queued for perimeter firewalls & SIEM ticket created.</p>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          <button className="btn-cancel" onClick={onClose}>Close</button>
          <button 
            className="btn-deploy"
            onClick={handleDeploy}
            disabled={isDeploying}
          >
            {isDeploying ? (
              <>
                <div className="spinner sm"></div>
                <span>PROVISIONING ACTION...</span>
              </>
            ) : (
              <>
                <Send size={15} />
                <span>EXECUTE AUTO-CONTAINMENT</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
