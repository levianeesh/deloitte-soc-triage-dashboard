import React, { useState } from 'react';
import { Shield, Terminal, Mail, FileText, CheckCircle2, Copy, Check, ExternalLink, Code } from 'lucide-react';

export default function Playbooks() {
  const [copiedType, setCopiedType] = useState(null);

  const copyCode = (type, code) => {
    navigator.clipboard.writeText(code);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const panOsCode = `# Palo Alto Networks PAN-OS CLI Automated Containment
set profiles custom-url-category "DELOITTE-SOC-BLOCKLIST" list [ malicious-target-ioc.xyz ]
set rulebase security rules "DROP-PHISHING-CAMPAIGN" category [ DELOITTE-SOC-BLOCKLIST ] action drop
commit`;

  const m365PurgeCode = `# Microsoft 365 Exchange Online Purge Automation
Connect-ExchangeOnline -UserPrincipalName soc-automation@deloitte.com
$Search = New-ComplianceSearch -Name "PHISH_PURGE_$(Get-Date -Format yyyyMMddHHmm)" \\
  -ExchangeLocation All -ContentMatchQuery 'body:"http*"'
Start-ComplianceSearch -Identity $Search.Identity
New-ComplianceSearchAction -SearchName $Search.Identity -Purge -PurgeType SoftDelete`;

  const sentinelKql = `// Microsoft Sentinel KQL Proactive Threat Hunting Query
let MaliciousDomain = "malicious-target-ioc.xyz";
DeviceNetworkEvents
| where RemoteUrl has MaliciousDomain or RemoteIP in ("192.168.1.105")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, ActionType
| sort by TimeGenerated desc`;

  return (
    <div className="playbooks-container">
      <div className="playbooks-hero">
        <Shield size={24} className="text-deloitte" />
        <div>
          <h2>Deloitte SOC Incident Containment Playbooks & SOPs</h2>
          <p>
            Standard Operating Procedures and automated scripts for rapid enterprise incident response and threat remediation.
          </p>
        </div>
      </div>

      <div className="playbooks-grid">
        {/* Playbook 1: Perimeter Firewall Containment */}
        <div className="playbook-card">
          <div className="playbook-head">
            <div className="playbook-icon-wrapper">
              <Terminal size={18} />
            </div>
            <div>
              <h3>PERIMETER FIREWALL SINKHOLE & ACL</h3>
              <span className="playbook-sub">Palo Alto Networks / FortiGate / Cisco</span>
            </div>
            <button 
              className="copy-playbook-btn"
              onClick={() => copyCode('panos', panOsCode)}
            >
              {copiedType === 'panos' ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
              <span>{copiedType === 'panos' ? 'Copied' : 'Copy PAN-OS CLI'}</span>
            </button>
          </div>
          <p className="playbook-desc">
            Instantly pushes identified malicious FQDNs or IP addresses to the perimeter URL filtering drop policy to sever outbound callback beaconing.
          </p>
          <pre className="code-block"><code>{panOsCode}</code></pre>
        </div>

        {/* Playbook 2: Email Gateway Invalidation */}
        <div className="playbook-card">
          <div className="playbook-head">
            <div className="playbook-icon-wrapper mail">
              <Mail size={18} />
            </div>
            <div>
              <h3>EXCHANGE ONLINE / M365 EMAIL PURGE</h3>
              <span className="playbook-sub">Microsoft Defender for Office 365</span>
            </div>
            <button 
              className="copy-playbook-btn"
              onClick={() => copyCode('m365', m365PurgeCode)}
            >
              {copiedType === 'm365' ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
              <span>{copiedType === 'm365' ? 'Copied' : 'Copy PowerShell'}</span>
            </button>
          </div>
          <p className="playbook-desc">
            Executes tenant-wide compliance search across all corporate mailboxes and automatically soft-deletes unread phishing emails containing the target payload URL.
          </p>
          <pre className="code-block"><code>{m365PurgeCode}</code></pre>
        </div>

        {/* Playbook 3: SIEM / EDR Threat Hunting */}
        <div className="playbook-card full-width">
          <div className="playbook-head">
            <div className="playbook-icon-wrapper kql">
              <Code size={18} />
            </div>
            <div>
              <h3>MICROSOFT SENTINEL / DEFENDER FOR ENDPOINT (KQL)</h3>
              <span className="playbook-sub">Kusto Query Language for Fleet Correlation</span>
            </div>
            <button 
              className="copy-playbook-btn"
              onClick={() => copyCode('kql', sentinelKql)}
            >
              {copiedType === 'kql' ? <Check size={14} className="text-safe" /> : <Copy size={14} />}
              <span>{copiedType === 'kql' ? 'Copied' : 'Copy KQL'}</span>
            </button>
          </div>
          <p className="playbook-desc">
            Queries endpoint telemetry across the corporate fleet to identify any workstation that initiated outbound network traffic to the malicious IoC within the past 7 days.
          </p>
          <pre className="code-block"><code>{sentinelKql}</code></pre>
        </div>
      </div>
    </div>
  );
}
