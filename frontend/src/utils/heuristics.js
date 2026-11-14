// Deloitte Cyber Threat Intelligence - Heuristic & IoC Analysis Engine

export const SUSPICIOUS_KEYWORDS = [
  'login',
  'verify',
  'update',
  'secure',
  'account',
  'banking',
  'signin',
  'authenticate',
  'confirm',
  'credential',
  'password',
  'security',
  'wallet',
  'support',
  'invoice'
];

export const HIGH_RISK_TLDS = [
  'xyz', 'top', 'club', 'work', 'date', 'kim', 'loan', 'racing', 'men', 'click', 'cfd', 'cc', 'tk', 'ml', 'ga', 'gq'
];

/**
 * Deconstructs and extracts deep cyber heuristics from a raw target URL.
 */
export function extractUrlFeatures(rawUrl) {
  const url = (rawUrl || '').trim();
  let parsed = null;
  let hasValidProtocol = false;

  try {
    let normalized = url;
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = 'http://' + normalized;
    }
    parsed = new URL(normalized);
    hasValidProtocol = /^https?:\/\//i.test(url);
  } catch (e) {
    // URL parsing fallback
    parsed = {
      protocol: 'http:',
      hostname: url.split('/')[0].split('?')[0].split('@').pop() || '',
      pathname: '/' + (url.split('/')[1] || ''),
      search: '',
      hash: '',
      port: ''
    };
  }

  const hostname = parsed.hostname || '';
  const length = url.length;
  const hasAtSymbol = url.includes('@') ? 1 : 0;
  const hasIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(hostname) || /\[[0-9a-fA-F:]+\]/.test(hostname) ? 1 : 0;
  const dotCount = (url.match(/\./g) || []).length;
  const hostnameDotCount = (hostname.match(/\./g) || []).length;

  // Suspicious keyword matches
  const lowerUrl = url.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => lowerUrl.includes(kw));
  const hasSuspiciousWords = matchedKeywords.length > 0 ? 1 : 0;

  // Top Level Domain analysis
  const hostParts = hostname.split('.');
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1].toLowerCase() : '';
  const isHighRiskTld = HIGH_RISK_TLDS.includes(tld);

  // Subdomain depth analysis
  const subdomainDepth = Math.max(0, hostParts.length - 2);

  // Obfuscation & character entropy indicators
  const hyphenCount = (url.match(/-/g) || []).length;
  const hasHexOrPercent = /%[0-9a-fA-F]{2}/.test(url);
  const hasMultipleSubdomains = subdomainDepth >= 3;
  const hasNonStandardPort = parsed.port && !['80', '443'].includes(parsed.port);

  // AI Random Forest Feature Mapping (exact match to Python model format)
  const ai_features = {
    "Length": length,
    "Has '@'": hasAtSymbol,
    "Has IP": hasIp,
    "Dot Count": dotCount,
    "Suspicious Words": hasSuspiciousWords
  };

  // Heuristic Threat Score Calculation (0 to 100)
  let threatScore = 5; // Base baseline

  if (hasAtSymbol) threatScore += 35; // Major phishing indicator (obscures true host)
  if (hasIp) threatScore += 30; // Direct IP hosts bypass domain reputation
  if (hasSuspiciousWords) threatScore += 20 + Math.min(15, (matchedKeywords.length - 1) * 8);
  if (dotCount >= 4) threatScore += 15;
  if (length > 75) threatScore += 12;
  if (isHighRiskTld) threatScore += 18;
  if (hasMultipleSubdomains) threatScore += 15;
  if (hyphenCount >= 3) threatScore += 10;
  if (hasHexOrPercent) threatScore += 8;
  if (parsed.protocol === 'http:') threatScore += 10; // Unencrypted transport
  if (hasNonStandardPort) threatScore += 12;

  // Known trusted whitelist deduction
  const trustedDomains = ['google.com', 'microsoft.com', 'deloitte.com', 'github.com', 'apple.com', 'wikipedia.org', 'cloudflare.com'];
  if (trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
    threatScore = Math.min(threatScore, 10);
  }

  threatScore = Math.min(99, Math.max(1, threatScore));

  const isMalicious = threatScore >= 60 || hasAtSymbol === 1 || (hasIp === 1 && hasSuspiciousWords === 1);
  const ai_risk_score = isMalicious ? 1 : 0;

  // Simulated VirusTotal Flags if backend is in standalone mode
  let vt_malicious_flags = 0;
  if (threatScore >= 80) {
    vt_malicious_flags = Math.floor(18 + (threatScore - 80) * 1.5);
  } else if (threatScore >= 55) {
    vt_malicious_flags = Math.floor(4 + (threatScore - 55) * 0.4);
  } else if (threatScore >= 35) {
    vt_malicious_flags = Math.random() > 0.6 ? 1 : 0;
  }

  return {
    rawUrl,
    parsed: {
      protocol: parsed.protocol || 'http:',
      hostname,
      pathname: parsed.pathname || '/',
      port: parsed.port || '',
      tld,
      subdomainDepth
    },
    ai_risk_score,
    ai_features,
    threatScore,
    vt_malicious_flags,
    matchedKeywords,
    indicators: {
      hasAtSymbol: Boolean(hasAtSymbol),
      hasIp: Boolean(hasIp),
      isHighRiskTld,
      hasMultipleSubdomains,
      lengthRisk: length > 75,
      excessiveDots: dotCount >= 4,
      hyphenCount,
      hasNonStandardPort: Boolean(hasNonStandardPort)
    }
  };
}

/**
 * Maps threat indicators to the MITRE ATT&CK Enterprise Matrix.
 */
export function getMitreAttackMapping(features) {
  const tactics = [];

  if (features.ai_risk_score === 1 || features.threatScore >= 50) {
    tactics.push({
      id: 'T1566.002',
      name: 'Spearphishing Link',
      tactic: 'Initial Access',
      severity: 'Critical',
      description: 'Adversary crafts malicious hyperlinks to lure targets into credential harvesting or payload execution.'
    });

    tactics.push({
      id: 'T1204.001',
      name: 'User Execution: Malicious Link',
      tactic: 'Execution',
      severity: 'High',
      description: 'Reliance on victim clicking an unvetted or obfuscated URL to initiate malicious web session.'
    });
  }

  if (features.indicators.hasAtSymbol || features.indicators.excessiveDots || features.indicators.hasMultipleSubdomains) {
    tactics.push({
      id: 'T1036.007',
      name: 'Masquerading: Obfuscated Domain Hierarchy',
      tactic: 'Defense Evasion',
      severity: 'High',
      description: 'Leveraging nested subdomains or user-info delimiters (@) to mimic legitimate brand identity.'
    });
  }

  if (features.indicators.hasIp) {
    tactics.push({
      id: 'T1583.001',
      name: 'Acquire Infrastructure: Direct IP Staging',
      tactic: 'Resource Development',
      severity: 'Medium',
      description: 'Direct IP host usage without domain registration, common in ephemeral C2 or rapid phishing kits.'
    });
  }

  if (features.indicators.isHighRiskTld) {
    tactics.push({
      id: 'T1583.001',
      name: 'Acquire Infrastructure: High-Risk Registrar TLD',
      tactic: 'Resource Development',
      severity: 'Medium',
      description: 'Utilization of low-reputation or free TLDs prone to automated disposable domain provisioning.'
    });
  }

  if (tactics.length === 0) {
    tactics.push({
      id: 'T1596.001',
      name: 'Search Open Technical Databases (Benign Traffic)',
      tactic: 'Reconnaissance',
      severity: 'Info',
      description: 'No active offensive adversary tactics detected in target parameters.'
    });
  }

  return tactics;
}

/**
 * Generates automated SOC Containment Scripts & Rules.
 */
export function generateContainmentRules(targetUrl, hostname, threatScore) {
  const sanitizedHost = (hostname || 'malicious-domain.xyz').replace(/[^a-zA-Z0-9.-]/g, '');
  const timestamp = new Date().toISOString();

  // Palo Alto Networks CLI Block Command
  const paloAltoRule = `# Palo Alto Networks PAN-OS URL Filtering Block Rule
set profiles custom-url-category "SOC-DELOITTE-MALICIOUS-IOCS" list [ ${sanitizedHost} ]
set rulebase security rules "BLOCK-MALICIOUS-OUTBOUND" category [ SOC-DELOITTE-MALICIOUS-IOCS ] action drop
commit`;

  // Cisco / iptables Sinkhole Rule
  const iptablesRule = `# Linux iptables DNS & Outbound Drop Rule
iptables -A OUTPUT -p tcp -m string --string "${sanitizedHost}" --algo bm -j DROP
iptables -A OUTPUT -p udp --dport 53 -m string --string "${sanitizedHost}" --algo bm -j REJECT --reject-with icmp-port-unreachable`;

  // Microsoft 365 Defender / Exchange Online PowerShell Purge
  const exchangePowerShell = `# Exchange Online / M365 Security Purge Script
# Created by Deloitte SOC Triage Engine at ${timestamp}
Connect-ExchangeOnline
New-ComplianceSearch -Name "SOC_Purge_${Date.now()}" -ExchangeLocation All -ContentMatchQuery 'body:"${targetUrl}"'
Start-ComplianceSearch -Identity "SOC_Purge_${Date.now()}"
# Action: Soft-delete or Move to Quarantine`;

  // Splunk SPL Threat Hunting Query
  const splunkSpl = `index=firewall OR index=proxy OR index=edr
| search "${sanitizedHost}" OR "${targetUrl}"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src_ip, user, dest_ip, url, action
| eval ThreatRating="DELOITTE-SOC-ALERT", RiskScore=${threatScore}
| table first_seen, last_seen, src_ip, user, dest_ip, url, action, ThreatRating`;

  // ServiceNow SecOps Incident Payload
  const serviceNowTicket = {
    incident_number: `INC-SOC-${Math.floor(100000 + Math.random() * 900000)}`,
    title: `[DELOITTE-SOC] High Severity Malicious URL Detected: ${sanitizedHost}`,
    category: 'Cybersecurity Threat',
    priority: threatScore >= 75 ? '1 - Critical' : threatScore >= 50 ? '2 - High' : '3 - Medium',
    assigned_group: 'Deloitte Global SOC Tier-2 Incident Response',
    target_indicator: targetUrl,
    heuristic_risk_score: threatScore,
    recommended_action: 'Isolate affected host, update perimeter firewall blocklist, revoke active authentication tokens.'
  };

  return {
    paloAltoRule,
    iptablesRule,
    exchangePowerShell,
    splunkSpl,
    serviceNowTicket
  };
}
