// Pre-loaded realistic Deloitte SOC Triage Audit Trail items
export const INITIAL_AUDIT_LOGS = [
  {
    _id: "soc-entry-901",
    url: "http://secure-update-login-paypal.com.account-verify.xyz/@auth/session",
    ai_risk_score: 1,
    vt_malicious_flags: 24,
    threatScore: 94,
    status: "CRITICAL",
    timestamp: new Date(Date.now() - 1000 * 60 * 4).toISOString(), // 4 mins ago
    analyst: "A. Levi (L2)",
    indicators: ["Obfuscated @ symbol", "Suspicious tokens: login, secure, update, account", "High-risk TLD: .xyz", "Deep dot hierarchy"]
  },
  {
    _id: "soc-entry-902",
    url: "http://192.168.1.105:8080/update/secure-patch.exe",
    ai_risk_score: 1,
    vt_malicious_flags: 17,
    threatScore: 88,
    status: "CRITICAL",
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(), // 18 mins ago
    analyst: "Automated SIEM",
    indicators: ["Raw IPv4 Host", "Non-standard port 8080", "Suspicious token: secure", "Direct executable path"]
  },
  {
    _id: "soc-entry-903",
    url: "http://verify.account.appleid.security.login.com.fake-auth.net/portal",
    ai_risk_score: 1,
    vt_malicious_flags: 31,
    threatScore: 92,
    status: "CRITICAL",
    timestamp: new Date(Date.now() - 1000 * 60 * 42).toISOString(),
    analyst: "A. Levi (L2)",
    indicators: ["Subdomain spoofing: appleid.security", "Tokens: verify, account, login", "Deep dot hierarchy (6 dots)"]
  },
  {
    _id: "soc-entry-904",
    url: "https://portal.deloitte.com/identity/saml2/sso",
    ai_risk_score: 0,
    vt_malicious_flags: 0,
    threatScore: 4,
    status: "SAFE",
    timestamp: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
    analyst: "Endpoint Guard",
    indicators: ["Deloitte verified enterprise FQDN", "Valid TLS certificate", "Clean reputation"]
  },
  {
    _id: "soc-entry-905",
    url: "http://customer-invoice-document-dl.cfd/view.pdf",
    ai_risk_score: 1,
    vt_malicious_flags: 8,
    threatScore: 78,
    status: "WARNING",
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    analyst: "Email Filter Gateway",
    indicators: ["High-risk registrar TLD (.cfd)", "Insecure HTTP scheme", "Spam campaign correlation"]
  },
  {
    _id: "soc-entry-906",
    url: "https://github.com/deloitte/threat-intel-feeds/archive/main.zip",
    ai_risk_score: 0,
    vt_malicious_flags: 0,
    threatScore: 2,
    status: "SAFE",
    timestamp: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    analyst: "DevOps Pipeline",
    indicators: ["Reputable software repository", "HTTPS TLS v1.3", "Zero vendor flags"]
  },
  {
    _id: "soc-entry-907",
    url: "http://microsoft-outlook-web-access-recovery.club/auth",
    ai_risk_score: 1,
    vt_malicious_flags: 19,
    threatScore: 89,
    status: "CRITICAL",
    timestamp: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
    analyst: "A. Levi (L2)",
    indicators: ["Typosquatting: outlook-web-access", "High-risk TLD: .club", "Credential harvesting target"]
  }
];

export const PRESET_SCENARIOS = [
  {
    id: "phishing-bank",
    title: "PayPal Credential Harvester",
    badge: "Phishing Kit",
    url: "http://secure-update-login-paypal.com.account-verify.xyz/@auth/session",
    severity: "danger",
    description: "Multi-token bait with '@' obfuscator on disposable .xyz TLD"
  },
  {
    id: "malware-ip",
    title: "Direct IP Payload Stager",
    badge: "Malware Stager",
    url: "http://192.168.1.105:8080/update/secure-patch.exe",
    severity: "danger",
    description: "Direct RFC1918 host on non-standard port serving binary payload"
  },
  {
    id: "subdomain-spoof",
    title: "Deep Subdomain Brand Spoof",
    badge: "Brand Impersonation",
    url: "http://verify.account.appleid.security.login.com.fake-auth.net/portal",
    severity: "warning",
    description: "6-tier subdomain hierarchy spoofing Apple ID authentication"
  },
  {
    id: "deloitte-corp",
    title: "Deloitte Enterprise SSO",
    badge: "Corporate Portal",
    url: "https://portal.deloitte.com/identity/saml2/sso",
    severity: "safe",
    description: "Legitimate enterprise SAML 2.0 Identity Provider gateway"
  },
  {
    id: "clean-web",
    title: "Public Knowledge Base",
    badge: "Whitelisted",
    url: "https://en.wikipedia.org/wiki/Computer_security",
    severity: "safe",
    description: "High-reputation public encyclopedia with valid TLS 1.3"
  }
];
