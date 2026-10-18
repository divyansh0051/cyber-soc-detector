export const PRESET_URLS = [
  {
    title: "Phishing: PayPal Spoofed Portal",
    url: "http://paypal-security-account-verification.xyz/login?session_token=9821fab3490",
    expected: "MALICIOUS",
    risk: 98.4
  },
  {
    title: "Phishing: Raw IP Authentication",
    url: "http://185.220.101.5/banking/update-credentials.php?target=auth",
    expected: "MALICIOUS",
    risk: 96.2
  },
  {
    title: "Phishing: Typosquatting Brand",
    url: "http://micros0ft-support-alert.top/verify-identity",
    expected: "MALICIOUS",
    risk: 94.7
  },
  {
    title: "Legitimate: Google Cloud Console",
    url: "https://console.cloud.google.com/monitoring/dashboards",
    expected: "SAFE",
    risk: 3.2
  },
  {
    title: "Legitimate: GitHub Repository",
    url: "https://github.com/scikit-learn/scikit-learn/releases/tag/1.4.0",
    expected: "SAFE",
    risk: 2.1
  },
  {
    title: "Edge Case: Enterprise SSO Callback",
    url: "https://auth.company.internal/oauth/v2/authorize?client_id=4821&state=e918ab2",
    expected: "SUSPICIOUS / SAFE (Gated)",
    risk: 38.5
  }
];

export const SOC_METRICS = {
  accuracy: 97.67,
  precision: 98.97,
  recall: 96.33,
  f1_score: 97.64,
  roc_auc: 0.9996,
  test_size: 2400,
  dataset_size: 12000,
  confusion_matrix: {
    true_negatives: 1188,
    false_positives: 12,
    false_negatives: 44,
    true_positives: 1156
  },
  feature_importances: [
    { feature: "is_ip_address", importance: 0.2450 },
    { feature: "suspicious_keywords_count", importance: 0.1820 },
    { feature: "tld_risk_score", importance: 0.1415 },
    { feature: "count_subdomains", importance: 0.1180 },
    { feature: "shannon_entropy", importance: 0.0945 },
    { feature: "url_length", importance: 0.0620 },
    { feature: "is_url_shortener", importance: 0.0480 },
    { feature: "count_hyphens", importance: 0.0385 },
    { feature: "has_https", importance: 0.0310 },
    { feature: "digit_ratio", importance: 0.0210 },
    { feature: "count_dots", importance: 0.0185 }
  ]
};

export const SAMPLE_LOG_INCIDENTS = [
  {
    id: "INC-2026-001",
    ip: "185.220.101.5",
    timestamp: "14/Oct/2026:15:32:11 +0000",
    method: "GET",
    uri: "/api/v1/users?id=10+UNION+SELECT+1,username,password+FROM+accounts--",
    status: 500,
    bytes: 1420,
    latency_ms: 840,
    severity: "CRITICAL",
    threat_category: "SQL_INJECTION",
    verdict: "MALICIOUS",
    anomaly_score: 0.985
  },
  {
    id: "INC-2026-002",
    ip: "194.26.29.112",
    timestamp: "14/Oct/2026:15:33:45 +0000",
    method: "GET",
    uri: "/download?file=../../../../etc/passwd",
    status: 403,
    bytes: 280,
    latency_ms: 412,
    severity: "HIGH",
    threat_category: "PATH_TRAVERSAL",
    verdict: "MALICIOUS",
    anomaly_score: 0.920
  },
  {
    id: "INC-2026-003",
    ip: "45.154.255.89",
    timestamp: "14/Oct/2026:15:34:02 +0000",
    method: "POST",
    uri: "/search?q=<script>alert('xss-session-steal')</script>",
    status: 200,
    bytes: 3100,
    latency_ms: 180,
    severity: "HIGH",
    threat_category: "CROSS_SITE_SCRIPTING",
    verdict: "MALICIOUS",
    anomaly_score: 0.895
  },
  {
    id: "INC-2026-004",
    ip: "185.220.101.5",
    timestamp: "14/Oct/2026:15:35:19 +0000",
    method: "POST",
    uri: "/cgi-bin/test-cgi?cmd=;+cat+/etc/shadow",
    status: 403,
    bytes: 340,
    latency_ms: 1200,
    severity: "CRITICAL",
    threat_category: "COMMAND_INJECTION",
    verdict: "MALICIOUS",
    anomaly_score: 0.992
  },
  {
    id: "INC-2026-005",
    ip: "194.26.29.112",
    timestamp: "14/Oct/2026:15:36:20 +0000",
    method: "POST",
    uri: "/api/v1/auth/login [Burst 42 failed attempts]",
    status: 401,
    bytes: 512,
    latency_ms: 95,
    severity: "HIGH",
    threat_category: "BRUTE_FORCE_BURST",
    verdict: "SUSPICIOUS",
    anomaly_score: 0.875
  }
];

export const ATTACKER_IPS = [
  { ip: "185.220.101.5", incident_count: 14, categories: ["SQL_INJECTION", "COMMAND_INJECTION"], severity: "CRITICAL", country: "Tor Exit Node / Bulletproof" },
  { ip: "194.26.29.112", incident_count: 9, categories: ["PATH_TRAVERSAL", "BRUTE_FORCE_BURST"], severity: "HIGH", country: "Unassigned ASN" },
  { ip: "45.154.255.89", incident_count: 5, categories: ["CROSS_SITE_SCRIPTING"], severity: "HIGH", country: "Commercial VPN" }
];

// In-browser fallback scanner
export function clientScanUrl(url) {
  const clean = url.trim().toLowerCase();
  const isIp = /^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(clean);
  const keywords = ["login", "verify", "account", "security", "update", "banking", "paypal", "wallet", "signin"];
  const kwMatches = keywords.filter((k) => clean.includes(k));
  const hasHttps = clean.startsWith("https://");
  const subdomains = (clean.split("/")[2] || "").split(".").length - 2;
  const isShortener = /bit\.ly|tinyurl\.com|t\.co|cutt\.ly/.test(clean);
  const isRiskyTld = /\.xyz|\.top|\.club|\.click|\.buzz|\.cf|\.icu/.test(clean);

  let score = 5.0;
  const factors = [];

  if (isIp) {
    score += 55.0;
    factors.append ? null : factors.push({ factor: "Raw IP Host Format", impact: "HIGH", detail: "Direct IPv4 address masks domain registry reputation." });
  }
  if (kwMatches.length > 0) {
    score += kwMatches.length * 20.0;
    factors.push({ factor: `Credential keywords detected: ${kwMatches.join(', ')}`, impact: "HIGH", detail: "Targets authentication theft." });
  }
  if (isRiskyTld) {
    score += 25.0;
    factors.push({ factor: "High-Risk Domain TLD", impact: "MEDIUM", detail: "Domain registered on frequently abused TLD." });
  }
  if (subdomains >= 2) {
    score += 15.0;
    factors.push({ factor: `High subdomain depth (${subdomains})`, impact: "MEDIUM", detail: "Subdomain spoofing pattern." });
  }
  if (isShortener) {
    score += 20.0;
    factors.push({ factor: "URL Shortener Masking", impact: "MEDIUM", detail: "Destination domain hidden from initial view." });
  }
  if (!hasHttps) {
    score += 10.0;
    factors.push({ factor: "Missing HTTPS Protocol", impact: "LOW", detail: "Plaintext HTTP connection." });
  }

  score = Math.min(Math.max(score, 2.0), 98.9);

  let verdict = "SAFE";
  let severity = "LOW";
  if (score >= 70) {
    verdict = "MALICIOUS";
    severity = "CRITICAL";
  } else if (score >= 40) {
    verdict = "SUSPICIOUS";
    severity = "MEDIUM";
  }

  return {
    url,
    verdict,
    severity,
    risk_score: score,
    phishing_probability: Number((score / 100).toFixed(4)),
    features: {
      url_length: url.length,
      count_dots: url.split('.').length - 1,
      count_subdomains: Math.max(0, subdomains),
      is_ip_address: isIp ? 1 : 0,
      has_https: hasHttps ? 1 : 0,
      suspicious_keywords_count: kwMatches.length,
      is_url_shortener: isShortener ? 1 : 0,
      tld_risk_score: isRiskyTld ? 0.85 : 0.1
    },
    risk_factors: factors
  };
}
