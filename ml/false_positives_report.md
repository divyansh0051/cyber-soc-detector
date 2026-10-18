# Threat Defense Note: Deep-Dive Analysis on False Positives & Edge Cases

## 1. Executive Summary
In cybersecurity production systems, **False Positives (FP)** directly cause alert fatigue and disrupt legitimate business communications. Our URL classification model achieved **98.97% Precision** and **96.33% Recall** with an ROC-AUC of **0.9996**.

Out of 2400 held-out test URLs, only **12 False Positives** were observed (0.5% error rate).

---

## 2. Root Cause Breakdown of False Positives

| Edge Case Scenario | Why the Model Flagged It | Example URL | Defensive Mitigation Rule |
| :--- | :--- | :--- | :--- |
| **Enterprise SSO & OAuth Callbacks** | High entropy tokens, embedded query parameters (`?code=...&state=...`), and auth keywords (`/login`, `/auth`). | `https://auth.company.com/oauth/v2/authorize?client_id=9812&state=x7F9` | Whitelist apex enterprise domains and verify TLS certificate identity. |
| **Content Delivery Networks (CDNs)** | Subdomain depth >= 3 and hash-based asset paths mimicking obfuscated phishing paths. | `https://static.cdn.fastly.net/assets/v2/bundle.481f9a.js` | Disregard asset extensions (`.js`, `.css`, `.png`, `.woff2`) from phishing classification. |
| **Marketing & Tracking URLs** | Multiple redirect hops, deep query strings, and tracking parameters (`utm_source`, `affiliate_id`). | `https://store.target.com/promo?utm_source=email&affiliate=partner` | Parameter stripping during URL normalization prior to feature extraction. |
| **URL Shorteners for Legitimate Ads** | Domain masking (`bit.ly`, `tinyurl.com`) without visible destination hostname. | `https://bit.ly/3xSummerSale` | Automated HTTP HEAD pre-flight resolution to evaluate final destination domain before scoring. |

---

## 3. Engineering Mitigation Strategies Implemented

1. **Reputation Whitelisting**: Automated integration with Tranco / Cisco Umbrella Top 10k domains to bypass scoring for established corporate entities.
2. **Confidence Threshold Gating**:
   - `P(Phishing) >= 0.85`: High Confidence Malicious (Automated Block & Incident Ticket).
   - `0.50 <= P(Phishing) < 0.85`: Suspicious (Browser Warning Interstitial & User Consent).
   - `P(Phishing) < 0.50`: Clean (Transparent Passthrough).
3. **Multi-Modal Verification**: If URL has high entropy but valid TLS certificate issued by a recognized root CA to an established Organization (OV/EV), risk weight is discounted by 40%.
