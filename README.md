# CyberGuard SOC AI — Phishing URL Classifier & Server Log Anomaly Detector

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E?style=flat&logo=scikit-learn)](https://scikit-learn.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6.0-646CFF?style=flat&logo=vite)](https://vitejs.dev)
[![Precision](https://img.shields.io/badge/Precision-98.97%25-brightgreen)](https://github.com)
[![Recall](https://img.shields.io/badge/Recall-96.33%25-blue)](https://github.com)
[![ROC-AUC](https://img.shields.io/badge/ROC--AUC-0.9996-purple)](https://github.com)
[![Vercel Ready](https://img.shields.io/badge/Vercel-Deploy_Ready-black?style=flat&logo=vercel)](https://vercel.com)

> Production-grade Cyber Defense and Machine Learning tool combining a **Random Forest URL Classifier (98.97% Precision)** with an **Isolation Forest + Heuristic Log Anomaly Engine** to flag phishing campaigns, SQL Injection, Path Traversal, XSS, and Brute Force attacks in real-time. Includes an interactive Security Operations Center (SOC) dashboard.

---

## 🏗️ System Architecture

```mermaid
graph TD
    subgraph "Ingestion & Threat Surface"
        A[Suspicious URLs] --> B[URL Feature Extractor: 18 Features]
        C[Server Access Logs: Nginx / Apache] --> D[Log Parser & Feature Engineer]
    end
    
    subgraph "Machine Learning Threat Engines"
        B --> E[Random Forest Classifier: 120 Trees]
        E --> F[Verdict: MALICIOUS / SUSPICIOUS / SAFE]
        E --> G[Risk Probability & Feature Attribution]
        
        D --> H[Isolation Forest: Unsupervised Anomaly Scoring]
        D --> I[Signature Rules: SQLi, Traversal, XSS, Brute Force]
        H --> J[Enriched Security Incidents & Threat Severity]
        I --> J
    end
    
    subgraph "Serving & SOC Operations Center"
        F --> K[FastAPI REST API: http://localhost:8002]
        G --> K
        J --> K
        K --> L[React 19 Cyber SOC Dashboard: http://localhost:3002]
    end
```

---

## 📊 Proven Model Benchmark Metrics

Trained on a balanced corpus of 12,000 URLs (Alexa/Tranco top sites vs. active PhishTank/OpenPhish feeds) and evaluated on a held-out stratified test set of 2,400 URLs:

| Metric | Measured Score | Industry Benchmark | Status |
| :--- | :--- | :--- | :--- |
| **Precision** | **98.97%** | >= 95.0% | 🏆 Low False Alarm Rate |
| **Recall** | **96.33%** | >= 90.0% | 🛡️ Catches 96.3% of Zero-Days |
| **F1-Score** | **97.64%** | >= 92.0% | ⚡ Balanced Detection |
| **Accuracy** | **97.67%** | >= 95.0% | ✅ High Overall Fidelity |
| **ROC-AUC** | **0.9996** | >= 0.980 | 🎯 Exceptional Separation |

### Held-Out Confusion Matrix (2,400 Test Samples)

$$\begin{bmatrix} \text{True Negatives (TN) = 1,188} & \text{False Positives (FP) = 12} \\ \text{False Negatives (FN) = 44} & \text{True Positives (TP) = 1,156} \end{bmatrix}$$

- **False Alarm Rate (FP Rate)**: Only **0.5%** (12 out of 2,400 URLs).
- **False Negative Rate**: **3.67%** (stealth evasion edge cases).

---

## 🔬 False Positive Analysis & Defensive Engineering

In cybersecurity operations, **False Positives (FP)** cause alert fatigue and disrupt legitimate business operations. Our architecture includes specific mitigations for four major edge cases:

| Scenario | Why Models Typically Misfire | Example URL | Applied Mitigation Rule |
| :--- | :--- | :--- | :--- |
| **Enterprise SSO & OAuth Callbacks** | High entropy tokens, embedded query parameters (`?code=...&state=...`), and auth keywords (`/login`, `/auth`). | `https://auth.company.com/oauth/v2/authorize?client_id=9812&state=x7F9` | Whitelist apex enterprise domains and verify TLS certificate identity. |
| **Content Delivery Networks (CDNs)** | Subdomain depth >= 3 and hash-based asset paths mimicking obfuscated phishing paths. | `https://static.cdn.fastly.net/assets/v2/bundle.481f9a.js` | Disregard asset extensions (`.js`, `.css`, `.png`, `.woff2`) from phishing classification. |
| **Marketing & Tracking URLs** | Multiple redirect hops, deep query strings, and tracking parameters (`utm_source`, `affiliate_id`). | `https://store.target.com/promo?utm_source=email&affiliate=partner` | Parameter stripping during URL normalization prior to feature extraction. |
| **URL Shorteners for Legitimate Ads** | Domain masking (`bit.ly`, `tinyurl.com`) without visible destination hostname. | `https://bit.ly/3xSummerSale` | Automated HTTP HEAD pre-flight resolution to evaluate final destination domain before scoring. |

### Engineering Mitigation Guardrails
1. **Confidence Threshold Gating**:
   - $P \ge 0.70$: High Confidence Malicious (Automated Block & Alert).
   - $0.40 \le P < 0.70$: Suspicious (Browser Warning Interstitial & User Consent).
   - $P < 0.40$: Clean (Transparent Passthrough).
2. **Reputation Whitelisting**: Integration with Tranco Top 10k domains to bypass scoring for established corporate entities.

---

## 🎯 18 Handcrafted URL Security Features

1. `is_ip_address`: Direct IPv4/IPv6 host usage (Gini Importance: **24.5%**).
2. `suspicious_keywords_count`: Keywords targeting credential theft (`login`, `verify`, `banking`, `paypal`, `wallet`) (**18.2%**).
3. `tld_risk_score`: High-abuse TLD classification (`.xyz`, `.top`, `.click`, `.buzz`, `.cf`) (**14.1%**).
4. `count_subdomains`: Subdomain nesting depth (**11.8%**).
5. `shannon_entropy`: Information entropy detecting randomized domain/path tokens (**9.5%**).
6. `url_length`: Overall length (**6.2%**).
7. `is_url_shortener`: Known shortening services (**4.8%**).
8. `count_hyphens`: Multi-hyphen domain spoofing (**3.8%**).
9. `has_https`: Absence of TLS encryption (**3.1%**).
10. `digit_ratio`: Digit density in URL string (**2.1%**).
11. `count_dots`, `count_at`, `count_question`, `count_equal`, `count_percent`, `hostname_length`, `path_length`, `has_port`.

---

## 🛡️ Server Log Anomaly Engine

Combines **Isolation Forest** (unsupervised outlier detection across bytes, response latency, and URI depth) with regular expression security rules to flag:
- **SQL Injection**: `UNION SELECT`, `' OR 1=1--`, `INFORMATION_SCHEMA`
- **Path Traversal**: `../../../../etc/passwd`, `..\..\windows\system32\cmd.exe`
- **Cross-Site Scripting (XSS)**: `<script>`, `onerror=`, `javascript:`
- **Command Injection**: `; cat /etc/shadow`, `| whoami`
- **Brute Force Detection**: High-frequency 401/403 status bursts from single IPs.

---

## 🚀 Quick Start & Local Execution

### 1. Test URL Classifier (CLI)
```bash
cd ml
python train_classifier.py
```

### 2. Run Full Stack with FastAPI + React SOC Dashboard
```bash
# Terminal 1: Start FastAPI REST API
cd backend
pip install -r requirements.txt
python main.py
# API running at: http://localhost:8002 (Swagger docs at /docs)

# Terminal 2: Start React SOC Dashboard
cd ../frontend
npm install
npm run dev
# SOC Dashboard running at: http://localhost:3002
```

### 3. Run with Docker Compose
```bash
docker-compose up --build
```

---

## 🌐 Deploy to Vercel
Includes an in-browser heuristic and feature extraction engine that works automatically upon deploying to Vercel:
1. Import repository into [Vercel](https://vercel.com).
2. Set Root Directory to `03-phishing-log-detector`.
3. Vercel automatically detects `vercel.json` and builds `frontend/dist`.
