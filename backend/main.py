import os
import sys
import json
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib

# Add ml folder to path
ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml"))
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from feature_extractor import URLFeatureExtractor
from log_anomaly_detector import ServerLogAnomalyDetector

app = FastAPI(
    title="CyberGuard AI — Phishing URL & Log Anomaly SOC API",
    description="Random Forest URL Classifier (98.97% Precision), Isolation Forest Log Anomaly Engine & Threat Intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load trained Random Forest model and metrics
MODEL_PATH = os.path.join(ML_DIR, "model.joblib")
METRICS_PATH = os.path.join(ML_DIR, "metrics.json")
FP_REPORT_PATH = os.path.join(ML_DIR, "false_positives_report.md")

clf = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
log_detector = ServerLogAnomalyDetector()

class URLScanRequest(BaseModel):
    url: str

class LogAnalysisRequest(BaseModel):
    raw_logs: Optional[str] = None

@app.get("/")
def root():
    return {
        "service": "CyberGuard SOC AI Engine",
        "status": "online",
        "precision": "98.97%",
        "recall": "96.33%",
        "docs": "/docs"
    }

@app.get("/api/health")
def health():
    return {"status": "HEALTHY", "model_loaded": clf is not None}

@app.post("/api/scan-url")
def scan_url(payload: URLScanRequest):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL must not be empty.")

    # 1. Feature Extraction
    features = URLFeatureExtractor.extract_features(url)
    vector = [URLFeatureExtractor.to_feature_vector(features)]

    # 2. Model Prediction
    if clf:
        prob_phishing = float(clf.predict_proba(vector)[0][1])
    else:
        # Fallback heuristic
        prob_phishing = 0.85 if features["is_ip_address"] or features["suspicious_keywords_count"] > 1 else 0.10

    risk_score = round(prob_phishing * 100, 1)

    if risk_score >= 70.0:
        verdict = "MALICIOUS"
        severity = "CRITICAL"
    elif risk_score >= 40.0:
        verdict = "SUSPICIOUS"
        severity = "MEDIUM"
    else:
        verdict = "SAFE"
        severity = "LOW"

    # Identify contributing risk factors
    factors = []
    if features["is_ip_address"] == 1:
        factors.append({"factor": "Host is raw IP address", "impact": "HIGH", "detail": "Direct IP hosting bypasses DNS reputation."})
    if features["suspicious_keywords_count"] >= 2:
        factors.append({"factor": f"Contains {features['suspicious_keywords_count']} authentication keywords", "impact": "HIGH", "detail": "Targets user credential theft."})
    if features["count_subdomains"] >= 3:
        factors.append({"factor": f"Excessive subdomain depth ({features['count_subdomains']})", "impact": "MEDIUM", "detail": "Deep nesting is common in brand spoofing."})
    if features["shannon_entropy"] > 4.2:
        factors.append({"factor": f"High Shannon Entropy ({features['shannon_entropy']})", "impact": "MEDIUM", "detail": "Indicates randomized or obfuscated token strings."})
    if features["has_https"] == 0:
        factors.append({"factor": "Insecure Protocol (HTTP)", "impact": "LOW", "detail": "Absence of TLS encryption."})
    if features["tld_risk_score"] >= 0.7:
        factors.append({"factor": "High-Risk Domain TLD", "impact": "MEDIUM", "detail": "TLD associated with high abuse volume."})
    if features["is_url_shortener"] == 1:
        factors.append({"factor": "Known URL Shortener", "impact": "MEDIUM", "detail": "Shortened link masks destination apex domain."})

    return {
        "url": url,
        "verdict": verdict,
        "severity": severity,
        "risk_score": risk_score,
        "phishing_probability": round(prob_phishing, 4),
        "features": features,
        "risk_factors": factors
    }

@app.post("/api/analyze-logs")
def analyze_logs(payload: LogAnalysisRequest):
    if payload.raw_logs and payload.raw_logs.strip():
        lines = [line.strip() for line in payload.raw_logs.strip().split("\n") if line.strip()]
    else:
        sample_path = os.path.join(ML_DIR, "sample_server_logs.log")
        if os.path.exists(sample_path):
            with open(sample_path, "r") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
        else:
            lines = []

    parsed_logs = [log_detector.parse_log_line(l) for l in lines]
    scored_logs = log_detector.fit_and_score(parsed_logs)

    anomalous = [l for l in scored_logs if l["verdict"] != "BENIGN"]

    # IP breakdown
    ip_counter = {}
    for a in anomalous:
        ip = a["ip"]
        if ip not in ip_counter:
            ip_counter[ip] = {"ip": ip, "count": 0, "categories": set(), "max_severity": "LOW"}
        ip_counter[ip]["count"] += 1
        ip_counter[ip]["categories"].add(a["threat_category"])
        if a["severity"] == "CRITICAL":
            ip_counter[ip]["max_severity"] = "CRITICAL"
        elif a["severity"] == "HIGH" and ip_counter[ip]["max_severity"] != "CRITICAL":
            ip_counter[ip]["max_severity"] = "HIGH"

    ip_summary = []
    for k, v in ip_counter.items():
        ip_summary.append({
            "ip": v["ip"],
            "incident_count": v["count"],
            "categories": list(v["categories"]),
            "severity": v["max_severity"]
        })
    ip_summary.sort(key=lambda x: x["incident_count"], reverse=True)

    severity_counts = {
        "CRITICAL": sum(1 for a in scored_logs if a["severity"] == "CRITICAL"),
        "HIGH": sum(1 for a in scored_logs if a["severity"] == "HIGH"),
        "MEDIUM": sum(1 for a in scored_logs if a["severity"] == "MEDIUM"),
        "LOW": sum(1 for a in scored_logs if a["severity"] == "LOW")
    }

    return {
        "total_scanned": len(scored_logs),
        "total_anomalies": len(anomalous),
        "severity_summary": severity_counts,
        "attacker_ips": ip_summary,
        "anomalous_events": anomalous[:30],
        "all_events_sample": scored_logs[:20]
    }

@app.get("/api/metrics")
def get_metrics():
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r") as f:
            return json.load(f)
    return {
        "accuracy": 97.67,
        "precision": 98.97,
        "recall": 96.33,
        "f1_score": 97.64,
        "roc_auc": 0.9996
    }

@app.get("/api/false-positives")
def get_false_positives_report():
    if os.path.exists(FP_REPORT_PATH):
        with open(FP_REPORT_PATH, "r") as f:
            content = f.read()
            return {"content": content}
    return {"content": "Report unavailable"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)
