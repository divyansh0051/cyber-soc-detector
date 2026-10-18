import re
import datetime
import random
from typing import List, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest

# Regular Expression Signatures for Web Attack Vectors
SECURITY_SIGNATURES = {
    "SQL_INJECTION": [
        re.compile(r"(\bUNION\b.*\bSELECT\b)", re.IGNORECASE),
        re.compile(r"(\bOR\b\s+['\d\w]+\s*=\s*['\d\w]+)", re.IGNORECASE),
        re.compile(r"(--|#|/\*|;\s*DROP\s+TABLE)", re.IGNORECASE),
        re.compile(r"(\bINFORMATION_SCHEMA\b)", re.IGNORECASE),
        re.compile(r"(\bSLEEP\(\d+\)|\bBENCHMARK\(\d+)", re.IGNORECASE)
    ],
    "PATH_TRAVERSAL": [
        re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
        re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|boot\.ini)", re.IGNORECASE),
        re.compile(r"(windows[\\/]system32)", re.IGNORECASE)
    ],
    "CROSS_SITE_SCRIPTING": [
        re.compile(r"(<script.*?>.*?</script>)", re.IGNORECASE),
        re.compile(r"(javascript\s*:)", re.IGNORECASE),
        re.compile(r"(onload\s*=|onerror\s*=|onclick\s*=)", re.IGNORECASE),
        re.compile(r"(<svg.*?>|<iframe.*?>)", re.IGNORECASE)
    ],
    "COMMAND_INJECTION": [
        re.compile(r"(;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b)", re.IGNORECASE),
        re.compile(r"(\|\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh)\b)", re.IGNORECASE),
        re.compile(r"(`.*?`)", re.IGNORECASE)
    ]
}

# Common Log Format (Nginx / Apache): IP - - [Timestamp] "METHOD /path HTTP/1.1" STATUS BYTES "REFERER" "USER_AGENT" LATENCY_MS
LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\s+(?P<bytes>\d+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"(?:\s+(?P<latency_ms>\d+))?'
)

class ServerLogAnomalyDetector:
    def __init__(self):
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42
        )
        self.is_fitted = False

    def parse_log_line(self, line: str) -> Dict[str, Any]:
        match = LOG_REGEX.match(line.strip())
        if match:
            d = match.groupdict()
            return {
                "ip": d["ip"],
                "timestamp": d["timestamp"],
                "method": d["method"],
                "uri": d["uri"],
                "status": int(d["status"]),
                "bytes": int(d["bytes"]),
                "referrer": d["referrer"],
                "user_agent": d["user_agent"],
                "latency_ms": int(d["latency_ms"]) if d.get("latency_ms") else random.randint(15, 250),
                "raw_line": line.strip()
            }
        # Fallback loose parser
        parts = line.strip().split()
        return {
            "ip": parts[0] if parts else "127.0.0.1",
            "timestamp": datetime.datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "method": "GET",
            "uri": line,
            "status": 200,
            "bytes": 512,
            "referrer": "-",
            "user_agent": "Mozilla/5.0",
            "latency_ms": 45,
            "raw_line": line.strip()
        }

    def detect_signature_threats(self, uri: str) -> List[str]:
        threats = []
        for threat_type, sig_list in SECURITY_SIGNATURES.items():
            for sig in sig_list:
                if sig.search(uri):
                    threats.append(threat_type)
                    break
        return threats

    def fit_and_score(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs both signature rules and Isolation Forest numerical anomaly scoring.
        """
        # Feature extraction for Isolation Forest: [bytes, latency_ms, uri_len, special_chars_count, is_error_status]
        feature_matrix = []
        for log in logs:
            uri = log["uri"]
            specials = sum(1 for c in uri if c in "'\"<>;|&%#*?=\\/")
            is_error = 1 if log["status"] >= 400 else 0
            feature_matrix.append([
                log["bytes"],
                log["latency_ms"],
                len(uri),
                specials,
                is_error
            ])

        X = np.array(feature_matrix)
        # Isolation Forest scoring
        self.iso_forest.fit(X)
        self.is_fitted = True
        scores = self.iso_forest.decision_function(X) # lower score = more anomalous

        # Normalize score into Anomaly Risk Probability (0.0 to 1.0)
        # Decision function is typically between -0.5 and +0.5
        min_s, max_s = scores.min(), scores.max()
        if max_s > min_s:
            norm_risks = 1.0 - ((scores - min_s) / (max_s - min_s))
        else:
            norm_risks = np.zeros(len(scores))

        enriched_logs = []
        for i, log in enumerate(logs):
            sig_threats = self.detect_signature_threats(log["uri"])
            anomaly_risk = round(float(norm_risks[i]), 3)

            # Assign Severity & Threat Category
            if sig_threats:
                severity = "CRITICAL" if any(t in ["SQL_INJECTION", "COMMAND_INJECTION"] for t in sig_threats) else "HIGH"
                verdict = "MALICIOUS"
                category = ", ".join(sig_threats)
            elif log["status"] in [401, 403] and anomaly_risk > 0.70:
                severity = "HIGH"
                verdict = "SUSPICIOUS"
                category = "BRUTE_FORCE_BURST"
            elif anomaly_risk > 0.85:
                severity = "MEDIUM"
                verdict = "SUSPICIOUS"
                category = "UNSUPERVISED_OUTLIER"
            else:
                severity = "LOW"
                verdict = "BENIGN"
                category = "NORMAL_TRAFFIC"

            enriched_logs.append({
                **log,
                "anomaly_score": anomaly_risk,
                "verdict": verdict,
                "severity": severity,
                "threat_category": category,
                "detected_signatures": sig_threats
            })

        return enriched_logs

def generate_sample_access_logs(num_lines: int = 150) -> List[str]:
    """Generates authentic Apache/Nginx web server access logs with embedded attacks."""
    random.seed(42)
    benign_ips = ["192.168.1.45", "10.0.0.12", "172.16.4.88", "198.51.100.14", "203.0.113.19"]
    attacker_ips = ["185.220.101.5", "45.154.255.89", "194.26.29.112"]

    benign_uris = [
        "/api/v1/user/profile", "/dashboard/overview", "/assets/css/theme.css",
        "/static/images/logo.png", "/api/v1/products/list?page=1&limit=20",
        "/checkout/cart", "/docs/api-reference", "/favicon.ico",
        "/api/v1/auth/refresh", "/search?q=enterprise+cloud"
    ]

    attack_uris = [
        "/api/v1/users?id=10+UNION+SELECT+1,username,password+FROM+accounts--",
        "/download?file=../../../../etc/passwd",
        "/search?q=<script>alert('xss-session-steal')</script>",
        "/cgi-bin/test-cgi?cmd=;+cat+/etc/shadow",
        "/api/v1/auth/login", # Brute force burst
        "/admin/config.php?load=..\\..\\windows\\system32\\cmd.exe",
        "/products/query?cat=electronics'+OR+1=1--"
    ]

    logs = []
    base_time = datetime.datetime.utcnow() - datetime.timedelta(hours=2)

    for i in range(num_lines):
        time_offset = base_time + datetime.timedelta(seconds=i * 24)
        ts = time_offset.strftime("%d/%b/%Y:%H:%M:%S +0000")

        # 12% probability of attack
        if random.random() < 0.12:
            ip = random.choice(attacker_ips)
            uri = random.choice(attack_uris)
            status = random.choice([401, 403, 500, 200])
            bytes_sent = random.randint(240, 1800)
            latency = random.randint(350, 1400)
            method = "POST" if "login" in uri else "GET"
        else:
            ip = random.choice(benign_ips)
            uri = random.choice(benign_uris)
            status = random.choice([200, 200, 200, 201, 304])
            bytes_sent = random.randint(800, 15000)
            latency = random.randint(18, 120)
            method = "GET"

        line = f'{ip} - - [{ts}] "{method} {uri} HTTP/1.1" {status} {bytes_sent} "https://company.internal/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" {latency}'
        logs.append(line)

    return logs

if __name__ == "__main__":
    detector = ServerLogAnomalyDetector()
    raw_logs = generate_sample_access_logs(50)
    parsed = [detector.parse_log_line(l) for l in raw_logs]
    scored = detector.fit_and_score(parsed)
    threats = [s for s in scored if s["verdict"] != "BENIGN"]
    print(f"[OK] Analyzed {len(scored)} server log entries.")
    print(f"[!] Flagged {len(threats)} security anomalies & signature violations.")
    for t in threats[:5]:
        print(f"    [{t['severity']}] {t['threat_category']} from {t['ip']} -> {t['uri'][:65]}")
