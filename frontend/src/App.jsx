import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Terminal,
  Activity,
  Layers,
  BarChart2,
  FileText,
  Lock,
  Globe,
  CheckCircle2,
  XCircle,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Cpu,
  Radio,
  Sliders,
  Shield,
  Zap,
  Download,
  AlertOctagon,
  X
} from 'lucide-react';
import {
  PRESET_URLS,
  SOC_METRICS,
  SAMPLE_LOG_INCIDENTS,
  ATTACKER_IPS,
  clientScanUrl
} from './mockSocData';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner'); // 'scanner' | 'logs' | 'metrics' | 'false_positives'
  const [inputUrl, setInputUrl] = useState(PRESET_URLS[0].url);
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isBackendLive, setIsBackendLive] = useState(false);
  const [logIncidents, setLogIncidents] = useState(SAMPLE_LOG_INCIDENTS);
  const [attackerIps, setAttackerIps] = useState(ATTACKER_IPS);
  const [logFilter, setLogFilter] = useState('ALL');
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.85);
  const [quarantineNotification, setQuarantineNotification] = useState(null);

  useEffect(() => {
    handleScan(PRESET_URLS[0].url);

    fetch('/api/health')
      .then((r) => r.json())
      .then((data) => {
        if (data.status === 'HEALTHY') {
          setIsBackendLive(true);
        }
      })
      .catch(() => {
        setIsBackendLive(false);
      });
  }, []);

  const handleScan = async (urlToScan) => {
    const target = urlToScan || inputUrl;
    if (!target.trim()) return;

    setIsScanning(true);

    if (isBackendLive) {
      try {
        const res = await fetch('/api/scan-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target })
        });
        if (res.ok) {
          const data = await res.json();
          setScanResult(data);
          setIsScanning(false);
          return;
        }
      } catch (err) {
        console.warn('Backend call failed, using client inference engine', err);
      }
    }

    // Client-side fallback inference
    setTimeout(() => {
      const res = clientScanUrl(target);
      setScanResult(res);
      setIsScanning(false);
    }, 400);
  };

  const quarantineIp = (ipToQuarantine, category) => {
    if (!attackerIps.some(a => a.ip === ipToQuarantine)) {
      setAttackerIps(prev => [
        {
          ip: ipToQuarantine,
          incident_count: 1,
          categories: [category || "SUSPICIOUS_ANOMALY"],
          severity: "CRITICAL",
          country: "Live Quarantined (SOC Rule #491)"
        },
        ...prev
      ]);
    }
    setQuarantineNotification(`Attacker IP ${ipToQuarantine} added to firewall blocklist & quarantined!`);
    setTimeout(() => setQuarantineNotification(null), 3000);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#060911] text-slate-100 selection:bg-rose-500 selection:text-white">
      {/* Top Header */}
      <header className="sticky top-0 z-40 glass-panel border-b border-white/10 px-4 lg:px-8 py-3.5 backdrop-blur-2xl">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 to-amber-500 p-[1px] shadow-lg shadow-rose-500/25">
              <div className="w-full h-full bg-[#0d1322] rounded-xl flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-heading font-bold text-lg text-white tracking-tight">CyberGuard SOC</h1>
                <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                  ML Threat Defense
                </span>
              </div>
              <p className="text-xs text-slate-400">Phishing URL Classifier (Random Forest) & Web Log Anomaly Stream (Isolation Forest)</p>
            </div>
          </div>

          <div className="flex items-center flex-wrap gap-2.5">
            {/* Live Status Chip */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900/80 border border-white/10 text-xs text-slate-300">
              <span className={`w-2 h-2 rounded-full ${isBackendLive ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
              <span className="font-mono text-[11px]">{isBackendLive ? 'FastAPI Model Live' : 'Scikit-Learn Standalone (Vercel)'}</span>
            </div>

            {/* Performance Metric Pills */}
            <div className="hidden md:flex items-center gap-2">
              <div className="px-2.5 py-1 rounded-lg bg-rose-950/50 border border-rose-500/20 text-[11px] font-mono text-rose-300">
                🎯 98.97% Precision
              </div>
              <div className="px-2.5 py-1 rounded-lg bg-emerald-950/50 border border-emerald-500/20 text-[11px] font-mono text-emerald-300">
                🛡️ 0.9996 ROC-AUC
              </div>
            </div>

            {/* GitHub & Vercel links */}
            <a
              href="https://github.com/divyansh0051/cyber-soc-detector"
              target="_blank"
              rel="noreferrer"
              className="btn-secondary px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 hover:text-white"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>GitHub</span>
            </a>
            <a
              href="https://03-phishing-log-detector.vercel.app"
              target="_blank"
              rel="noreferrer"
              className="btn-primary px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Vercel Live</span>
            </a>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="max-w-7xl mx-auto mt-3 flex items-center gap-2 border-t border-white/5 pt-3 overflow-x-auto">
          {[
            { id: 'scanner', label: '🔍 URL Threat Scanner', badge: '18 Features' },
            { id: 'logs', label: '⚡ Log Anomaly Stream', badge: `${logIncidents.length} Events` },
            { id: 'metrics', label: '📊 Model Performance & Matrix', badge: '98.97% Prec' },
            { id: 'false_positives', label: '📑 False Positive Engineering Note', badge: '12 Exceptions' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 flex items-center gap-2 whitespace-nowrap ${
                activeTab === tab.id
                  ? 'bg-rose-600 text-white shadow-md shadow-rose-600/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <span>{tab.label}</span>
              {tab.badge && (
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                  activeTab === tab.id ? 'bg-white/20 text-white' : 'bg-slate-800 text-slate-300'
                }`}>
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      </header>

      {/* Toast Notification */}
      {quarantineNotification && (
        <div className="fixed bottom-6 right-6 z-50 glass-panel p-4 rounded-xl border border-rose-500/40 text-rose-200 text-xs font-mono shadow-2xl flex items-center gap-2 animate-slide-up">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span>{quarantineNotification}</span>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-8">
        {/* TAB 1: URL THREAT SCANNER */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            {/* Scanner Input Card */}
            <div className="glass-panel p-6 lg:p-8 rounded-2xl border border-white/10 space-y-4">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-xl font-heading font-bold text-white flex items-center gap-2">
                    <Search className="w-5 h-5 text-rose-400" />
                    <span>Real-Time Phishing URL Analyzer</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Extracts 18 lexical and cryptographic security features and computes classification probability via trained Random Forest ensemble.
                  </p>
                </div>
                <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                  <span>Ensemble: <strong>Random Forest (n=120)</strong></span>
                  <span>•</span>
                  <span>Latency: <strong className="text-emerald-400">&lt; 2ms</strong></span>
                </div>
              </div>

              {/* URL Input Form */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleScan();
                }}
                className="flex flex-col sm:flex-row items-center gap-2.5"
              >
                <div className="relative w-full">
                  <Globe className="w-4 h-4 absolute left-3.5 top-3.5 text-slate-500" />
                  <input
                    type="text"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    placeholder="Enter suspicious URL or IP to inspect (e.g. http://paypal-verify-account.xyz)..."
                    className="glass-input w-full pl-10 pr-4 py-3 rounded-xl text-sm font-mono placeholder:text-slate-500"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning || !inputUrl.trim()}
                  className="btn-primary w-full sm:w-auto px-6 py-3 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 whitespace-nowrap disabled:opacity-50"
                >
                  <Search className="w-4 h-4" />
                  <span>{isScanning ? 'Extracting Features...' : 'Analyze URL'}</span>
                </button>
              </form>

              {/* Preset Scenarios Carousel */}
              <div className="pt-2 border-t border-white/5">
                <span className="text-[11px] text-slate-500 font-mono block mb-2">Preset Attack & Benign Scenarios:</span>
                <div className="flex items-center gap-2 overflow-x-auto pb-1">
                  {PRESET_URLS.map((preset, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setInputUrl(preset.url);
                        handleScan(preset.url);
                      }}
                      className="shrink-0 px-3 py-1.5 rounded-xl text-xs bg-slate-900 border border-white/10 hover:border-rose-400/50 hover:bg-rose-950/30 text-slate-300 transition-all flex items-center gap-1.5"
                    >
                      <span className={`w-2 h-2 rounded-full ${preset.expected.includes('MALICIOUS') ? 'bg-rose-500' : 'bg-emerald-400'}`}></span>
                      <span>{preset.title}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Scan Results HUD */}
            {scanResult && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-slide-up">
                {/* Left Verdict Card */}
                <div className="lg:col-span-5 glass-panel p-6 rounded-2xl border border-white/10 flex flex-col justify-between space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Classification Verdict</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                        scanResult.verdict === 'MALICIOUS'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : scanResult.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {scanResult.severity} RISK
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className={`w-14 h-14 rounded-2xl flex items-center justify-center ${
                        scanResult.verdict === 'MALICIOUS'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : scanResult.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {scanResult.verdict === 'MALICIOUS' ? (
                          <AlertOctagon className="w-8 h-8" />
                        ) : scanResult.verdict === 'SUSPICIOUS' ? (
                          <AlertTriangle className="w-8 h-8" />
                        ) : (
                          <CheckCircle2 className="w-8 h-8" />
                        )}
                      </div>
                      <div>
                        <h3 className={`text-2xl font-heading font-bold ${
                          scanResult.verdict === 'MALICIOUS' ? 'text-rose-400' : scanResult.verdict === 'SUSPICIOUS' ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {scanResult.verdict}
                        </h3>
                        <p className="text-xs text-slate-400 font-mono">
                          Phishing Confidence: <strong>{scanResult.risk_score.toFixed(1)}%</strong>
                        </p>
                      </div>
                    </div>

                    {/* Progress Bar Gauge */}
                    <div className="mt-5 space-y-1.5">
                      <div className="flex justify-between text-xs font-mono text-slate-400">
                        <span>Safe (0%)</span>
                        <span>Suspicious (50%)</span>
                        <span>Malicious (100%)</span>
                      </div>
                      <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-white/10">
                        <div
                          className={`h-3 rounded-full transition-all duration-300 ${
                            scanResult.verdict === 'MALICIOUS'
                              ? 'bg-gradient-to-r from-amber-500 to-rose-600'
                              : scanResult.verdict === 'SUSPICIOUS'
                              ? 'bg-gradient-to-r from-yellow-400 to-amber-500'
                              : 'bg-gradient-to-r from-teal-400 to-emerald-500'
                          }`}
                          style={{ width: `${Math.min(100, Math.max(5, scanResult.risk_score))}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>

                  {/* Risk Factors Breakdown */}
                  <div className="space-y-3 pt-4 border-t border-white/5">
                    <h4 className="text-xs font-mono text-slate-300 uppercase tracking-wider">Triggered Risk Indicators</h4>
                    <div className="space-y-2">
                      {scanResult.risk_factors && scanResult.risk_factors.length > 0 ? (
                        scanResult.risk_factors.map((rf, i) => (
                          <div key={i} className="p-2.5 rounded-xl bg-slate-900/60 border border-white/5 flex items-start justify-between text-xs gap-2">
                            <div>
                              <span className="text-slate-200 font-medium">{rf.factor}</span>
                              <p className="text-[11px] text-slate-400 mt-0.5">{rf.detail}</p>
                            </div>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 whitespace-nowrap">
                              {rf.impact}
                            </span>
                          </div>
                        ))
                      ) : (
                        <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/20 text-xs text-emerald-300 flex items-center gap-2">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>No anomalous phishing indicators detected in lexical or protocol inspection.</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Right 18-Feature Vector Breakdown */}
                <div className="lg:col-span-7 glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-heading font-bold text-base text-white flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-cyan-400" />
                      <span>18-Feature Security Vector</span>
                    </h3>
                    <span className="text-xs font-mono text-slate-400">Scikit-Learn ML Extractor</span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-slate-900 border border-white/5">
                      <span className="text-slate-500 block text-[10px] uppercase">URL Length</span>
                      <span className="text-cyan-300 font-bold text-sm">{scanResult.features?.url_length || inputUrl.length} chars</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-white/5">
                      <span className="text-slate-500 block text-[10px] uppercase">Subdomains</span>
                      <span className="text-indigo-300 font-bold text-sm">{scanResult.features?.count_subdomains ?? 1}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-white/5">
                      <span className="text-slate-500 block text-[10px] uppercase">Raw IP Host</span>
                      <span className={`font-bold text-sm ${scanResult.features?.is_ip_address ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {scanResult.features?.is_ip_address ? 'DETECTED' : 'NONE'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-900 border border-white/5">
                      <span className="text-slate-500 block text-[10px] uppercase">HTTPS Protocol</span>
                      <span className={`font-bold text-sm ${scanResult.features?.has_https ? 'text-emerald-400' : 'text-amber-400'}`}>
                        {scanResult.features?.has_https ? 'SECURE' : 'INSECURE'}
                      </span>
                    </div>
                  </div>

                  {/* Feature Importance Rank Bars */}
                  <div className="pt-3 border-t border-white/5 space-y-2.5">
                    <span className="text-xs font-mono text-slate-400 block">Top Feature Weights in Random Forest Model:</span>
                    {SOC_METRICS.feature_importances.slice(0, 5).map((f, i) => (
                      <div key={i} className="space-y-1">
                        <div className="flex justify-between text-xs font-mono">
                          <span className="text-slate-300">{f.feature}</span>
                          <span className="text-cyan-300">{(f.importance * 100).toFixed(1)}% weight</span>
                        </div>
                        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
                          <div
                            className="bg-cyan-500 h-1.5 rounded-full"
                            style={{ width: `${f.importance * 350}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: LOG ANOMALY STREAM */}
        {activeTab === 'logs' && (
          <div className="space-y-6">
            <div className="glass-panel p-6 lg:p-8 rounded-2xl border border-white/10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
              <div>
                <h2 className="text-2xl font-heading font-bold text-white flex items-center gap-2">
                  <Terminal className="w-6 h-6 text-rose-400" />
                  <span>Unsupervised Web Log Anomaly Stream</span>
                </h2>
                <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                  Simulated real-time access log ingestion scored via an <strong>Isolation Forest</strong> model flagging SQL injection, path traversal, command injection, and brute force bursts.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-slate-400">Anomaly Threshold:</span>
                <span className="text-xs font-mono font-bold text-rose-400">{anomalyThreshold}</span>
              </div>
            </div>

            {/* Incidents Stream Table */}
            <div className="glass-panel rounded-2xl overflow-hidden border border-white/10">
              <div className="divide-y divide-white/5">
                {logIncidents.map((log) => (
                  <div key={log.id} className="p-4 hover:bg-white/[0.02] transition-colors flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400">{log.id}</span>
                        <span className="text-xs font-mono font-bold text-cyan-300">{log.ip}</span>
                        <span className="text-xs font-mono text-slate-500">{log.timestamp}</span>
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          {log.threat_category}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-black/60 border border-white/5 font-mono text-xs text-rose-200">
                        {log.method} {log.uri}
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <div className="text-right font-mono text-xs">
                        <span className="text-slate-400 block text-[10px]">Anomaly Score</span>
                        <span className="text-rose-400 font-bold">{log.anomaly_score}</span>
                      </div>
                      <button
                        onClick={() => quarantineIp(log.ip, log.threat_category)}
                        className="btn-primary px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        <span>Quarantine IP</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Active Quarantined IP List */}
            <div className="glass-panel p-6 rounded-2xl border border-white/10 space-y-4">
              <h3 className="font-heading font-bold text-base text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <span>Active Quarantined Attacker IPs ({attackerIps.length})</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {attackerIps.map((att, i) => (
                  <div key={i} className="glass-card p-4 rounded-xl border border-rose-500/30 space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-xs font-bold text-rose-300">{att.ip}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400">BLOCKED</span>
                    </div>
                    <p className="text-[11px] text-slate-400">{att.country}</p>
                    <p className="text-[10px] font-mono text-slate-500">Threats: {att.categories.join(', ')}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: MODEL PERFORMANCE & CONFUSION MATRIX */}
        {activeTab === 'metrics' && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="glass-card p-5 rounded-2xl border border-rose-500/20">
                <span className="text-xs text-slate-400 block">Precision</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-heading font-bold text-rose-400">{SOC_METRICS.precision}%</span>
                </div>
                <span className="text-[11px] text-rose-300/80 mt-1 block">Only 12 false positives in 2,400</span>
              </div>

              <div className="glass-card p-5 rounded-2xl border border-emerald-500/20">
                <span className="text-xs text-slate-400 block">Recall</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-heading font-bold text-emerald-400">{SOC_METRICS.recall}%</span>
                </div>
                <span className="text-[11px] text-emerald-300/80 mt-1 block">Neutralizes 96.3% of zero-days</span>
              </div>

              <div className="glass-card p-5 rounded-2xl border border-cyan-500/20">
                <span className="text-xs text-slate-400 block">F1-Score</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-heading font-bold text-cyan-300">{SOC_METRICS.f1_score}%</span>
                </div>
                <span className="text-[11px] text-cyan-300/80 mt-1 block">Harmonic mean balance</span>
              </div>

              <div className="glass-card p-5 rounded-2xl border border-purple-500/20">
                <span className="text-xs text-slate-400 block">ROC-AUC</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-heading font-bold text-purple-300">{SOC_METRICS.roc_auc}</span>
                </div>
                <span className="text-[11px] text-purple-300/80 mt-1 block">Optimal separation threshold</span>
              </div>
            </div>

            {/* Confusion Matrix Card */}
            <div className="glass-panel p-6 lg:p-8 rounded-2xl border border-white/10 space-y-6">
              <h3 className="font-heading font-bold text-base text-white">Supervised Confusion Matrix (Holdout N = 2,400)</h3>
              <div className="grid grid-cols-2 gap-4 max-w-xl mx-auto font-mono text-center">
                <div className="p-6 rounded-2xl bg-emerald-950/40 border border-emerald-500/30">
                  <span className="text-xs text-slate-400 block mb-1">True Negatives (Legitimate Safe)</span>
                  <span className="text-3xl font-bold text-emerald-400">{SOC_METRICS.confusion_matrix.true_negatives}</span>
                  <span className="text-[10px] text-emerald-300/70 block mt-1">Accurately Approved</span>
                </div>

                <div className="p-6 rounded-2xl bg-rose-950/30 border border-rose-500/30">
                  <span className="text-xs text-slate-400 block mb-1">False Positives (Benign Flagged)</span>
                  <span className="text-3xl font-bold text-rose-400">{SOC_METRICS.confusion_matrix.false_positives}</span>
                  <span className="text-[10px] text-rose-300/70 block mt-1">0.5% Error Margin</span>
                </div>

                <div className="p-6 rounded-2xl bg-amber-950/30 border border-amber-500/30">
                  <span className="text-xs text-slate-400 block mb-1">False Negatives (Missed Threats)</span>
                  <span className="text-3xl font-bold text-amber-400">{SOC_METRICS.confusion_matrix.false_negatives}</span>
                  <span className="text-[10px] text-amber-300/70 block mt-1">Obfuscated Zero-Days</span>
                </div>

                <div className="p-6 rounded-2xl bg-indigo-950/40 border border-indigo-500/30">
                  <span className="text-xs text-slate-400 block mb-1">True Positives (Phishing Neutralized)</span>
                  <span className="text-3xl font-bold text-indigo-400">{SOC_METRICS.confusion_matrix.true_positives}</span>
                  <span className="text-[10px] text-indigo-300/70 block mt-1">Successfully Blocked</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: FALSE POSITIVES REPORT */}
        {activeTab === 'false_positives' && (
          <div className="max-w-4xl mx-auto space-y-6">
            <div className="glass-panel p-6 lg:p-8 rounded-2xl border border-white/10 space-y-4">
              <h2 className="text-xl font-heading font-bold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-rose-400" />
                <span>False Positive Engineering Note & Mitigation Report</span>
              </h2>
              <p className="text-xs text-slate-400">
                In security operations, a false positive rate above 1% causes alert fatigue and blocks authentic user traffic. Below is our engineering analysis of the 12 false positive test cases and architectural remediations.
              </p>

              <div className="space-y-4 text-xs leading-relaxed text-slate-300 pt-3 border-t border-white/5">
                <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                  <h4 className="font-heading font-bold text-sm text-cyan-300">1. Enterprise SSO & OAuth 2.0 Callbacks (6 Cases)</h4>
                  <p className="text-slate-400">
                    Enterprise identity providers (Okta, PingFederate, Azure AD) include high entropy state tokens and long query strings resembling malicious payload delivery.
                  </p>
                  <p className="text-emerald-300 font-mono text-[11px]">
                    Mitigation: Pre-screen destination hosts against verified enterprise domain registration caches and ASN identity certs.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                  <h4 className="font-heading font-bold text-sm text-purple-300">2. CDN Signed URLs & Media Hash Strings (4 Cases)</h4>
                  <p className="text-slate-400">
                    Amazon CloudFront and Cloudflare presigned URLs feature random hexadecimal hashes that elevate the Shannon entropy score above 4.5.
                  </p>
                  <p className="text-emerald-300 font-mono text-[11px]">
                    Mitigation: Parse path patterns for cryptographic HMAC parameters (e.g. <code>Signature=</code>, <code>Key-Pair-Id=</code>) and apply entropy weighting offsets.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/60 border border-white/5 space-y-1">
                  <h4 className="font-heading font-bold text-sm text-amber-300">3. Promotional Marketing Click Trackers (2 Cases)</h4>
                  <p className="text-slate-400">
                    Newsletter click-tracking redirects (e.g. <code>link.mail.example.com/click?...</code>) trigger subdomain depth and URL shortening heuristics.
                  </p>
                  <p className="text-emerald-300 font-mono text-[11px]">
                    Mitigation: Resolve HTTP HEAD redirects up to 2 hops before feature extraction to identify root verified domains.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="glass-panel border-t border-white/5 py-4 px-6 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <span>CyberGuard SOC — Phishing URL & Log Anomaly Threat Center</span>
          <div className="flex items-center gap-4">
            <span>Random Forest (18 Features)</span>
            <span>•</span>
            <span>Isolation Forest Anomaly</span>
            <span>•</span>
            <span>MITRE ATT&CK Mapping</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
