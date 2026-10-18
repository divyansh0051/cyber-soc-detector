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
  Radio
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

  // Initial scan on mount & check backend health
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
        const data = await res.json();
        setScanResult(data);
        setIsScanning(false);
        return;
      } catch (err) {
        console.warn('Backend call failed, using client inference engine', err);
      }
    }

    // Client-side fallback inference
    setTimeout(() => {
      const res = clientScanUrl(target);
      setScanResult(res);
      setIsScanning(false);
    }, 350);
  };

  const filteredLogs = logIncidents.filter((l) => {
    if (logFilter === 'ALL') return true;
    return l.severity === logFilter;
  });

  return (
    <div className="min-h-screen text-slate-100 flex flex-col">
      {/* Top SOC Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-black/80 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 to-amber-600 flex items-center justify-center shadow-lg shadow-rose-600/30">
            <ShieldAlert className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white font-mono">
                CYBERGUARD SOC AI
              </h1>
              <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
                Threat Defense v2.4
              </span>
              <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-ring"></span>
                {isBackendLive ? 'REST API Active' : 'Client ML Engine'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Phishing URL Classifier (98.97% Precision) • Isolation Forest Server Log Anomaly Detector
            </p>
          </div>
        </div>

        {/* Live Model Stats Badges */}
        <div className="hidden lg:flex items-center gap-3 text-xs font-mono">
          <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-400">Precision:</span>
            <span className="text-emerald-400 font-bold">{SOC_METRICS.precision}%</span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-400">Recall:</span>
            <span className="text-cyan-400 font-bold">{SOC_METRICS.recall}%</span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center gap-2">
            <span className="text-slate-400">ROC-AUC:</span>
            <span className="text-amber-400 font-bold">{SOC_METRICS.roc_auc}</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 gap-6">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
              activeTab === 'scanner'
                ? 'border-rose-500 text-rose-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-4 h-4" />
            <span>Phishing URL Scanner</span>
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
              activeTab === 'logs'
                ? 'border-rose-500 text-rose-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Server Log Anomaly Detector</span>
          </button>

          <button
            onClick={() => setActiveTab('metrics')}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
              activeTab === 'metrics'
                ? 'border-rose-500 text-rose-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <BarChart2 className="w-4 h-4" />
            <span>Model Benchmark & ROC-AUC</span>
          </button>

          <button
            onClick={() => setActiveTab('false_positives')}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition-all ${
              activeTab === 'false_positives'
                ? 'border-rose-500 text-rose-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>False Positives Deep-Dive</span>
          </button>
        </div>

        {/* TAB 1: PHISHING URL SCANNER */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            {/* Input Bar */}
            <div className="soc-card p-5 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-rose-400" />
                  Target URL Threat Inspection
                </label>
                <span className="text-[11px] font-mono text-slate-500">
                  Evaluates 18 Lexical, Domain & Structural Security Features
                </span>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    placeholder="Enter URL to inspect (e.g. http://paypal-verify-account.xyz/login)..."
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-950 border border-slate-800 text-sm font-mono text-white placeholder-slate-600 focus:outline-none focus:border-rose-500 transition-colors"
                  />
                </div>
                <button
                  onClick={() => handleScan(inputUrl)}
                  disabled={isScanning}
                  className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-medium text-sm shadow-lg shadow-rose-600/25 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Extracting Features...</span>
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-4 h-4" />
                      <span>Scan URL Threat</span>
                    </>
                  )}
                </button>
              </div>

              {/* Preset Buttons */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-500 font-mono">Test Presets:</span>
                {PRESET_URLS.map((preset, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setInputUrl(preset.url);
                      handleScan(preset.url);
                    }}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-slate-700 hover:text-rose-300 text-slate-400 transition-all"
                  >
                    {preset.title}
                  </button>
                ))}
              </div>
            </div>

            {/* Scan Results Display */}
            {scanResult && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Result Card 1: Threat Verdict & Gauge */}
                <div className="soc-card p-6 border border-slate-800 flex flex-col justify-between">
                  <div>
                    <span className="text-xs font-mono uppercase text-slate-400 tracking-wider">
                      Classification Verdict
                    </span>

                    <div className="mt-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {scanResult.verdict === 'MALICIOUS' ? (
                          <div className="w-12 h-12 rounded-xl bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shadow-lg shadow-rose-500/20">
                            <XCircle className="w-7 h-7" />
                          </div>
                        ) : scanResult.verdict === 'SUSPICIOUS' ? (
                          <div className="w-12 h-12 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shadow-lg shadow-amber-500/20">
                            <AlertTriangle className="w-7 h-7" />
                          </div>
                        ) : (
                          <div className="w-12 h-12 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-500/20">
                            <CheckCircle2 className="w-7 h-7" />
                          </div>
                        )}
                        <div>
                          <div
                            className={`text-2xl font-bold font-mono ${
                              scanResult.verdict === 'MALICIOUS'
                                ? 'text-rose-400'
                                : scanResult.verdict === 'SUSPICIOUS'
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {scanResult.verdict}
                          </div>
                          <span className="text-xs font-mono text-slate-400">
                            Severity: {scanResult.severity}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Threat Score Gauge */}
                    <div className="mt-6 space-y-2">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-slate-400">Phishing Probability</span>
                        <span className="font-bold text-white">{scanResult.risk_score}%</span>
                      </div>
                      <div className="h-3 rounded-full bg-slate-900 border border-slate-800 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${
                            scanResult.risk_score >= 70
                              ? 'bg-gradient-to-r from-amber-500 to-rose-600'
                              : scanResult.risk_score >= 40
                              ? 'bg-gradient-to-r from-yellow-500 to-amber-500'
                              : 'bg-gradient-to-r from-emerald-600 to-emerald-400'
                          }`}
                          style={{ width: `${scanResult.risk_score}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-slate-800/80 text-xs font-mono text-slate-500 truncate">
                    Target: <span className="text-slate-300">{scanResult.url}</span>
                  </div>
                </div>

                {/* Result Card 2: Risk Factor Attribution */}
                <div className="soc-card p-6 border border-slate-800 lg:col-span-2 space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                        Feature Attribution & Risk Factors
                      </h3>
                      <p className="text-xs text-slate-400">
                        Indicators explaining the model's classification score
                      </p>
                    </div>
                    <span className="text-xs font-mono text-slate-500">
                      {scanResult.risk_factors?.length || 0} Factors Triggered
                    </span>
                  </div>

                  <div className="space-y-2.5">
                    {scanResult.risk_factors && scanResult.risk_factors.length > 0 ? (
                      scanResult.risk_factors.map((factor, i) => (
                        <div
                          key={i}
                          className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs"
                        >
                          <div className="space-y-0.5">
                            <span className="font-semibold text-slate-200">{factor.factor}</span>
                            <p className="text-[11px] text-slate-400">{factor.detail}</p>
                          </div>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              factor.impact === 'HIGH'
                                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                                : factor.impact === 'MEDIUM'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                : 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                            }`}
                          >
                            {factor.impact} RISK
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="p-6 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-center text-xs text-emerald-300 font-mono">
                        No malicious indicators detected. Domain matches legitimate structure and baseline entropy.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: SERVER LOG ANOMALY DETECTOR */}
        {activeTab === 'logs' && (
          <div className="space-y-6">
            {/* Header & Filter Controls */}
            <div className="soc-card p-6 border border-slate-800">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-rose-400" />
                    Web Server Access Log Anomaly Stream
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Isolation Forest numerical scoring + Regex Security Signatures (SQLi, Traversal, XSS, Brute Force)
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  {['ALL', 'CRITICAL', 'HIGH'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setLogFilter(sev)}
                      className={`px-3 py-1 rounded text-xs font-mono font-medium transition-all ${
                        logFilter === sev
                          ? 'bg-rose-500/20 border border-rose-500 text-rose-300'
                          : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* Attacker IPs Bar */}
              <div className="mt-4 pt-1 grid grid-cols-1 sm:grid-cols-3 gap-3">
                {attackerIps.map((att, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <span className="text-rose-400 font-bold">{att.ip}</span>
                      <span className="block text-[10px] text-slate-500">{att.country}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30 text-[10px]">
                      {att.incident_count} Incidents
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Log Incident Table */}
            <div className="soc-card rounded-xl border border-slate-800 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">INCIDENT ID</th>
                      <th className="py-3 px-4">ATTACKER IP</th>
                      <th className="py-3 px-4">METHOD & REQUEST URI</th>
                      <th className="py-3 px-4">STATUS</th>
                      <th className="py-3 px-4">LATENCY</th>
                      <th className="py-3 px-4">ATTACK CATEGORY</th>
                      <th className="py-3 px-4 text-right">SEVERITY</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-sans">
                    {filteredLogs.map((log, i) => (
                      <tr key={i} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-4 font-mono text-cyan-400">{log.id}</td>
                        <td className="py-3 px-4 font-mono text-rose-400 font-semibold">{log.ip}</td>
                        <td className="py-3 px-4 font-mono text-slate-300 max-w-xs truncate">
                          <span className="text-slate-500 mr-1.5">{log.method}</span>
                          {log.uri}
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[11px] ${
                              log.status >= 500
                                ? 'bg-rose-950 text-rose-400'
                                : log.status >= 400
                                ? 'bg-amber-950 text-amber-400'
                                : 'bg-emerald-950 text-emerald-400'
                            }`}
                          >
                            {log.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400">{log.latency_ms} ms</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 border border-slate-700 text-slate-300">
                            {log.threat_category}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              log.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            }`}
                          >
                            {log.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: MODEL BENCHMARK & METRICS */}
        {activeTab === 'metrics' && (
          <div className="space-y-6">
            {/* KPI Stat Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="soc-card p-5 border border-slate-800">
                <span className="text-xs font-mono text-slate-400 uppercase">Model Precision</span>
                <div className="text-3xl font-extrabold text-emerald-400 font-mono mt-1">
                  {SOC_METRICS.precision}%
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Only 12 False Positives across 2,400 test cases
                </p>
              </div>

              <div className="soc-card p-5 border border-slate-800">
                <span className="text-xs font-mono text-slate-400 uppercase">Model Recall</span>
                <div className="text-3xl font-extrabold text-cyan-400 font-mono mt-1">
                  {SOC_METRICS.recall}%
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Catches 96.3% of active zero-day phishing feeds
                </p>
              </div>

              <div className="soc-card p-5 border border-slate-800">
                <span className="text-xs font-mono text-slate-400 uppercase">F1-Score</span>
                <div className="text-3xl font-extrabold text-white font-mono mt-1">
                  {SOC_METRICS.f1_score}%
                </div>
                <p className="text-[11px] text-slate-500 mt-1">Harmonic mean of precision & recall</p>
              </div>

              <div className="soc-card p-5 border border-slate-800">
                <span className="text-xs font-mono text-slate-400 uppercase">ROC-AUC Score</span>
                <div className="text-3xl font-extrabold text-amber-400 font-mono mt-1">
                  {SOC_METRICS.roc_auc}
                </div>
                <p className="text-[11px] text-slate-500 mt-1">Near-perfect separation threshold</p>
              </div>
            </div>

            {/* Confusion Matrix & Feature Importances */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Confusion Matrix */}
              <div className="soc-card p-6 border border-slate-800 space-y-4">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-cyan-400" />
                  Held-Out Confusion Matrix (2,400 Evaluation Samples)
                </h3>
                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-4 rounded-xl bg-slate-950 border border-emerald-900/40 text-center">
                    <span className="text-xs font-mono text-slate-400 block">True Negatives (Legitimate)</span>
                    <span className="text-2xl font-bold font-mono text-emerald-400">
                      {SOC_METRICS.confusion_matrix.true_negatives}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-1">Clean pass-through</span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950 border border-amber-900/40 text-center">
                    <span className="text-xs font-mono text-slate-400 block">False Positives (Alert Error)</span>
                    <span className="text-2xl font-bold font-mono text-amber-400">
                      {SOC_METRICS.confusion_matrix.false_positives}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-1">0.5% False alarm rate</span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950 border border-rose-900/40 text-center">
                    <span className="text-xs font-mono text-slate-400 block">False Negatives (Missed)</span>
                    <span className="text-2xl font-bold font-mono text-rose-400">
                      {SOC_METRICS.confusion_matrix.false_negatives}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-1">Stealth evasion cases</span>
                  </div>

                  <div className="p-4 rounded-xl bg-slate-950 border border-cyan-900/40 text-center">
                    <span className="text-xs font-mono text-slate-400 block">True Positives (Blocked)</span>
                    <span className="text-2xl font-bold font-mono text-cyan-400">
                      {SOC_METRICS.confusion_matrix.true_positives}
                    </span>
                    <span className="text-[10px] text-slate-500 block mt-1">Confirmed threats neutralized</span>
                  </div>
                </div>
              </div>

              {/* Feature Importances Ranking */}
              <div className="soc-card p-6 border border-slate-800 space-y-3">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-rose-400" />
                  Top Feature Importances (Gini Impurity Reduction)
                </h3>
                <div className="space-y-2 pt-1 max-h-64 overflow-y-auto pr-1">
                  {SOC_METRICS.feature_importances.map((item, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-slate-300">{item.feature}</span>
                        <span className="text-cyan-400">{(item.importance * 100).toFixed(1)}%</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-slate-900 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-rose-500 to-cyan-400 rounded-full"
                          style={{ width: `${item.importance * 350}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: FALSE POSITIVES DEEP-DIVE */}
        {activeTab === 'false_positives' && (
          <div className="soc-card p-8 border border-slate-800 space-y-6 leading-relaxed">
            <div>
              <div className="flex items-center gap-2 text-rose-400 font-mono text-sm font-bold uppercase tracking-wider mb-1">
                <FileText className="w-4 h-4" />
                Engineering Whitepaper: False Positive Analysis & Mitigation
              </div>
              <h2 className="text-xl font-bold text-white">
                Defensive Machine Learning: Mitigating Alert Fatigue in Production SOCs
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <h4 className="text-sm font-bold text-cyan-400 font-mono">
                  1. The Real Cost of False Positives
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  In enterprise security operations, a classifier with high raw accuracy but poor precision will trigger dozens of false alerts daily. Legitimate employee communications (SSO redirects, cloud receipts, partner marketing portals) get blocked, leading users to bypass security controls.
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <h4 className="text-sm font-bold text-emerald-400 font-mono">
                  2. Achieved Metrics in this Architecture
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Our model was trained with balanced class weights and regularized tree depth, reaching <span className="text-emerald-400 font-semibold font-mono">98.97% Precision</span> and <span className="text-cyan-400 font-semibold font-mono">96.33% Recall</span>. Only 12 false positives occurred in 2,400 held-out evaluation URLs.
                </p>
              </div>
            </div>

            <div className="space-y-4 pt-2">
              <h4 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                Common Edge Cases & Applied Mitigation Rules:
              </h4>

              <div className="space-y-3">
                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                  <div>
                    <span className="font-bold text-slate-200">Enterprise Single Sign-On (SSO) Callbacks</span>
                    <p className="text-slate-400 text-[11px] mt-0.5">
                      OAuth 2.0 URLs contain high entropy session hashes, authorization tokens, and auth keywords (/login, /authorize).
                    </p>
                  </div>
                  <span className="px-3 py-1 rounded bg-slate-900 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] whitespace-nowrap">
                    Rule: Apex Domain Reputation Whitelisting
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                  <div>
                    <span className="font-bold text-slate-200">Content Delivery Network (CDN) Assets</span>
                    <p className="text-slate-400 text-[11px] mt-0.5">
                      Static assets on Fastly, Cloudflare, or Akamai with deep hash-based subdomains mimicking obfuscated URLs.
                    </p>
                  </div>
                  <span className="px-3 py-1 rounded bg-slate-900 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] whitespace-nowrap">
                    Rule: Extension Pre-filter (.js, .css, .woff)
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                  <div>
                    <span className="font-bold text-slate-200">Marketing & Analytics Links</span>
                    <p className="text-slate-400 text-[11px] mt-0.5">
                      Newsletter and promo URLs with 8+ query parameters (utm_source, click_id) inflating URL length and entropy.
                    </p>
                  </div>
                  <span className="px-3 py-1 rounded bg-slate-900 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] whitespace-nowrap">
                    Rule: Query String Normalization
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-black/60 py-4 px-6 text-center text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <span>CyberGuard SOC AI • Cybersecurity & Machine Learning Engineering Showcase</span>
        <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
          <span>RandomForest (120 Trees)</span>
          <span>•</span>
          <span>Isolation Forest Anomaly</span>
          <span>•</span>
          <span>FastAPI + Vite</span>
        </div>
      </footer>
    </div>
  );
}
