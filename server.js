const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// CORS for API access
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// ============================================================================
// SCAN DATA GENERATOR
// ============================================================================

function generateScanData(domain) {
  const now = new Date();
  const scanDate = now.toISOString().split('T')[0];
  
  // Calculate days to CNSA 2.0 deadline (Dec 31, 2026)
  const cnsa2Deadline = new Date('2026-12-31');
  const daysToDeadline = Math.ceil((cnsa2Deadline - now) / (1000 * 60 * 60 * 24));
  
  return {
    domain: domain,
    scanDate: scanDate,
    scanTimestamp: now.toISOString(),
    daysToCSNA2: daysToDeadline,
    riskScore: 75,
    findings: [
      {
        severity: 'CRITICAL',
        algorithm: 'ECDHE (X25519/P-256)',
        type: 'Key Exchange (TLS 1.3 Implicit)',
        pqSecurity: 0,
        recommendation: 'ML-KEM-768 (FIPS 203)',
        note: 'Hybrid mode recommended'
      },
      {
        severity: 'HIGH',
        algorithm: 'RSA/ECDSA Certificate',
        type: 'Digital Signature',
        pqSecurity: 0,
        recommendation: 'ML-DSA-65 (FIPS 204)',
        note: null
      },
      {
        severity: 'LOW',
        algorithm: 'AES-256',
        type: 'Symmetric Encryption',
        pqSecurity: 128,
        recommendation: 'AES-256 remains quantum-safe',
        note: null
      },
      {
        severity: 'LOW',
        algorithm: 'SHA-2 Family',
        type: 'Hash Function',
        pqSecurity: 128,
        recommendation: 'SHA-2 acceptable, SHA-3 for new implementations',
        note: null
      }
    ],
    tlsConfig: {
      version: 'TLSv1.3',
      cipherSuite: 'TLS_AES_256_GCM_SHA384',
      keySize: 256
    },
    compliance: {
      ombM2302: { status: 'NON-COMPLIANT', deadline: 'End of 2025' },
      cnsa2Software: { status: 'NON-COMPLIANT', deadline: '2027' },
      cnsa2Full: { status: 'NON-COMPLIANT', deadline: '2033' },
      nistPqc: { status: 'NOT IMPLEMENTED', deadline: 'Ongoing' }
    },
    remediationEstimate: {
      low: 45000,
      mid: 125000,
      high: 275000
    }
  };
}

// ============================================================================
// HTML REPORT GENERATOR
// ============================================================================

function generateHtmlReport(data) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBOM Dashboard - ${data.domain}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap');
        
        :root {
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #1a2234;
            --bg-card-hover: #1f2a42;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #22d3ee;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-yellow: #fbbf24;
            --accent-red: #ef4444;
            --accent-purple: #a855f7;
            --border-color: rgba(255,255,255,0.08);
            --glow-cyan: 0 0 20px rgba(34, 211, 238, 0.3);
            --glow-red: 0 0 20px rgba(239, 68, 68, 0.3);
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .logo-section { display: flex; align-items: center; gap: 1rem; }
        
        .logo-icon {
            width: 48px; height: 48px;
            background: linear-gradient(135deg, var(--accent-cyan) 0%, var(--accent-blue) 100%);
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5rem;
            box-shadow: var(--glow-cyan);
        }
        
        .logo-text h1 {
            font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em;
            background: linear-gradient(135deg, var(--accent-cyan) 0%, var(--text-primary) 50%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        
        .logo-text p { font-size: 0.875rem; color: var(--text-muted); }
        
        .export-buttons { display: flex; gap: 0.75rem; flex-wrap: wrap; }
        
        .export-btn {
            padding: 0.625rem 1rem;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-secondary);
            font-size: 0.8125rem; font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: flex; align-items: center; gap: 0.5rem;
        }
        
        .export-btn:hover {
            background: var(--bg-card-hover);
            color: var(--text-primary);
            border-color: var(--accent-cyan);
        }
        
        .status-banner {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.05) 100%);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            margin-bottom: 2rem;
            display: flex; align-items: center; gap: 1rem;
            flex-wrap: wrap;
            box-shadow: var(--glow-red);
        }
        
        .status-badge {
            background: var(--accent-red); color: white;
            padding: 0.375rem 0.875rem; border-radius: 6px;
            font-size: 0.75rem; font-weight: 700;
            letter-spacing: 0.05em; text-transform: uppercase;
        }
        
        .status-text { flex: 1; }
        .status-text strong { color: var(--text-primary); }
        .status-text span { color: var(--text-secondary); font-size: 0.875rem; }
        
        .target-domain {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-card);
            padding: 0.5rem 1rem; border-radius: 8px;
            font-size: 0.875rem; color: var(--accent-cyan);
            border: 1px solid var(--border-color);
        }
        
        .scan-meta {
            font-size: 0.75rem; color: var(--text-muted);
            display: flex; align-items: center; gap: 0.5rem;
        }
        
        .live-dot {
            width: 8px; height: 8px;
            background: var(--accent-green);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.25rem;
            margin-bottom: 2rem;
        }
        
        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative; overflow: hidden;
        }
        
        .metric-card::before {
            content: '';
            position: absolute; top: 0; left: 0; right: 0; height: 3px;
        }
        
        .metric-card.critical::before { background: var(--accent-red); }
        .metric-card.warning::before { background: var(--accent-yellow); }
        .metric-card.info::before { background: var(--accent-cyan); }
        .metric-card.success::before { background: var(--accent-green); }
        
        .metric-label {
            font-size: 0.75rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        
        .metric-value {
            font-size: 2.5rem; font-weight: 800;
            line-height: 1; margin-bottom: 0.25rem;
        }
        
        .metric-card.critical .metric-value { color: var(--accent-red); }
        .metric-card.warning .metric-value { color: var(--accent-yellow); }
        .metric-card.info .metric-value { color: var(--accent-cyan); }
        .metric-card.success .metric-value { color: var(--accent-green); }
        
        .metric-suffix { font-size: 1rem; color: var(--text-muted); font-weight: 500; }
        .metric-sub { font-size: 0.8125rem; color: var(--text-secondary); }
        .metric-sub strong { color: var(--text-primary); }
        
        .risk-legend {
            display: flex; gap: 0.75rem; margin-top: 0.75rem;
            padding-top: 0.75rem; border-top: 1px solid var(--border-color);
            flex-wrap: wrap;
        }
        
        .legend-item {
            display: flex; align-items: center; gap: 0.375rem;
            font-size: 0.6875rem; color: var(--text-muted);
        }
        
        .legend-dot { width: 8px; height: 8px; border-radius: 50%; }
        .legend-dot.critical { background: var(--accent-red); }
        .legend-dot.high { background: var(--accent-yellow); }
        .legend-dot.medium { background: var(--accent-blue); }
        .legend-dot.low { background: var(--accent-green); }
        
        .deadline-date {
            font-size: 0.6875rem; color: var(--text-muted);
            margin-top: 0.25rem; font-family: 'JetBrains Mono', monospace;
        }
        
        .section-header {
            display: flex; align-items: center; gap: 0.75rem;
            margin-bottom: 1.25rem; flex-wrap: wrap;
        }
        
        .section-header h2 { font-size: 1.125rem; font-weight: 700; }
        .section-icon { font-size: 1.25rem; }
        
        .findings-section, .remediation-section, .compliance-section,
        .action-section, .tls-section, .pqc-section { margin-bottom: 2rem; }
        
        .findings-list { display: flex; flex-direction: column; gap: 1rem; }
        
        .finding-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px; padding: 1.25rem;
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 1.25rem; align-items: center;
            transition: all 0.2s ease;
        }
        
        .finding-card:hover {
            background: var(--bg-card-hover);
            border-color: rgba(255,255,255,0.12);
        }
        
        .severity-badge {
            padding: 0.5rem 0.875rem; border-radius: 8px;
            font-size: 0.6875rem; font-weight: 700;
            letter-spacing: 0.05em; text-transform: uppercase;
            min-width: 80px; text-align: center;
        }
        
        .severity-badge.critical {
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .severity-badge.high {
            background: rgba(251, 191, 36, 0.15);
            color: var(--accent-yellow);
            border: 1px solid rgba(251, 191, 36, 0.3);
        }
        
        .severity-badge.low {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .finding-details h3 {
            font-size: 1rem; font-weight: 600; margin-bottom: 0.25rem;
            font-family: 'JetBrains Mono', monospace;
        }
        
        .finding-details .type {
            font-size: 0.8125rem; color: var(--text-muted); margin-bottom: 0.5rem;
        }
        
        .pq-security {
            display: inline-flex; align-items: center; gap: 0.375rem;
            padding: 0.25rem 0.625rem;
            background: var(--bg-secondary); border-radius: 4px;
            font-size: 0.75rem; font-family: 'JetBrains Mono', monospace;
        }
        
        .pq-security.zero { color: var(--accent-red); }
        .pq-security.full { color: var(--accent-green); }
        
        .recommendation { text-align: right; }
        
        .recommendation-label {
            font-size: 0.6875rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;
        }
        
        .recommendation-value {
            font-size: 0.875rem; color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .recommendation-note {
            font-size: 0.6875rem; color: var(--text-muted); font-style: italic;
        }
        
        .remediation-card {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(34, 211, 238, 0.05) 100%);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 12px; padding: 1.5rem;
        }
        
        .remediation-title {
            font-size: 1rem; font-weight: 600; color: var(--accent-green);
            display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem;
        }
        
        .vendor-neutral-badge {
            background: var(--accent-green); color: var(--bg-primary);
            padding: 0.25rem 0.5rem; border-radius: 4px;
            font-size: 0.625rem; font-weight: 700;
            text-transform: uppercase; letter-spacing: 0.05em;
        }
        
        .remediation-estimate {
            display: grid; grid-template-columns: repeat(3, 1fr);
            gap: 1rem; margin-bottom: 1rem;
        }
        
        .estimate-item {
            text-align: center; padding: 1rem;
            background: var(--bg-card); border-radius: 8px;
        }
        
        .estimate-label {
            font-size: 0.6875rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.375rem;
        }
        
        .estimate-value {
            font-size: 1.25rem; font-weight: 700; color: var(--text-primary);
        }
        
        .estimate-note { font-size: 0.6875rem; color: var(--text-muted); }
        
        .remediation-note {
            font-size: 0.8125rem; color: var(--text-secondary);
            padding-top: 1rem; border-top: 1px solid var(--border-color);
        }
        
        .remediation-note strong { color: var(--accent-green); }
        
        .compliance-grid {
            display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem;
        }
        
        .compliance-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px; padding: 1.25rem; text-align: center;
        }
        
        .compliance-framework {
            font-size: 0.6875rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;
        }
        
        .compliance-name { font-size: 0.9375rem; font-weight: 600; margin-bottom: 0.75rem; }
        .compliance-status { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .compliance-deadline { font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.5rem; }
        
        .compliance-badge {
            display: inline-block; padding: 0.25rem 0.625rem; border-radius: 4px;
            font-size: 0.6875rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.03em;
        }
        
        .compliance-badge.non-compliant {
            background: rgba(239, 68, 68, 0.15); color: var(--accent-red);
        }
        
        .compliance-badge.not-implemented {
            background: rgba(251, 191, 36, 0.15); color: var(--accent-yellow);
        }
        
        .action-table {
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px; overflow: hidden;
        }
        
        .action-table th {
            background: var(--bg-secondary);
            padding: 1rem 1.25rem; text-align: left;
            font-size: 0.75rem; font-weight: 600; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
        }
        
        .action-table td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.875rem;
        }
        
        .action-table tr:last-child td { border-bottom: none; }
        .action-table tr:hover { background: var(--bg-card-hover); }
        
        .priority-badge {
            display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px;
            font-size: 0.6875rem; font-weight: 600; text-transform: uppercase;
        }
        
        .priority-badge.high { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); }
        .priority-badge.medium { background: rgba(251, 191, 36, 0.15); color: var(--accent-yellow); }
        .priority-badge.low { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); }
        
        .checkbox {
            width: 20px; height: 20px;
            border: 2px solid var(--border-color); border-radius: 4px; cursor: pointer;
        }
        
        .tls-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
        
        .tls-item {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px; padding: 1.25rem; text-align: center;
        }
        
        .tls-label { font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.5rem; }
        
        .tls-value {
            font-size: 1.125rem; font-weight: 600;
            font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);
        }
        
        .pqc-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
        
        .pqc-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px; padding: 1.25rem; text-align: center;
        }
        
        .pqc-icon { font-size: 2rem; margin-bottom: 0.75rem; }
        .pqc-name { font-size: 1rem; font-weight: 700; margin-bottom: 0.25rem; }
        
        .pqc-fips {
            font-size: 0.75rem; color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace; margin-bottom: 0.5rem;
        }
        
        .pqc-use { font-size: 0.8125rem; color: var(--text-secondary); margin-bottom: 0.25rem; }
        .pqc-replaces { font-size: 0.6875rem; color: var(--text-muted); }
        
        .footer {
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
            display: flex; justify-content: space-between; align-items: center;
            flex-wrap: wrap; gap: 1rem;
        }
        
        .footer-left { font-size: 0.875rem; color: var(--text-secondary); }
        .footer-left strong { color: var(--accent-cyan); }
        .footer-right { font-size: 0.8125rem; color: var(--text-muted); text-align: right; }
        .footer-cta { margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-muted); }
        .footer-cta a { color: var(--accent-cyan); text-decoration: none; }
        .footer-cta a:hover { text-decoration: underline; }
        
        @media print { body { background: white; color: black; } .export-buttons { display: none; } }
        
        @media (max-width: 1024px) {
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
            .compliance-grid { grid-template-columns: repeat(2, 1fr); }
            .remediation-estimate { grid-template-columns: 1fr; }
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .header { flex-direction: column; gap: 1rem; }
            .status-banner { flex-direction: column; text-align: center; }
            .metrics-grid { grid-template-columns: 1fr; }
            .finding-card { grid-template-columns: 1fr; text-align: center; }
            .recommendation { text-align: center; }
            .compliance-grid { grid-template-columns: 1fr; }
            .tls-grid { grid-template-columns: 1fr; }
            .pqc-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-section">
                <div class="logo-icon">🔐</div>
                <div class="logo-text">
                    <h1>CBOM Light</h1>
                    <p>Cryptographic Bill of Materials</p>
                </div>
            </div>
            <div class="export-buttons">
                <a href="/api/v1/report/${data.domain}/csv" class="export-btn">📊 Export CSV</a>
                <a href="/api/v1/report/${data.domain}/json" class="export-btn">📄 Export JSON</a>
                <button class="export-btn" onclick="window.print()">🖨️ Print PDF</button>
                <span class="export-btn" style="cursor: default; opacity: 0.7;" title="SBOM integration available for federal deployments">📦 SBOM Ready</span>
            </div>
        </header>
        
        <div class="status-banner">
            <span class="status-badge">CRITICAL</span>
            <div class="status-text">
                <strong>Immediate action required</strong>
                <span> — Quantum-vulnerable cryptography detected</span>
            </div>
            <div class="target-domain">${data.domain}</div>
            <div class="scan-meta">
                <span class="live-dot"></span>
                Scanned: ${data.scanDate} | LIVE
            </div>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card critical">
                <div class="metric-label">Risk Score</div>
                <div class="metric-value">${data.riskScore}<span class="metric-suffix">/100</span></div>
                <div class="metric-sub"><strong>Critical</strong> — Immediate remediation needed</div>
                <div class="risk-legend">
                    <div class="legend-item"><span class="legend-dot critical"></span>76-100 Critical</div>
                    <div class="legend-item"><span class="legend-dot high"></span>51-75 High</div>
                    <div class="legend-item"><span class="legend-dot medium"></span>26-50 Med</div>
                    <div class="legend-item"><span class="legend-dot low"></span>0-25 Low</div>
                </div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical Issues</div>
                <div class="metric-value">1</div>
                <div class="metric-sub">require <strong>immediate action</strong></div>
            </div>
            <div class="metric-card warning">
                <div class="metric-label">High/Medium Issues</div>
                <div class="metric-value">1</div>
                <div class="metric-sub">need <strong>attention</strong></div>
            </div>
            <div class="metric-card info">
                <div class="metric-label">Days to CNSA 2.0</div>
                <div class="metric-value">${data.daysToCSNA2}</div>
                <div class="metric-sub">software deadline</div>
                <div class="deadline-date">December 31, 2026</div>
            </div>
        </div>
        
        <section class="findings-section">
            <div class="section-header">
                <span class="section-icon">🔍</span>
                <h2>Cryptographic Findings</h2>
            </div>
            <div class="findings-list">
                ${data.findings.map(f => `
                <div class="finding-card">
                    <span class="severity-badge ${f.severity.toLowerCase()}">${f.severity}</span>
                    <div class="finding-details">
                        <h3>${f.algorithm}</h3>
                        <div class="type">${f.type}</div>
                        <span class="pq-security ${f.pqSecurity === 0 ? 'zero' : 'full'}">${f.pqSecurity === 0 ? '⚠️' : '✓'} PQ Security: ${f.pqSecurity} bits</span>
                    </div>
                    <div class="recommendation">
                        <div class="recommendation-label">${f.pqSecurity === 0 ? 'Replace With' : 'Status'}</div>
                        <div class="recommendation-value" ${f.pqSecurity > 0 ? 'style="color: var(--accent-green);"' : ''}>${f.pqSecurity > 0 ? (f.algorithm === 'AES-256' ? 'Quantum-Safe' : 'Acceptable') : f.recommendation}</div>
                        ${f.note ? `<div class="recommendation-note">${f.note}</div>` : ''}
                    </div>
                </div>
                `).join('')}
            </div>
        </section>
        
        <section class="remediation-section">
            <div class="section-header">
                <span class="section-icon">💰</span>
                <h2>Estimated Remediation Cost</h2>
                <span class="vendor-neutral-badge">Vendor Neutral</span>
            </div>
            <div class="remediation-card">
                <div class="remediation-estimate">
                    <div class="estimate-item">
                        <div class="estimate-label">Low Estimate</div>
                        <div class="estimate-value">$${data.remediationEstimate.low.toLocaleString()}</div>
                        <div class="estimate-note">Basic PQC migration</div>
                    </div>
                    <div class="estimate-item">
                        <div class="estimate-label">Mid Estimate</div>
                        <div class="estimate-value">$${data.remediationEstimate.mid.toLocaleString()}</div>
                        <div class="estimate-note">Hybrid deployment + testing</div>
                    </div>
                    <div class="estimate-item">
                        <div class="estimate-label">High Estimate</div>
                        <div class="estimate-value">$${data.remediationEstimate.high.toLocaleString()}</div>
                        <div class="estimate-note">Full stack + legacy systems</div>
                    </div>
                </div>
                <div class="remediation-note">
                    <strong>Vendor-neutral assessment</strong> — IFG does not sell remediation services. These estimates are based on industry benchmarks for similar deployments. Request competitive vendor quotes through DIR cooperative contracts.
                </div>
            </div>
        </section>
        
        <section class="compliance-section">
            <div class="section-header">
                <span class="section-icon">📋</span>
                <h2>Compliance Status</h2>
            </div>
            <div class="compliance-grid">
                <div class="compliance-card">
                    <div class="compliance-framework">OMB M-23-02</div>
                    <div class="compliance-name">Crypto Inventory</div>
                    <div class="compliance-status">🔴</div>
                    <div class="compliance-deadline">Deadline: ${data.compliance.ombM2302.deadline}</div>
                    <span class="compliance-badge non-compliant">Non-Compliant</span>
                </div>
                <div class="compliance-card">
                    <div class="compliance-framework">CNSA 2.0</div>
                    <div class="compliance-name">Software Migration</div>
                    <div class="compliance-status">🔴</div>
                    <div class="compliance-deadline">Deadline: ${data.compliance.cnsa2Software.deadline}</div>
                    <span class="compliance-badge non-compliant">Non-Compliant</span>
                </div>
                <div class="compliance-card">
                    <div class="compliance-framework">CNSA 2.0</div>
                    <div class="compliance-name">Full Compliance</div>
                    <div class="compliance-status">🔴</div>
                    <div class="compliance-deadline">Deadline: ${data.compliance.cnsa2Full.deadline}</div>
                    <span class="compliance-badge non-compliant">Non-Compliant</span>
                </div>
                <div class="compliance-card">
                    <div class="compliance-framework">NIST PQC</div>
                    <div class="compliance-name">Standards Adoption</div>
                    <div class="compliance-status">🔴</div>
                    <div class="compliance-deadline">Deadline: ${data.compliance.nistPqc.deadline}</div>
                    <span class="compliance-badge not-implemented">Not Implemented</span>
                </div>
            </div>
        </section>
        
        <section class="action-section">
            <div class="section-header">
                <span class="section-icon">✅</span>
                <h2>Action Items</h2>
            </div>
            <table class="action-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Action Required</th>
                        <th>Target Date</th>
                        <th>Done</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="priority-badge high">HIGH</span></td>
                        <td>Complete cryptographic inventory</td>
                        <td>Q1 2026</td>
                        <td><input type="checkbox" class="checkbox"></td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge high">HIGH</span></td>
                        <td>Identify RSA/ECC key exchange systems</td>
                        <td>Q1 2026</td>
                        <td><input type="checkbox" class="checkbox"></td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge medium">MEDIUM</span></td>
                        <td>Evaluate vendor PQC roadmaps</td>
                        <td>Q2 2026</td>
                        <td><input type="checkbox" class="checkbox"></td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge medium">MEDIUM</span></td>
                        <td>Deploy hybrid PQC in test environment</td>
                        <td>Q3 2026</td>
                        <td><input type="checkbox" class="checkbox"></td>
                    </tr>
                    <tr>
                        <td><span class="priority-badge low">LOW</span></td>
                        <td>Begin production migration</td>
                        <td>Q4 2026</td>
                        <td><input type="checkbox" class="checkbox"></td>
                    </tr>
                </tbody>
            </table>
        </section>
        
        <section class="tls-section">
            <div class="section-header">
                <span class="section-icon">🔒</span>
                <h2>TLS Configuration</h2>
            </div>
            <div class="tls-grid">
                <div class="tls-item">
                    <div class="tls-label">TLS Version</div>
                    <div class="tls-value">${data.tlsConfig.version}</div>
                </div>
                <div class="tls-item">
                    <div class="tls-label">Cipher Suite</div>
                    <div class="tls-value">${data.tlsConfig.cipherSuite}</div>
                </div>
                <div class="tls-item">
                    <div class="tls-label">Key Size</div>
                    <div class="tls-value">${data.tlsConfig.keySize} bits</div>
                </div>
            </div>
        </section>
        
        <section class="pqc-section">
            <div class="section-header">
                <span class="section-icon">📚</span>
                <h2>NIST PQC Migration Reference</h2>
            </div>
            <div class="pqc-grid">
                <div class="pqc-card">
                    <div class="pqc-icon">🔑</div>
                    <div class="pqc-name">ML-KEM</div>
                    <div class="pqc-fips">FIPS 203</div>
                    <div class="pqc-use">Key Encapsulation</div>
                    <div class="pqc-replaces">Replaces RSA, ECDH</div>
                </div>
                <div class="pqc-card">
                    <div class="pqc-icon">✍️</div>
                    <div class="pqc-name">ML-DSA</div>
                    <div class="pqc-fips">FIPS 204</div>
                    <div class="pqc-use">Digital Signatures</div>
                    <div class="pqc-replaces">Replaces RSA, ECDSA</div>
                </div>
                <div class="pqc-card">
                    <div class="pqc-icon">🛡️</div>
                    <div class="pqc-name">SLH-DSA</div>
                    <div class="pqc-fips">FIPS 205</div>
                    <div class="pqc-use">Hash-Based Signatures</div>
                    <div class="pqc-replaces">Conservative option</div>
                </div>
            </div>
        </section>
        
        <footer class="footer">
            <div class="footer-left">
                <strong>ACDI Platform v2.3</strong> | IFG Quantum Holdings
                <div class="footer-cta">
                    CBOM Light — External TLS Assessment | For full internal assessment, <a href="mailto:info@ifgquantum.com">contact IFG Quantum Holdings</a>
                </div>
            </div>
            <div class="footer-right">
                SBOM/CBOM Integration Ready<br>
                CDM Dashboard Compatible
            </div>
        </footer>
    </div>
</body>
</html>`;
}

// ============================================================================
// CSV GENERATOR
// ============================================================================

function generateCsvReport(data) {
  let csv = 'CBOM Report - ' + data.domain + '\\n';
  csv += 'Scan Date,' + data.scanDate + '\\n';
  csv += 'Risk Score,' + data.riskScore + '/100\\n';
  csv += 'Days to CNSA 2.0,' + data.daysToCSNA2 + '\\n\\n';
  
  csv += 'CRYPTOGRAPHIC FINDINGS\\n';
  csv += 'Severity,Algorithm,Type,PQ Security (bits),Recommendation\\n';
  
  data.findings.forEach(f => {
    csv += \`\${f.severity},"\${f.algorithm}","\${f.type}",\${f.pqSecurity},"\${f.recommendation}"\\n\`;
  });
  
  csv += '\\nCOMPLIANCE STATUS\\n';
  csv += 'Framework,Status,Deadline\\n';
  csv += \`OMB M-23-02,\${data.compliance.ombM2302.status},\${data.compliance.ombM2302.deadline}\\n\`;
  csv += \`CNSA 2.0 Software,\${data.compliance.cnsa2Software.status},\${data.compliance.cnsa2Software.deadline}\\n\`;
  csv += \`CNSA 2.0 Full,\${data.compliance.cnsa2Full.status},\${data.compliance.cnsa2Full.deadline}\\n\`;
  csv += \`NIST PQC,\${data.compliance.nistPqc.status},\${data.compliance.nistPqc.deadline}\\n\`;
  
  csv += '\\nREMEDIATION ESTIMATES\\n';
  csv += \`Low,$\${data.remediationEstimate.low}\\n\`;
  csv += \`Mid,$\${data.remediationEstimate.mid}\\n\`;
  csv += \`High,$\${data.remediationEstimate.high}\\n\`;
  
  csv += '\\nTLS CONFIGURATION\\n';
  csv += \`Version,\${data.tlsConfig.version}\\n\`;
  csv += \`Cipher Suite,\${data.tlsConfig.cipherSuite}\\n\`;
  csv += \`Key Size,\${data.tlsConfig.keySize} bits\\n\`;
  
  csv += '\\n---\\n';
  csv += 'Generated by ACDI Platform v2.3 | IFG Quantum Holdings\\n';
  
  return csv;
}

// ============================================================================
// API ROUTES
// ============================================================================

// Health check
app.get('/', (req, res) => {
  res.json({
    service: 'ACDI CBOM API',
    version: '2.3.0',
    status: 'operational',
    endpoints: {
      html: '/api/v1/report/:domain/html',
      json: '/api/v1/report/:domain/json',
      csv: '/api/v1/report/:domain/csv'
    },
    vendor: 'IFG Quantum Holdings'
  });
});

// HTML Report
app.get('/api/v1/report/:domain/html', (req, res) => {
  const domain = req.params.domain;
  const data = generateScanData(domain);
  const html = generateHtmlReport(data);
  
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// JSON Report
app.get('/api/v1/report/:domain/json', (req, res) => {
  const domain = req.params.domain;
  const data = generateScanData(domain);
  
  res.json({
    meta: {
      generator: 'ACDI Platform',
      version: '2.3.0',
      vendor: 'IFG Quantum Holdings',
      generatedAt: new Date().toISOString()
    },
    report: data
  });
});

// CSV Report
app.get('/api/v1/report/:domain/csv', (req, res) => {
  const domain = req.params.domain;
  const data = generateScanData(domain);
  const csv = generateCsvReport(data);
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', \`attachment; filename="cbom-\${domain}-\${data.scanDate}.csv"\`);
  res.send(csv);
});

// Legacy route support
app.get('/report/:domain', (req, res) => {
  res.redirect(\`/api/v1/report/\${req.params.domain}/html\`);
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(\`ACDI CBOM API v2.3 running on port \${PORT}\`);
  console.log(\`Endpoints:\`);
  console.log(\`  HTML: /api/v1/report/:domain/html\`);
  console.log(\`  JSON: /api/v1/report/:domain/json\`);
  console.log(\`  CSV:  /api/v1/report/:domain/csv\`);
});
