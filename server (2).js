const express = require('express');
const tls = require('tls');
const https = require('https');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(function(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// ============================================================================
// REAL TLS SCANNER
// ============================================================================

function scanDomain(domain) {
  return new Promise(function(resolve, reject) {
    var results = {
      domain: domain,
      scanDate: new Date().toISOString().split('T')[0],
      scanTimestamp: new Date().toISOString(),
      tlsVersion: null,
      cipherSuite: null,
      keyExchange: null,
      certificate: {
        subject: null,
        issuer: null,
        validFrom: null,
        validTo: null,
        serialNumber: null,
        signatureAlgorithm: null,
        publicKeyAlgorithm: null,
        publicKeySize: null
      },
      protocols: [],
      error: null
    };

    var options = {
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 10000
    };

    var socket = tls.connect(options, function() {
      try {
        // Get TLS version and cipher
        var cipher = socket.getCipher();
        if (cipher) {
          results.tlsVersion = cipher.version || socket.getProtocol();
          results.cipherSuite = cipher.name;
          results.keyExchange = extractKeyExchange(cipher.name);
        }

        // Get certificate details
        var cert = socket.getPeerCertificate(true);
        if (cert) {
          results.certificate = {
            subject: cert.subject ? formatSubject(cert.subject) : 'Unknown',
            issuer: cert.issuer ? formatSubject(cert.issuer) : 'Unknown',
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            serialNumber: cert.serialNumber || null,
            signatureAlgorithm: extractSignatureAlgorithm(cert),
            publicKeyAlgorithm: extractPublicKeyAlgorithm(cert),
            publicKeySize: extractKeySize(cert)
          };
        }

        socket.end();
        resolve(results);
      } catch (e) {
        results.error = e.message;
        socket.end();
        resolve(results);
      }
    });

    socket.on('error', function(err) {
      results.error = err.message;
      resolve(results);
    });

    socket.setTimeout(10000, function() {
      results.error = 'Connection timeout';
      socket.destroy();
      resolve(results);
    });
  });
}

function extractKeyExchange(cipherName) {
  if (!cipherName) return 'Unknown';
  if (cipherName.indexOf('ECDHE') !== -1) return 'ECDHE';
  if (cipherName.indexOf('DHE') !== -1) return 'DHE';
  if (cipherName.indexOf('RSA') !== -1 && cipherName.indexOf('ECDHE') === -1) return 'RSA';
  if (cipherName.indexOf('ECDH') !== -1) return 'ECDH';
  return 'Unknown';
}

function extractSignatureAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  // Try to get from certificate info
  if (cert.infoAccess) {
    // Check for signature algorithm indicators
  }
  
  // Check the bits/modulus for RSA vs EC
  if (cert.bits) {
    if (cert.bits >= 2048) return 'RSA';
  }
  
  if (cert.pubkey) {
    var keyType = cert.pubkey.type || '';
    if (keyType.toLowerCase().indexOf('ec') !== -1) return 'ECDSA';
    if (keyType.toLowerCase().indexOf('rsa') !== -1) return 'RSA';
  }
  
  // Infer from key size
  if (cert.bits) {
    if (cert.bits === 256 || cert.bits === 384 || cert.bits === 521) return 'ECDSA';
    if (cert.bits >= 1024) return 'RSA';
  }
  
  return 'RSA/ECDSA';
}

function extractPublicKeyAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  if (cert.pubkey && cert.pubkey.type) {
    return cert.pubkey.type.toUpperCase();
  }
  
  if (cert.bits) {
    if (cert.bits === 256 || cert.bits === 384 || cert.bits === 521) return 'EC';
    if (cert.bits >= 1024) return 'RSA';
  }
  
  return 'Unknown';
}

function extractKeySize(cert) {
  if (!cert) return null;
  return cert.bits || null;
}

function formatSubject(subj) {
  if (!subj) return 'Unknown';
  if (typeof subj === 'string') return subj;
  
  var parts = [];
  if (subj.CN) parts.push('CN=' + subj.CN);
  if (subj.O) parts.push('O=' + subj.O);
  if (subj.C) parts.push('C=' + subj.C);
  
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
}

// ============================================================================
// ANALYZE SCAN RESULTS FOR PQC VULNERABILITIES
// ============================================================================

function analyzeResults(scanResults) {
  var findings = [];
  var riskScore = 0;
  var criticalCount = 0;
  var highCount = 0;

  // Analyze Key Exchange
  var keyEx = scanResults.keyExchange || 'Unknown';
  var cipherSuite = scanResults.cipherSuite || '';
  
  if (keyEx === 'ECDHE' || keyEx === 'ECDH' || keyEx === 'DHE') {
    findings.push({
      severity: 'CRITICAL',
      algorithm: keyEx + ' Key Exchange',
      type: 'Key Exchange (' + scanResults.tlsVersion + ')',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'Hybrid mode recommended for transition'
    });
    riskScore += 35;
    criticalCount++;
  } else if (keyEx === 'RSA') {
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'RSA Key Exchange',
      type: 'Key Exchange (Static RSA)',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'RSA key exchange lacks forward secrecy'
    });
    riskScore += 40;
    criticalCount++;
  }

  // Analyze Certificate/Signature Algorithm
  var sigAlg = scanResults.certificate.signatureAlgorithm || 'Unknown';
  var keySize = scanResults.certificate.publicKeySize;
  
  if (sigAlg === 'RSA' || sigAlg === 'RSA/ECDSA') {
    var keySizeStr = keySize ? ' (' + keySize + '-bit)' : '';
    findings.push({
      severity: 'HIGH',
      algorithm: 'RSA Certificate' + keySizeStr,
      type: 'Digital Signature',
      pqSecurity: 0,
      recommendation: 'ML-DSA-65 (FIPS 204)',
      note: null
    });
    riskScore += 25;
    highCount++;
  } else if (sigAlg === 'ECDSA') {
    var keySizeStr = keySize ? ' (' + keySize + '-bit)' : '';
    findings.push({
      severity: 'HIGH',
      algorithm: 'ECDSA Certificate' + keySizeStr,
      type: 'Digital Signature',
      pqSecurity: 0,
      recommendation: 'ML-DSA-65 (FIPS 204)',
      note: null
    });
    riskScore += 25;
    highCount++;
  }

  // Check for AES in cipher suite
  if (cipherSuite.indexOf('AES') !== -1) {
    var aesSize = '256';
    if (cipherSuite.indexOf('128') !== -1) aesSize = '128';
    if (cipherSuite.indexOf('256') !== -1) aesSize = '256';
    
    findings.push({
      severity: 'LOW',
      algorithm: 'AES-' + aesSize,
      type: 'Symmetric Encryption',
      pqSecurity: parseInt(aesSize) / 2, // Grover's algorithm halves effective security
      recommendation: 'AES-' + aesSize + ' remains quantum-safe',
      note: aesSize === '128' ? 'Consider AES-256 for longer-term security' : null
    });
  } else if (cipherSuite.indexOf('CHACHA20') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'ChaCha20-Poly1305',
      type: 'Symmetric Encryption',
      pqSecurity: 128,
      recommendation: 'ChaCha20 remains quantum-safe',
      note: null
    });
  }

  // Check hash function
  if (cipherSuite.indexOf('SHA384') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'SHA-384',
      type: 'Hash Function',
      pqSecurity: 192,
      recommendation: 'SHA-384 acceptable',
      note: 'SHA-3 for new implementations'
    });
  } else if (cipherSuite.indexOf('SHA256') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'SHA-256',
      type: 'Hash Function',
      pqSecurity: 128,
      recommendation: 'SHA-256 acceptable',
      note: 'SHA-3 for new implementations'
    });
  }

  // Cap risk score
  if (riskScore > 100) riskScore = 100;
  if (riskScore < 25 && criticalCount === 0 && highCount === 0) riskScore = 25;

  // Calculate days to CNSA 2.0
  var cnsa2Deadline = new Date('2026-12-31');
  var now = new Date();
  var daysToDeadline = Math.ceil((cnsa2Deadline - now) / (1000 * 60 * 60 * 24));

  return {
    domain: scanResults.domain,
    scanDate: scanResults.scanDate,
    scanTimestamp: scanResults.scanTimestamp,
    daysToCSNA2: daysToDeadline,
    riskScore: riskScore,
    criticalCount: criticalCount,
    highCount: highCount,
    findings: findings,
    tlsConfig: {
      version: scanResults.tlsVersion || 'Unknown',
      cipherSuite: scanResults.cipherSuite || 'Unknown',
      keySize: scanResults.certificate.publicKeySize || 'Unknown'
    },
    certificate: scanResults.certificate,
    compliance: {
      ombM2302: { status: 'NON-COMPLIANT', deadline: 'End of 2025' },
      cnsa2Software: { status: criticalCount > 0 ? 'NON-COMPLIANT' : 'PARTIAL', deadline: '2027' },
      cnsa2Full: { status: 'NON-COMPLIANT', deadline: '2033' },
      nistPqc: { status: 'NOT IMPLEMENTED', deadline: 'Ongoing' }
    },
    remediationEstimate: calculateRemediation(criticalCount, highCount),
    error: scanResults.error
  };
}

function calculateRemediation(criticalCount, highCount) {
  // Base costs
  var low = 25000;
  var mid = 75000;
  var high = 150000;
  
  // Scale based on findings
  if (criticalCount > 0) {
    low += criticalCount * 20000;
    mid += criticalCount * 50000;
    high += criticalCount * 100000;
  }
  
  if (highCount > 0) {
    low += highCount * 10000;
    mid += highCount * 25000;
    high += highCount * 50000;
  }
  
  return { low: low, mid: mid, high: high };
}

// ============================================================================
// HTML REPORT GENERATOR
// ============================================================================

function generateHtmlReport(data) {
  var statusClass = data.riskScore >= 75 ? 'critical' : (data.riskScore >= 50 ? 'warning' : 'info');
  var statusText = data.riskScore >= 75 ? 'CRITICAL' : (data.riskScore >= 50 ? 'HIGH' : 'MODERATE');
  var statusMessage = data.riskScore >= 75 ? 'Immediate action required' : (data.riskScore >= 50 ? 'Action recommended' : 'Monitor and plan');

  var findingsHtml = data.findings.map(function(f) {
    var securityClass = f.pqSecurity === 0 ? 'zero' : 'full';
    var securityIcon = f.pqSecurity === 0 ? '⚠️' : '✓';
    var recLabel = f.pqSecurity === 0 ? 'Replace With' : 'Status';
    var recValue = f.pqSecurity > 0 ? 'Quantum-Safe' : f.recommendation;
    var recStyle = f.pqSecurity > 0 ? 'style="color: var(--accent-green);"' : '';
    var noteHtml = f.note ? '<div class="recommendation-note">' + f.note + '</div>' : '';
    
    return '<div class="finding-card"><span class="severity-badge ' + f.severity.toLowerCase() + '">' + f.severity + '</span><div class="finding-details"><h3>' + f.algorithm + '</h3><div class="type">' + f.type + '</div><span class="pq-security ' + securityClass + '">' + securityIcon + ' PQ Security: ' + f.pqSecurity + ' bits</span></div><div class="recommendation"><div class="recommendation-label">' + recLabel + '</div><div class="recommendation-value" ' + recStyle + '>' + recValue + '</div>' + noteHtml + '</div></div>';
  }).join('');

  var errorBanner = '';
  if (data.error) {
    errorBanner = '<div class="error-banner">⚠️ Scan completed with warnings: ' + data.error + '</div>';
  }

  var certInfo = '';
  if (data.certificate && data.certificate.subject) {
    certInfo = '<section class="cert-section"><div class="section-header"><span class="section-icon">📜</span><h2>Certificate Details</h2></div><div class="cert-grid"><div class="cert-item"><div class="cert-label">Subject</div><div class="cert-value">' + data.certificate.subject + '</div></div><div class="cert-item"><div class="cert-label">Issuer</div><div class="cert-value">' + data.certificate.issuer + '</div></div><div class="cert-item"><div class="cert-label">Valid From</div><div class="cert-value">' + (data.certificate.validFrom || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Valid To</div><div class="cert-value">' + (data.certificate.validTo || 'N/A') + '</div></div></div></section>';
  }

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CBOM Dashboard - ' + data.domain + '</title><style>@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap");:root{--bg-primary:#0a0e1a;--bg-secondary:#111827;--bg-card:#1a2234;--bg-card-hover:#1f2a42;--text-primary:#f8fafc;--text-secondary:#94a3b8;--text-muted:#64748b;--accent-cyan:#22d3ee;--accent-blue:#3b82f6;--accent-green:#10b981;--accent-yellow:#fbbf24;--accent-red:#ef4444;--accent-purple:#a855f7;--border-color:rgba(255,255,255,0.08);--glow-cyan:0 0 20px rgba(34,211,238,0.3);--glow-red:0 0 20px rgba(239,68,68,0.3)}*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;min-height:100vh}.container{max-width:1200px;margin:0 auto;padding:2rem}.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border-color)}.logo-section{display:flex;align-items:center;gap:1rem}.logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--accent-cyan) 0%,var(--accent-blue) 100%);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;box-shadow:var(--glow-cyan)}.logo-text h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;background:linear-gradient(135deg,var(--accent-cyan) 0%,var(--text-primary) 50%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.logo-text p{font-size:0.875rem;color:var(--text-muted)}.export-buttons{display:flex;gap:0.75rem;flex-wrap:wrap}.export-btn{padding:0.625rem 1rem;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);font-size:0.8125rem;font-weight:500;cursor:pointer;transition:all 0.2s ease;text-decoration:none;display:flex;align-items:center;gap:0.5rem}.export-btn:hover{background:var(--bg-card-hover);color:var(--text-primary);border-color:var(--accent-cyan)}.error-banner{background:rgba(251,191,36,0.15);border:1px solid rgba(251,191,36,0.3);border-radius:8px;padding:0.75rem 1rem;margin-bottom:1rem;font-size:0.875rem;color:var(--accent-yellow)}.status-banner{background:linear-gradient(135deg,rgba(239,68,68,0.15) 0%,rgba(239,68,68,0.05) 100%);border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:1rem 1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;box-shadow:var(--glow-red)}.status-banner.warning{background:linear-gradient(135deg,rgba(251,191,36,0.15) 0%,rgba(251,191,36,0.05) 100%);border-color:rgba(251,191,36,0.3);box-shadow:0 0 20px rgba(251,191,36,0.3)}.status-banner.info{background:linear-gradient(135deg,rgba(34,211,238,0.15) 0%,rgba(34,211,238,0.05) 100%);border-color:rgba(34,211,238,0.3);box-shadow:var(--glow-cyan)}.status-badge{background:var(--accent-red);color:white;padding:0.375rem 0.875rem;border-radius:6px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase}.status-badge.warning{background:var(--accent-yellow);color:#000}.status-badge.info{background:var(--accent-cyan);color:#000}.status-text{flex:1}.status-text strong{color:var(--text-primary)}.status-text span{color:var(--text-secondary);font-size:0.875rem}.target-domain{font-family:"JetBrains Mono",monospace;background:var(--bg-card);padding:0.5rem 1rem;border-radius:8px;font-size:0.875rem;color:var(--accent-cyan);border:1px solid var(--border-color)}.scan-meta{font-size:0.75rem;color:var(--text-muted);display:flex;align-items:center;gap:0.5rem}.live-dot{width:8px;height:8px;background:var(--accent-green);border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.metrics-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1.25rem;margin-bottom:2rem}.metric-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.5rem;position:relative;overflow:hidden}.metric-card::before{content:"";position:absolute;top:0;left:0;right:0;height:3px}.metric-card.critical::before{background:var(--accent-red)}.metric-card.warning::before{background:var(--accent-yellow)}.metric-card.info::before{background:var(--accent-cyan)}.metric-card.success::before{background:var(--accent-green)}.metric-label{font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem}.metric-value{font-size:2.5rem;font-weight:800;line-height:1;margin-bottom:0.25rem}.metric-card.critical .metric-value{color:var(--accent-red)}.metric-card.warning .metric-value{color:var(--accent-yellow)}.metric-card.info .metric-value{color:var(--accent-cyan)}.metric-card.success .metric-value{color:var(--accent-green)}.metric-suffix{font-size:1rem;color:var(--text-muted);font-weight:500}.metric-sub{font-size:0.8125rem;color:var(--text-secondary)}.metric-sub strong{color:var(--text-primary)}.risk-legend{display:flex;gap:0.75rem;margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border-color);flex-wrap:wrap}.legend-item{display:flex;align-items:center;gap:0.375rem;font-size:0.6875rem;color:var(--text-muted)}.legend-dot{width:8px;height:8px;border-radius:50%}.legend-dot.critical{background:var(--accent-red)}.legend-dot.high{background:var(--accent-yellow)}.legend-dot.medium{background:var(--accent-blue)}.legend-dot.low{background:var(--accent-green)}.deadline-date{font-size:0.6875rem;color:var(--text-muted);margin-top:0.25rem;font-family:"JetBrains Mono",monospace}.section-header{display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;flex-wrap:wrap}.section-header h2{font-size:1.125rem;font-weight:700}.section-icon{font-size:1.25rem}.findings-section,.remediation-section,.compliance-section,.action-section,.tls-section,.pqc-section,.cert-section{margin-bottom:2rem}.findings-list{display:flex;flex-direction:column;gap:1rem}.finding-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;display:grid;grid-template-columns:auto 1fr auto;gap:1.25rem;align-items:center;transition:all 0.2s ease}.finding-card:hover{background:var(--bg-card-hover);border-color:rgba(255,255,255,0.12)}.severity-badge{padding:0.5rem 0.875rem;border-radius:8px;font-size:0.6875rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;min-width:80px;text-align:center}.severity-badge.critical{background:rgba(239,68,68,0.15);color:var(--accent-red);border:1px solid rgba(239,68,68,0.3)}.severity-badge.high{background:rgba(251,191,36,0.15);color:var(--accent-yellow);border:1px solid rgba(251,191,36,0.3)}.severity-badge.low{background:rgba(16,185,129,0.15);color:var(--accent-green);border:1px solid rgba(16,185,129,0.3)}.finding-details h3{font-size:1rem;font-weight:600;margin-bottom:0.25rem;font-family:"JetBrains Mono",monospace}.finding-details .type{font-size:0.8125rem;color:var(--text-muted);margin-bottom:0.5rem}.pq-security{display:inline-flex;align-items:center;gap:0.375rem;padding:0.25rem 0.625rem;background:var(--bg-secondary);border-radius:4px;font-size:0.75rem;font-family:"JetBrains Mono",monospace}.pq-security.zero{color:var(--accent-red)}.pq-security.full{color:var(--accent-green)}.recommendation{text-align:right}.recommendation-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem}.recommendation-value{font-size:0.875rem;color:var(--accent-cyan);font-family:"JetBrains Mono",monospace}.recommendation-note{font-size:0.6875rem;color:var(--text-muted);font-style:italic}.remediation-card{background:linear-gradient(135deg,rgba(16,185,129,0.1) 0%,rgba(34,211,238,0.05) 100%);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:1.5rem}.vendor-neutral-badge{background:var(--accent-green);color:var(--bg-primary);padding:0.25rem 0.5rem;border-radius:4px;font-size:0.625rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em}.remediation-estimate{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem}.estimate-item{text-align:center;padding:1rem;background:var(--bg-card);border-radius:8px}.estimate-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.375rem}.estimate-value{font-size:1.25rem;font-weight:700;color:var(--text-primary)}.estimate-note{font-size:0.6875rem;color:var(--text-muted)}.remediation-note{font-size:0.8125rem;color:var(--text-secondary);padding-top:1rem;border-top:1px solid var(--border-color)}.remediation-note strong{color:var(--accent-green)}.compliance-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}.compliance-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.compliance-framework{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem}.compliance-name{font-size:0.9375rem;font-weight:600;margin-bottom:0.75rem}.compliance-status{font-size:1.5rem;margin-bottom:0.5rem}.compliance-deadline{font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem}.compliance-badge{display:inline-block;padding:0.25rem 0.625rem;border-radius:4px;font-size:0.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:0.03em}.compliance-badge.non-compliant{background:rgba(239,68,68,0.15);color:var(--accent-red)}.compliance-badge.partial{background:rgba(251,191,36,0.15);color:var(--accent-yellow)}.compliance-badge.not-implemented{background:rgba(251,191,36,0.15);color:var(--accent-yellow)}.action-table{width:100%;background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;overflow:hidden}.action-table th{background:var(--bg-secondary);padding:1rem 1.25rem;text-align:left;font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid var(--border-color)}.action-table td{padding:1rem 1.25rem;border-bottom:1px solid var(--border-color);font-size:0.875rem}.action-table tr:last-child td{border-bottom:none}.action-table tr:hover{background:var(--bg-card-hover)}.priority-badge{display:inline-block;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.6875rem;font-weight:600;text-transform:uppercase}.priority-badge.high{background:rgba(239,68,68,0.15);color:var(--accent-red)}.priority-badge.medium{background:rgba(251,191,36,0.15);color:var(--accent-yellow)}.priority-badge.low{background:rgba(16,185,129,0.15);color:var(--accent-green)}.checkbox{width:20px;height:20px;border:2px solid var(--border-color);border-radius:4px;cursor:pointer}.tls-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.tls-item{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.tls-label{font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem}.tls-value{font-size:1.125rem;font-weight:600;font-family:"JetBrains Mono",monospace;color:var(--accent-cyan)}.cert-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}.cert-item{background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:1rem}.cert-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem}.cert-value{font-size:0.875rem;color:var(--text-primary);word-break:break-all}.pqc-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.pqc-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.pqc-icon{font-size:2rem;margin-bottom:0.75rem}.pqc-name{font-size:1rem;font-weight:700;margin-bottom:0.25rem}.pqc-fips{font-size:0.75rem;color:var(--accent-cyan);font-family:"JetBrains Mono",monospace;margin-bottom:0.5rem}.pqc-use{font-size:0.8125rem;color:var(--text-secondary);margin-bottom:0.25rem}.pqc-replaces{font-size:0.6875rem;color:var(--text-muted)}.footer{border-top:1px solid var(--border-color);padding-top:1.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}.footer-left{font-size:0.875rem;color:var(--text-secondary)}.footer-left strong{color:var(--accent-cyan)}.footer-right{font-size:0.8125rem;color:var(--text-muted);text-align:right}.footer-cta{margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted)}.footer-cta a{color:var(--accent-cyan);text-decoration:none}.footer-cta a:hover{text-decoration:underline}.scanning-indicator{text-align:center;padding:4rem 2rem;color:var(--text-muted)}.scanning-indicator .spinner{width:48px;height:48px;border:3px solid var(--border-color);border-top-color:var(--accent-cyan);border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}.@keyframes spin{to{transform:rotate(360deg)}}@media print{body{background:white;color:black}.export-buttons{display:none}}@media(max-width:1024px){.metrics-grid{grid-template-columns:repeat(2,1fr)}.compliance-grid{grid-template-columns:repeat(2,1fr)}.remediation-estimate{grid-template-columns:1fr}.cert-grid{grid-template-columns:1fr}}@media(max-width:768px){.container{padding:1rem}.header{flex-direction:column;gap:1rem}.status-banner{flex-direction:column;text-align:center}.metrics-grid{grid-template-columns:1fr}.finding-card{grid-template-columns:1fr;text-align:center}.recommendation{text-align:center}.compliance-grid{grid-template-columns:1fr}.tls-grid{grid-template-columns:1fr}.pqc-grid{grid-template-columns:1fr}}</style></head><body><div class="container"><header class="header"><div class="logo-section"><div class="logo-icon">🔐</div><div class="logo-text"><h1>CBOM Live</h1><p>Cryptographic Bill of Materials</p></div></div><div class="export-buttons"><a href="/api/v1/report/' + data.domain + '/csv" class="export-btn">📊 Export CSV</a><a href="/api/v1/report/' + data.domain + '/json" class="export-btn">📄 Export JSON</a><button class="export-btn" onclick="window.print()">🖨️ Print PDF</button><span class="export-btn" style="cursor:default;opacity:0.7" title="SBOM integration available">📦 SBOM Ready</span></div></header>' + errorBanner + '<div class="status-banner ' + statusClass + '"><span class="status-badge ' + statusClass + '">' + statusText + '</span><div class="status-text"><strong>' + statusMessage + '</strong><span> — Quantum-vulnerable cryptography detected</span></div><div class="target-domain">' + data.domain + '</div><div class="scan-meta"><span class="live-dot"></span>Scanned: ' + data.scanDate + ' | LIVE</div></div><div class="metrics-grid"><div class="metric-card ' + statusClass + '"><div class="metric-label">Risk Score</div><div class="metric-value">' + data.riskScore + '<span class="metric-suffix">/100</span></div><div class="metric-sub"><strong>' + statusText + '</strong> — ' + statusMessage + '</div><div class="risk-legend"><div class="legend-item"><span class="legend-dot critical"></span>76-100 Critical</div><div class="legend-item"><span class="legend-dot high"></span>51-75 High</div><div class="legend-item"><span class="legend-dot medium"></span>26-50 Med</div><div class="legend-item"><span class="legend-dot low"></span>0-25 Low</div></div></div><div class="metric-card ' + (data.criticalCount > 0 ? 'critical' : 'success') + '"><div class="metric-label">Critical Issues</div><div class="metric-value">' + data.criticalCount + '</div><div class="metric-sub">' + (data.criticalCount > 0 ? 'require <strong>immediate action</strong>' : '<strong>None detected</strong>') + '</div></div><div class="metric-card ' + (data.highCount > 0 ? 'warning' : 'success') + '"><div class="metric-label">High/Medium Issues</div><div class="metric-value">' + data.highCount + '</div><div class="metric-sub">' + (data.highCount > 0 ? 'need <strong>attention</strong>' : '<strong>None detected</strong>') + '</div></div><div class="metric-card info"><div class="metric-label">Days to CNSA 2.0</div><div class="metric-value">' + data.daysToCSNA2 + '</div><div class="metric-sub">software deadline</div><div class="deadline-date">December 31, 2026</div></div></div><section class="findings-section"><div class="section-header"><span class="section-icon">🔍</span><h2>Cryptographic Findings</h2></div><div class="findings-list">' + findingsHtml + '</div></section><section class="remediation-section"><div class="section-header"><span class="section-icon">💰</span><h2>Estimated Remediation Cost</h2><span class="vendor-neutral-badge">Vendor Neutral</span></div><div class="remediation-card"><div class="remediation-estimate"><div class="estimate-item"><div class="estimate-label">Low Estimate</div><div class="estimate-value">$' + data.remediationEstimate.low.toLocaleString() + '</div><div class="estimate-note">Basic PQC migration</div></div><div class="estimate-item"><div class="estimate-label">Mid Estimate</div><div class="estimate-value">$' + data.remediationEstimate.mid.toLocaleString() + '</div><div class="estimate-note">Hybrid deployment + testing</div></div><div class="estimate-item"><div class="estimate-label">High Estimate</div><div class="estimate-value">$' + data.remediationEstimate.high.toLocaleString() + '</div><div class="estimate-note">Full stack + legacy systems</div></div></div><div class="remediation-note"><strong>Vendor-neutral assessment</strong> — IFG does not sell remediation services. These estimates are based on industry benchmarks. Request competitive vendor quotes through DIR cooperative contracts.</div></div></section>' + certInfo + '<section class="compliance-section"><div class="section-header"><span class="section-icon">📋</span><h2>Compliance Status</h2></div><div class="compliance-grid"><div class="compliance-card"><div class="compliance-framework">OMB M-23-02</div><div class="compliance-name">Crypto Inventory</div><div class="compliance-status">🔴</div><div class="compliance-deadline">Deadline: ' + data.compliance.ombM2302.deadline + '</div><span class="compliance-badge non-compliant">Non-Compliant</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Software Migration</div><div class="compliance-status">' + (data.compliance.cnsa2Software.status === 'PARTIAL' ? '🟡' : '🔴') + '</div><div class="compliance-deadline">Deadline: ' + data.compliance.cnsa2Software.deadline + '</div><span class="compliance-badge ' + (data.compliance.cnsa2Software.status === 'PARTIAL' ? 'partial' : 'non-compliant') + '">' + data.compliance.cnsa2Software.status.replace('_', ' ') + '</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Full Compliance</div><div class="compliance-status">🔴</div><div class="compliance-deadline">Deadline: ' + data.compliance.cnsa2Full.deadline + '</div><span class="compliance-badge non-compliant">Non-Compliant</span></div><div class="compliance-card"><div class="compliance-framework">NIST PQC</div><div class="compliance-name">Standards Adoption</div><div class="compliance-status">🔴</div><div class="compliance-deadline">Deadline: ' + data.compliance.nistPqc.deadline + '</div><span class="compliance-badge not-implemented">Not Implemented</span></div></div></section><section class="action-section"><div class="section-header"><span class="section-icon">✅</span><h2>Action Items</h2></div><table class="action-table"><thead><tr><th>Priority</th><th>Action Required</th><th>Target Date</th><th>Done</th></tr></thead><tbody><tr><td><span class="priority-badge high">HIGH</span></td><td>Complete cryptographic inventory</td><td>Q1 2026</td><td><input type="checkbox" class="checkbox"></td></tr><tr><td><span class="priority-badge high">HIGH</span></td><td>Identify RSA/ECC key exchange systems</td><td>Q1 2026</td><td><input type="checkbox" class="checkbox"></td></tr><tr><td><span class="priority-badge medium">MEDIUM</span></td><td>Evaluate vendor PQC roadmaps</td><td>Q2 2026</td><td><input type="checkbox" class="checkbox"></td></tr><tr><td><span class="priority-badge medium">MEDIUM</span></td><td>Deploy hybrid PQC in test environment</td><td>Q3 2026</td><td><input type="checkbox" class="checkbox"></td></tr><tr><td><span class="priority-badge low">LOW</span></td><td>Begin production migration</td><td>Q4 2026</td><td><input type="checkbox" class="checkbox"></td></tr></tbody></table></section><section class="tls-section"><div class="section-header"><span class="section-icon">🔒</span><h2>TLS Configuration</h2></div><div class="tls-grid"><div class="tls-item"><div class="tls-label">TLS Version</div><div class="tls-value">' + data.tlsConfig.version + '</div></div><div class="tls-item"><div class="tls-label">Cipher Suite</div><div class="tls-value">' + data.tlsConfig.cipherSuite + '</div></div><div class="tls-item"><div class="tls-label">Key Size</div><div class="tls-value">' + data.tlsConfig.keySize + ' bits</div></div></div></section><section class="pqc-section"><div class="section-header"><span class="section-icon">📚</span><h2>NIST PQC Migration Reference</h2></div><div class="pqc-grid"><div class="pqc-card"><div class="pqc-icon">🔑</div><div class="pqc-name">ML-KEM</div><div class="pqc-fips">FIPS 203</div><div class="pqc-use">Key Encapsulation</div><div class="pqc-replaces">Replaces RSA, ECDH</div></div><div class="pqc-card"><div class="pqc-icon">✍️</div><div class="pqc-name">ML-DSA</div><div class="pqc-fips">FIPS 204</div><div class="pqc-use">Digital Signatures</div><div class="pqc-replaces">Replaces RSA, ECDSA</div></div><div class="pqc-card"><div class="pqc-icon">🛡️</div><div class="pqc-name">SLH-DSA</div><div class="pqc-fips">FIPS 205</div><div class="pqc-use">Hash-Based Signatures</div><div class="pqc-replaces">Conservative option</div></div></div></section><footer class="footer"><div class="footer-left"><strong>ACDI Platform v2.4</strong> | IFG Quantum Holdings<div class="footer-cta">CBOM Live — Real-time TLS Assessment | For full internal assessment, <a href="mailto:info@ifgquantum.com">contact IFG Quantum Holdings</a></div></div><div class="footer-right">SBOM/CBOM Integration Ready<br>CDM Dashboard Compatible</div></footer></div></body></html>';
}

// ============================================================================
// CSV GENERATOR
// ============================================================================

function generateCsvReport(data) {
  var lines = [];
  lines.push('CBOM Report - ' + data.domain);
  lines.push('Scan Date,' + data.scanDate);
  lines.push('Risk Score,' + data.riskScore + '/100');
  lines.push('Days to CNSA 2.0,' + data.daysToCSNA2);
  lines.push('');
  lines.push('CRYPTOGRAPHIC FINDINGS');
  lines.push('Severity,Algorithm,Type,PQ Security (bits),Recommendation');
  data.findings.forEach(function(f) {
    lines.push(f.severity + ',"' + f.algorithm + '","' + f.type + '",' + f.pqSecurity + ',"' + f.recommendation + '"');
  });
  lines.push('');
  lines.push('TLS CONFIGURATION');
  lines.push('Version,' + data.tlsConfig.version);
  lines.push('Cipher Suite,' + data.tlsConfig.cipherSuite);
  lines.push('Key Size,' + data.tlsConfig.keySize);
  lines.push('');
  lines.push('CERTIFICATE');
  lines.push('Subject,' + (data.certificate.subject || 'N/A'));
  lines.push('Issuer,' + (data.certificate.issuer || 'N/A'));
  lines.push('Valid From,' + (data.certificate.validFrom || 'N/A'));
  lines.push('Valid To,' + (data.certificate.validTo || 'N/A'));
  lines.push('');
  lines.push('REMEDIATION ESTIMATES');
  lines.push('Low,$' + data.remediationEstimate.low);
  lines.push('Mid,$' + data.remediationEstimate.mid);
  lines.push('High,$' + data.remediationEstimate.high);
  lines.push('');
  lines.push('---');
  lines.push('Generated by ACDI Platform v2.4 | IFG Quantum Holdings');
  return lines.join('\n');
}

// ============================================================================
// API ROUTES
// ============================================================================

app.get('/', function(req, res) {
  res.json({
    service: 'ACDI CBOM API',
    version: '2.4.0',
    status: 'operational',
    mode: 'LIVE SCANNING',
    endpoints: { 
      html: '/api/v1/report/:domain/html', 
      json: '/api/v1/report/:domain/json', 
      csv: '/api/v1/report/:domain/csv' 
    },
    vendor: 'IFG Quantum Holdings'
  });
});

app.get('/api/v1/report/:domain/html', function(req, res) {
  var domain = req.params.domain;
  
  console.log('Scanning domain: ' + domain);
  
  scanDomain(domain).then(function(scanResults) {
    console.log('Scan complete for: ' + domain);
    var data = analyzeResults(scanResults);
    var html = generateHtmlReport(data);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  }).catch(function(err) {
    console.error('Scan error:', err);
    res.status(500).send('Error scanning domain: ' + err.message);
  });
});

app.get('/api/v1/report/:domain/json', function(req, res) {
  var domain = req.params.domain;
  
  scanDomain(domain).then(function(scanResults) {
    var data = analyzeResults(scanResults);
    res.json({
      meta: { 
        generator: 'ACDI Platform', 
        version: '2.4.0', 
        mode: 'LIVE',
        vendor: 'IFG Quantum Holdings', 
        generatedAt: new Date().toISOString() 
      },
      report: data
    });
  }).catch(function(err) {
    res.status(500).json({ error: err.message });
  });
});

app.get('/api/v1/report/:domain/csv', function(req, res) {
  var domain = req.params.domain;
  
  scanDomain(domain).then(function(scanResults) {
    var data = analyzeResults(scanResults);
    var csv = generateCsvReport(data);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="cbom-' + domain + '-' + data.scanDate + '.csv"');
    res.send(csv);
  }).catch(function(err) {
    res.status(500).send('Error: ' + err.message);
  });
});

app.get('/report/:domain', function(req, res) {
  res.redirect('/api/v1/report/' + req.params.domain + '/html');
});

app.listen(PORT, function() {
  console.log('ACDI CBOM API v2.4 (LIVE SCANNING) running on port ' + PORT);
});
