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
        publicKeySize: null,
        fingerprint: null
      },
      protocols: [],
      error: null
    };

    var options = {
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 15000
    };

    var socket = tls.connect(options, function() {
      try {
        // Get TLS version and cipher
        var cipher = socket.getCipher();
        var protocol = socket.getProtocol();
        
        if (cipher) {
          results.tlsVersion = protocol || cipher.version;
          results.cipherSuite = cipher.name;
          results.keyExchange = extractKeyExchange(cipher.name, protocol);
          results.cipherStandardName = cipher.standardName || cipher.name;
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
            publicKeySize: extractKeySize(cert),
            fingerprint: cert.fingerprint || null,
            bits: cert.bits || null,
            asn1Curve: cert.asn1Curve || null
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

    socket.setTimeout(15000, function() {
      results.error = 'Connection timeout';
      socket.destroy();
      resolve(results);
    });
  });
}

function extractKeyExchange(cipherName, protocol) {
  if (!cipherName) return 'Unknown';
  
  // TLS 1.3 always uses ephemeral key exchange
  if (protocol === 'TLSv1.3') {
    if (cipherName.indexOf('AES_256') !== -1) return 'ECDHE-X25519';
    if (cipherName.indexOf('AES_128') !== -1) return 'ECDHE-P256';
    if (cipherName.indexOf('CHACHA20') !== -1) return 'ECDHE-X25519';
    return 'ECDHE';
  }
  
  // TLS 1.2 and below - parse cipher suite name
  if (cipherName.indexOf('ECDHE') !== -1) return 'ECDHE';
  if (cipherName.indexOf('DHE') !== -1 && cipherName.indexOf('ECDHE') === -1) return 'DHE';
  if (cipherName.indexOf('ECDH') !== -1 && cipherName.indexOf('ECDHE') === -1) return 'ECDH-Static';
  if (cipherName.indexOf('RSA') !== -1 && cipherName.indexOf('ECDHE') === -1 && cipherName.indexOf('DHE') === -1) return 'RSA-Static';
  
  return 'Unknown';
}

function extractSignatureAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  // Check asn1Curve for EC certificates
  if (cert.asn1Curve) {
    return 'ECDSA-' + cert.asn1Curve;
  }
  
  // Check bits for key type inference
  if (cert.bits) {
    // EC keys are typically 256, 384, or 521 bits
    if (cert.bits === 256) return 'ECDSA-P256';
    if (cert.bits === 384) return 'ECDSA-P384';
    if (cert.bits === 521) return 'ECDSA-P521';
    // RSA keys are typically 2048, 3072, or 4096 bits
    if (cert.bits >= 1024) return 'RSA-' + cert.bits;
  }
  
  return 'RSA/ECDSA';
}

function extractPublicKeyAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  if (cert.asn1Curve) return 'EC';
  
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
  if (subj.CN) parts.push(subj.CN);
  if (subj.O) parts.push(subj.O);
  
  return parts.length > 0 ? parts.join(' | ') : 'Unknown';
}

// ============================================================================
// ANALYZE SCAN RESULTS FOR PQC VULNERABILITIES - REALISTIC SCORING
// ============================================================================

function analyzeResults(scanResults) {
  var findings = [];
  var riskScore = 0;
  var criticalCount = 0;
  var highCount = 0;
  var mediumCount = 0;

  var keyEx = scanResults.keyExchange || 'Unknown';
  var cipherSuite = scanResults.cipherSuite || '';
  var tlsVersion = scanResults.tlsVersion || 'Unknown';
  var certAlg = scanResults.certificate.signatureAlgorithm || 'Unknown';
  var keySize = scanResults.certificate.publicKeySize;

  // =========================================================================
  // KEY EXCHANGE ANALYSIS - This is the most critical PQC vulnerability
  // =========================================================================
  
  if (keyEx.indexOf('ECDHE') !== -1 || keyEx === 'ECDHE') {
    // ECDHE is quantum-vulnerable but has forward secrecy
    var keyExDetail = keyEx;
    if (keyEx === 'ECDHE-X25519') {
      keyExDetail = 'ECDHE (X25519)';
      riskScore += 30; // X25519 is good classical security
    } else if (keyEx === 'ECDHE-P256') {
      keyExDetail = 'ECDHE (P-256)';
      riskScore += 32;
    } else {
      riskScore += 35;
    }
    
    findings.push({
      severity: 'CRITICAL',
      algorithm: keyExDetail,
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'Vulnerable to Harvest Now, Decrypt Later attacks'
    });
    criticalCount++;
    
  } else if (keyEx === 'DHE') {
    // DHE is slower and often uses smaller parameters
    riskScore += 40;
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'DHE Key Exchange',
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'Quantum-vulnerable; consider ECDHE for better performance'
    });
    criticalCount++;
    
  } else if (keyEx === 'RSA-Static') {
    // Static RSA key exchange - worst case, no forward secrecy
    riskScore += 50;
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'RSA Static Key Exchange',
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'No forward secrecy - all past traffic at risk if key compromised'
    });
    criticalCount++;
    
  } else if (keyEx === 'ECDH-Static') {
    riskScore += 45;
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'ECDH Static Key Exchange',
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'No forward secrecy - upgrade to ECDHE'
    });
    criticalCount++;
  }

  // =========================================================================
  // CERTIFICATE / SIGNATURE ALGORITHM ANALYSIS
  // =========================================================================
  
  if (certAlg.indexOf('ECDSA') !== -1) {
    var ecCurve = certAlg.replace('ECDSA-', '');
    var ecRisk = 20;
    var ecNote = null;
    
    if (ecCurve === 'P256' || ecCurve === 'prime256v1') {
      ecRisk = 18;
      ecNote = 'P-256 provides 128-bit classical security';
    } else if (ecCurve === 'P384') {
      ecRisk = 16;
      ecNote = 'P-384 provides 192-bit classical security';
    } else if (ecCurve === 'P521') {
      ecRisk = 14;
      ecNote = 'P-521 provides 256-bit classical security';
    }
    
    riskScore += ecRisk;
    findings.push({
      severity: 'HIGH',
      algorithm: 'ECDSA Certificate (' + ecCurve + ')',
      type: 'Digital Signature',
      pqSecurity: 0,
      recommendation: 'ML-DSA-65 (FIPS 204)',
      note: ecNote
    });
    highCount++;
    
  } else if (certAlg.indexOf('RSA') !== -1) {
    var rsaSize = keySize || 2048;
    var rsaRisk = 22;
    var rsaNote = null;
    
    if (rsaSize >= 4096) {
      rsaRisk = 18;
      rsaNote = 'RSA-4096 provides strong classical security';
    } else if (rsaSize >= 3072) {
      rsaRisk = 20;
      rsaNote = 'RSA-3072 meets current NIST recommendations';
    } else if (rsaSize >= 2048) {
      rsaRisk = 22;
      rsaNote = 'RSA-2048 minimum acceptable; upgrade recommended';
    } else {
      rsaRisk = 35;
      rsaNote = 'RSA key size below 2048 bits is critically weak';
      findings.push({
        severity: 'CRITICAL',
        algorithm: 'RSA-' + rsaSize + ' Certificate',
        type: 'Digital Signature',
        pqSecurity: 0,
        recommendation: 'Immediate upgrade required',
        note: rsaNote
      });
      criticalCount++;
      riskScore += rsaRisk;
    }
    
    if (rsaSize >= 2048) {
      riskScore += rsaRisk;
      findings.push({
        severity: 'HIGH',
        algorithm: 'RSA-' + rsaSize + ' Certificate',
        type: 'Digital Signature',
        pqSecurity: 0,
        recommendation: 'ML-DSA-65 (FIPS 204)',
        note: rsaNote
      });
      highCount++;
    }
  } else {
    // Unknown certificate type
    riskScore += 25;
    findings.push({
      severity: 'HIGH',
      algorithm: certAlg + ' Certificate',
      type: 'Digital Signature',
      pqSecurity: 0,
      recommendation: 'ML-DSA-65 (FIPS 204)',
      note: null
    });
    highCount++;
  }

  // =========================================================================
  // TLS VERSION ANALYSIS
  // =========================================================================
  
  if (tlsVersion === 'TLSv1.3') {
    // TLS 1.3 is best current practice - small bonus
    riskScore -= 5;
  } else if (tlsVersion === 'TLSv1.2') {
    // TLS 1.2 is acceptable
    riskScore += 3;
    mediumCount++;
  } else if (tlsVersion === 'TLSv1.1' || tlsVersion === 'TLSv1') {
    // Deprecated versions
    riskScore += 15;
    findings.push({
      severity: 'HIGH',
      algorithm: tlsVersion,
      type: 'Protocol Version',
      pqSecurity: 0,
      recommendation: 'Upgrade to TLS 1.3',
      note: 'Deprecated protocol with known vulnerabilities'
    });
    highCount++;
  }

  // =========================================================================
  // SYMMETRIC ENCRYPTION ANALYSIS - These are quantum-resistant
  // =========================================================================
  
  if (cipherSuite.indexOf('AES_256') !== -1 || cipherSuite.indexOf('AES256') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'AES-256-GCM',
      type: 'Symmetric Encryption',
      pqSecurity: 128,
      recommendation: 'Quantum-safe (Grover reduces to 128-bit)',
      note: 'No action required'
    });
  } else if (cipherSuite.indexOf('AES_128') !== -1 || cipherSuite.indexOf('AES128') !== -1) {
    riskScore += 5;
    findings.push({
      severity: 'MEDIUM',
      algorithm: 'AES-128-GCM',
      type: 'Symmetric Encryption',
      pqSecurity: 64,
      recommendation: 'Consider AES-256 for post-quantum security',
      note: 'Grover\'s algorithm reduces effective security to 64 bits'
    });
    mediumCount++;
  } else if (cipherSuite.indexOf('CHACHA20') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'ChaCha20-Poly1305',
      type: 'Symmetric Encryption',
      pqSecurity: 128,
      recommendation: 'Quantum-safe',
      note: 'Excellent choice for mobile/embedded'
    });
  } else if (cipherSuite.indexOf('3DES') !== -1 || cipherSuite.indexOf('DES') !== -1) {
    riskScore += 20;
    findings.push({
      severity: 'CRITICAL',
      algorithm: '3DES/DES',
      type: 'Symmetric Encryption',
      pqSecurity: 0,
      recommendation: 'Immediate upgrade to AES-256',
      note: 'Deprecated cipher with known weaknesses'
    });
    criticalCount++;
  }

  // =========================================================================
  // HASH FUNCTION ANALYSIS
  // =========================================================================
  
  if (cipherSuite.indexOf('SHA384') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'SHA-384',
      type: 'Hash Function (HMAC)',
      pqSecurity: 192,
      recommendation: 'Quantum-safe',
      note: 'Strong hash function'
    });
  } else if (cipherSuite.indexOf('SHA256') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'SHA-256',
      type: 'Hash Function (HMAC)',
      pqSecurity: 128,
      recommendation: 'Quantum-safe',
      note: 'Adequate for current use'
    });
  } else if (cipherSuite.indexOf('SHA1') !== -1 || cipherSuite.indexOf('SHA_') !== -1) {
    riskScore += 10;
    findings.push({
      severity: 'HIGH',
      algorithm: 'SHA-1',
      type: 'Hash Function',
      pqSecurity: 0,
      recommendation: 'Upgrade to SHA-256 or SHA-384',
      note: 'Deprecated - collision attacks demonstrated'
    });
    highCount++;
  }

  // =========================================================================
  // NORMALIZE RISK SCORE
  // =========================================================================
  
  // Ensure score is within bounds
  if (riskScore < 0) riskScore = 0;
  if (riskScore > 100) riskScore = 100;
  
  // Minimum score based on having any quantum-vulnerable crypto
  if (criticalCount > 0 && riskScore < 55) riskScore = 55 + (criticalCount * 5);
  if (highCount > 0 && riskScore < 45) riskScore = 45 + (highCount * 3);
  
  // Cap at 100
  if (riskScore > 100) riskScore = 100;

  // =========================================================================
  // CALCULATE COMPLIANCE AND REMEDIATION
  // =========================================================================

  var cnsa2Deadline = new Date('2026-12-31');
  var now = new Date();
  var daysToDeadline = Math.ceil((cnsa2Deadline - now) / (1000 * 60 * 60 * 24));

  // Determine compliance status based on findings
  var ombStatus = criticalCount > 0 || highCount > 0 ? 'NON-COMPLIANT' : 'PARTIAL';
  var cnsa2Status = criticalCount > 0 ? 'NON-COMPLIANT' : (highCount > 0 ? 'AT RISK' : 'PARTIAL');

  return {
    domain: scanResults.domain,
    scanDate: scanResults.scanDate,
    scanTimestamp: scanResults.scanTimestamp,
    daysToCSNA2: daysToDeadline,
    riskScore: riskScore,
    criticalCount: criticalCount,
    highCount: highCount,
    mediumCount: mediumCount,
    findings: findings,
    tlsConfig: {
      version: tlsVersion,
      cipherSuite: cipherSuite,
      keyExchange: keyEx,
      keySize: keySize || 'N/A'
    },
    certificate: scanResults.certificate,
    compliance: {
      ombM2302: { status: ombStatus, deadline: 'End of 2025' },
      cnsa2Software: { status: cnsa2Status, deadline: '2027' },
      cnsa2Full: { status: 'NON-COMPLIANT', deadline: '2033' },
      nistPqc: { status: 'NOT IMPLEMENTED', deadline: 'Ongoing' }
    },
    remediationEstimate: calculateRemediation(riskScore, criticalCount, highCount),
    error: scanResults.error
  };
}

function calculateRemediation(riskScore, criticalCount, highCount) {
  // Base costs scale with risk
  var baseMultiplier = riskScore / 50;
  
  var low = Math.round(20000 * baseMultiplier);
  var mid = Math.round(60000 * baseMultiplier);
  var high = Math.round(120000 * baseMultiplier);
  
  // Add per-issue costs
  low += criticalCount * 15000 + highCount * 8000;
  mid += criticalCount * 35000 + highCount * 20000;
  high += criticalCount * 75000 + highCount * 40000;
  
  // Round to nearest thousand
  low = Math.round(low / 1000) * 1000;
  mid = Math.round(mid / 1000) * 1000;
  high = Math.round(high / 1000) * 1000;
  
  // Minimum costs
  if (low < 15000) low = 15000;
  if (mid < 45000) mid = 45000;
  if (high < 100000) high = 100000;
  
  return { low: low, mid: mid, high: high };
}

// ============================================================================
// HTML REPORT GENERATOR
// ============================================================================

function generateHtmlReport(data) {
  var statusClass = data.riskScore >= 75 ? 'critical' : (data.riskScore >= 50 ? 'warning' : 'info');
  var statusText = data.riskScore >= 75 ? 'CRITICAL' : (data.riskScore >= 50 ? 'HIGH RISK' : 'MODERATE');
  var statusMessage = data.riskScore >= 75 ? 'Immediate action required' : (data.riskScore >= 50 ? 'Remediation recommended' : 'Monitor and plan migration');

  var findingsHtml = data.findings.map(function(f) {
    var sevClass = f.severity.toLowerCase();
    if (sevClass === 'medium') sevClass = 'warning';
    var securityClass = f.pqSecurity === 0 ? 'zero' : 'full';
    var securityIcon = f.pqSecurity === 0 ? '⚠️' : '✓';
    var recLabel = f.pqSecurity === 0 ? 'Replace With' : 'Status';
    var recValue = f.pqSecurity > 0 ? f.recommendation : f.recommendation;
    var recStyle = f.pqSecurity > 0 ? 'style="color: var(--accent-green);"' : '';
    var noteHtml = f.note ? '<div class="recommendation-note">' + f.note + '</div>' : '';
    
    return '<div class="finding-card"><span class="severity-badge ' + sevClass + '">' + f.severity + '</span><div class="finding-details"><h3>' + f.algorithm + '</h3><div class="type">' + f.type + '</div><span class="pq-security ' + securityClass + '">' + securityIcon + ' PQ Security: ' + f.pqSecurity + ' bits</span></div><div class="recommendation"><div class="recommendation-label">' + recLabel + '</div><div class="recommendation-value" ' + recStyle + '>' + recValue + '</div>' + noteHtml + '</div></div>';
  }).join('');

  var errorBanner = '';
  if (data.error) {
    errorBanner = '<div class="error-banner">⚠️ Scan Note: ' + data.error + '</div>';
  }

  var certInfo = '';
  if (data.certificate && data.certificate.subject) {
    certInfo = '<section class="cert-section"><div class="section-header"><span class="section-icon">📜</span><h2>Certificate Details</h2></div><div class="cert-grid"><div class="cert-item"><div class="cert-label">Subject</div><div class="cert-value">' + data.certificate.subject + '</div></div><div class="cert-item"><div class="cert-label">Issuer</div><div class="cert-value">' + data.certificate.issuer + '</div></div><div class="cert-item"><div class="cert-label">Valid From</div><div class="cert-value">' + (data.certificate.validFrom || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Valid To</div><div class="cert-value">' + (data.certificate.validTo || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Signature Algorithm</div><div class="cert-value">' + (data.certificate.signatureAlgorithm || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Public Key</div><div class="cert-value">' + (data.certificate.publicKeyAlgorithm || 'N/A') + ' ' + (data.certificate.publicKeySize || '') + '-bit</div></div></div></section>';
  }

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CBOM Report - ' + data.domain + '</title><style>@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap");:root{--bg-primary:#f8fafc;--bg-secondary:#f1f5f9;--bg-card:#ffffff;--bg-card-hover:#f8fafc;--text-primary:#0f172a;--text-secondary:#475569;--text-muted:#64748b;--accent-cyan:#0891b2;--accent-blue:#2563eb;--accent-green:#059669;--accent-yellow:#d97706;--accent-orange:#ea580c;--accent-red:#dc2626;--accent-purple:#7c3aed;--border-color:rgba(0,0,0,0.08);--glow-cyan:0 4px 12px rgba(8,145,178,0.15);--glow-red:0 4px 12px rgba(220,38,38,0.15)}*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;min-height:100vh}.container{max-width:1200px;margin:0 auto;padding:2rem}.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border-color)}.logo-section{display:flex;align-items:center;gap:1rem}.logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--accent-cyan) 0%,var(--accent-blue) 100%);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;box-shadow:var(--glow-cyan)}.logo-text h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;background:linear-gradient(135deg,var(--accent-blue) 0%,var(--accent-cyan) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.logo-text p{font-size:0.875rem;color:var(--text-muted)}.export-buttons{display:flex;gap:0.75rem;flex-wrap:wrap}.export-btn{padding:0.625rem 1rem;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);font-size:0.8125rem;font-weight:500;cursor:pointer;transition:all 0.2s ease;text-decoration:none;display:flex;align-items:center;gap:0.5rem}.export-btn:hover{background:var(--bg-card-hover);color:var(--text-primary);border-color:var(--accent-cyan)}.error-banner{background:rgba(251,191,36,0.15);border:1px solid rgba(251,191,36,0.3);border-radius:8px;padding:0.75rem 1rem;margin-bottom:1rem;font-size:0.875rem;color:var(--accent-yellow)}.status-banner{background:linear-gradient(135deg,rgba(239,68,68,0.15) 0%,rgba(239,68,68,0.05) 100%);border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:1rem 1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;box-shadow:var(--glow-red)}.status-banner.warning{background:linear-gradient(135deg,rgba(249,115,22,0.15) 0%,rgba(249,115,22,0.05) 100%);border-color:rgba(249,115,22,0.3);box-shadow:0 0 20px rgba(249,115,22,0.3)}.status-banner.info{background:linear-gradient(135deg,rgba(34,211,238,0.15) 0%,rgba(34,211,238,0.05) 100%);border-color:rgba(34,211,238,0.3);box-shadow:var(--glow-cyan)}.status-badge{background:var(--accent-red);color:white;padding:0.375rem 0.875rem;border-radius:6px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase}.status-badge.warning{background:var(--accent-orange);color:#fff}.status-badge.info{background:var(--accent-cyan);color:#fff}.status-text{flex:1}.status-text strong{color:var(--text-primary)}.status-text span{color:var(--text-secondary);font-size:0.875rem}.target-domain{font-family:"JetBrains Mono",monospace;background:var(--bg-card);padding:0.5rem 1rem;border-radius:8px;font-size:0.875rem;color:var(--accent-cyan);border:1px solid var(--border-color)}.scan-meta{font-size:0.75rem;color:var(--text-muted);display:flex;align-items:center;gap:0.5rem}.live-dot{width:8px;height:8px;background:var(--accent-green);border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.metrics-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1.25rem;margin-bottom:2rem}.metric-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.5rem;position:relative;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.05)}.metric-card::before{content:"";position:absolute;top:0;left:0;right:0;height:3px}.metric-card.critical::before{background:var(--accent-red)}.metric-card.warning::before{background:var(--accent-orange)}.metric-card.info::before{background:var(--accent-cyan)}.metric-card.success::before{background:var(--accent-green)}.metric-label{font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem}.metric-value{font-size:2.5rem;font-weight:800;line-height:1;margin-bottom:0.25rem}.metric-card.critical .metric-value{color:var(--accent-red)}.metric-card.warning .metric-value{color:var(--accent-orange)}.metric-card.info .metric-value{color:var(--accent-cyan)}.metric-card.success .metric-value{color:var(--accent-green)}.metric-suffix{font-size:1rem;color:var(--text-muted);font-weight:500}.metric-sub{font-size:0.8125rem;color:var(--text-secondary)}.metric-sub strong{color:var(--text-primary)}.risk-legend{display:flex;gap:0.5rem;margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border-color);flex-wrap:wrap}.legend-item{display:flex;align-items:center;gap:0.25rem;font-size:0.625rem;color:var(--text-muted)}.legend-dot{width:6px;height:6px;border-radius:50%}.legend-dot.critical{background:var(--accent-red)}.legend-dot.high{background:var(--accent-orange)}.legend-dot.medium{background:var(--accent-yellow)}.legend-dot.low{background:var(--accent-green)}.deadline-date{font-size:0.6875rem;color:var(--text-muted);margin-top:0.25rem;font-family:"JetBrains Mono",monospace}.section-header{display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;flex-wrap:wrap}.section-header h2{font-size:1.125rem;font-weight:700}.section-icon{font-size:1.25rem}.findings-section,.remediation-section,.compliance-section,.action-section,.tls-section,.pqc-section,.cert-section{margin-bottom:2rem}.findings-list{display:flex;flex-direction:column;gap:1rem}.finding-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;display:grid;grid-template-columns:auto 1fr auto;gap:1.25rem;align-items:center;transition:all 0.2s ease;box-shadow:0 1px 3px rgba(0,0,0,0.05)}.finding-card:hover{background:var(--bg-card-hover);border-color:rgba(255,255,255,0.12)}.severity-badge{padding:0.5rem 0.875rem;border-radius:8px;font-size:0.6875rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;min-width:80px;text-align:center}.severity-badge.critical{background:rgba(239,68,68,0.15);color:var(--accent-red);border:1px solid rgba(239,68,68,0.3)}.severity-badge.high{background:rgba(249,115,22,0.15);color:var(--accent-orange);border:1px solid rgba(249,115,22,0.3)}.severity-badge.medium,.severity-badge.warning{background:rgba(251,191,36,0.15);color:var(--accent-yellow);border:1px solid rgba(251,191,36,0.3)}.severity-badge.low{background:rgba(16,185,129,0.15);color:var(--accent-green);border:1px solid rgba(16,185,129,0.3)}.finding-details h3{font-size:1rem;font-weight:600;margin-bottom:0.25rem;font-family:"JetBrains Mono",monospace}.finding-details .type{font-size:0.8125rem;color:var(--text-muted);margin-bottom:0.5rem}.pq-security{display:inline-flex;align-items:center;gap:0.375rem;padding:0.25rem 0.625rem;background:var(--bg-secondary);border-radius:4px;font-size:0.75rem;font-family:"JetBrains Mono",monospace}.pq-security.zero{color:var(--accent-red)}.pq-security.full{color:var(--accent-green)}.recommendation{text-align:right}.recommendation-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem}.recommendation-value{font-size:0.875rem;color:var(--accent-cyan);font-family:"JetBrains Mono",monospace}.recommendation-note{font-size:0.6875rem;color:var(--text-muted);font-style:italic;margin-top:0.25rem}.remediation-card{background:linear-gradient(135deg,rgba(16,185,129,0.1) 0%,rgba(34,211,238,0.05) 100%);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:1.5rem}.vendor-neutral-badge{background:var(--accent-green);color:var(--bg-primary);padding:0.25rem 0.5rem;border-radius:4px;font-size:0.625rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em}.remediation-estimate{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem}.estimate-item{text-align:center;padding:1rem;background:var(--bg-card);border-radius:8px}.estimate-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.375rem}.estimate-value{font-size:1.25rem;font-weight:700;color:var(--text-primary)}.estimate-note{font-size:0.6875rem;color:var(--text-muted)}.remediation-note{font-size:0.8125rem;color:var(--text-secondary);padding-top:1rem;border-top:1px solid var(--border-color)}.remediation-note strong{color:var(--accent-green)}.compliance-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}.compliance-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.compliance-framework{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem}.compliance-name{font-size:0.9375rem;font-weight:600;margin-bottom:0.75rem}.compliance-status{font-size:1.5rem;margin-bottom:0.5rem}.compliance-deadline{font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem}.compliance-badge{display:inline-block;padding:0.25rem 0.625rem;border-radius:4px;font-size:0.6875rem;font-weight:600;text-transform:uppercase;letter-spacing:0.03em}.compliance-badge.non-compliant{background:rgba(239,68,68,0.15);color:var(--accent-red)}.compliance-badge.at-risk{background:rgba(249,115,22,0.15);color:var(--accent-orange)}.compliance-badge.partial{background:rgba(251,191,36,0.15);color:var(--accent-yellow)}.compliance-badge.not-implemented{background:rgba(107,114,128,0.15);color:var(--text-muted)}.action-table{width:100%;background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;overflow:hidden}.action-table th{background:var(--bg-secondary);padding:1rem 1.25rem;text-align:left;font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid var(--border-color)}.action-table td{padding:1rem 1.25rem;border-bottom:1px solid var(--border-color);font-size:0.875rem}.action-table tr:last-child td{border-bottom:none}.action-table tr:hover{background:var(--bg-card-hover)}.priority-badge{display:inline-block;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.6875rem;font-weight:600;text-transform:uppercase}.priority-badge.high{background:rgba(239,68,68,0.15);color:var(--accent-red)}.priority-badge.medium{background:rgba(251,191,36,0.15);color:var(--accent-yellow)}.priority-badge.low{background:rgba(16,185,129,0.15);color:var(--accent-green)}.checkbox{width:20px;height:20px;border:2px solid var(--border-color);border-radius:4px;cursor:pointer}.tls-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}.tls-item{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.tls-label{font-size:0.75rem;color:var(--text-muted);margin-bottom:0.5rem}.tls-value{font-size:1rem;font-weight:600;font-family:"JetBrains Mono",monospace;color:var(--accent-cyan);word-break:break-all}.cert-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}.cert-item{background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;padding:1rem}.cert-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem}.cert-value{font-size:0.875rem;color:var(--text-primary);word-break:break-all}.pqc-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.pqc-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.pqc-icon{font-size:2rem;margin-bottom:0.75rem}.pqc-name{font-size:1rem;font-weight:700;margin-bottom:0.25rem}.pqc-fips{font-size:0.75rem;color:var(--accent-cyan);font-family:"JetBrains Mono",monospace;margin-bottom:0.5rem}.pqc-use{font-size:0.8125rem;color:var(--text-secondary);margin-bottom:0.25rem}.pqc-replaces{font-size:0.6875rem;color:var(--text-muted)}.footer{border-top:1px solid var(--border-color);padding-top:1.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}.footer-left{font-size:0.875rem;color:var(--text-secondary)}.footer-left strong{color:var(--accent-cyan)}.footer-right{font-size:0.8125rem;color:var(--text-muted);text-align:right}.footer-cta{margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted)}.footer-cta a{color:var(--accent-cyan);text-decoration:none}.footer-cta a:hover{text-decoration:underline}@media print{.export-buttons{display:none}}@media(max-width:1024px){.metrics-grid{grid-template-columns:repeat(2,1fr)}.compliance-grid{grid-template-columns:repeat(2,1fr)}.tls-grid{grid-template-columns:repeat(2,1fr)}.remediation-estimate{grid-template-columns:1fr}.cert-grid{grid-template-columns:1fr}}@media(max-width:768px){.container{padding:1rem}.header{flex-direction:column;gap:1rem}.status-banner{flex-direction:column;text-align:center}.metrics-grid{grid-template-columns:1fr}.finding-card{grid-template-columns:1fr;text-align:center}.recommendation{text-align:center}.compliance-grid{grid-template-columns:1fr}.tls-grid{grid-template-columns:1fr}.pqc-grid{grid-template-columns:1fr}}</style></head><body><div class="container"><header class="header"><div class="logo-section"><div class="logo-icon">🔐</div><div class="logo-text"><h1>CBOM Live</h1><p>Cryptographic Bill of Materials</p></div></div><div class="export-buttons"><a href="/api/v1/report/' + data.domain + '/csv" class="export-btn">📊 CSV</a><a href="/api/v1/report/' + data.domain + '/json" class="export-btn">📄 JSON</a><button class="export-btn" onclick="window.print()">🖨️ PDF</button><span class="export-btn" style="cursor:default;opacity:0.7">📦 SBOM</span></div></header>' + errorBanner + '<div class="status-banner ' + statusClass + '"><span class="status-badge ' + statusClass + '">' + statusText + '</span><div class="status-text"><strong>' + statusMessage + '</strong><span> — Post-quantum cryptography migration required</span></div><div class="target-domain">' + data.domain + '</div><div class="scan-meta"><span class="live-dot"></span>Live Scan: ' + data.scanDate + '</div></div><div class="metrics-grid"><div class="metric-card ' + statusClass + '"><div class="metric-label">Risk Score</div><div class="metric-value">' + data.riskScore + '<span class="metric-suffix">/100</span></div><div class="metric-sub"><strong>' + statusText + '</strong></div><div class="risk-legend"><div class="legend-item"><span class="legend-dot critical"></span>75+ Critical</div><div class="legend-item"><span class="legend-dot high"></span>50-74 High</div><div class="legend-item"><span class="legend-dot medium"></span>25-49 Med</div><div class="legend-item"><span class="legend-dot low"></span>0-24 Low</div></div></div><div class="metric-card ' + (data.criticalCount > 0 ? 'critical' : 'success') + '"><div class="metric-label">Critical Issues</div><div class="metric-value">' + data.criticalCount + '</div><div class="metric-sub">' + (data.criticalCount > 0 ? 'Quantum-vulnerable' : 'None found') + '</div></div><div class="metric-card ' + (data.highCount > 0 ? 'warning' : 'success') + '"><div class="metric-label">High Risk</div><div class="metric-value">' + data.highCount + '</div><div class="metric-sub">' + (data.highCount > 0 ? 'Need attention' : 'None found') + '</div></div><div class="metric-card info"><div class="metric-label">CNSA 2.0 Deadline</div><div class="metric-value">' + data.daysToCSNA2 + '</div><div class="metric-sub">days remaining</div><div class="deadline-date">Dec 31, 2026</div></div></div><section class="findings-section"><div class="section-header"><span class="section-icon">🔍</span><h2>Cryptographic Findings</h2></div><div class="findings-list">' + findingsHtml + '</div></section><section class="remediation-section"><div class="section-header"><span class="section-icon">💰</span><h2>Estimated Remediation</h2><span class="vendor-neutral-badge">Vendor Neutral</span></div><div class="remediation-card"><div class="remediation-estimate"><div class="estimate-item"><div class="estimate-label">Low</div><div class="estimate-value">$' + data.remediationEstimate.low.toLocaleString() + '</div><div class="estimate-note">Basic migration</div></div><div class="estimate-item"><div class="estimate-label">Mid</div><div class="estimate-value">$' + data.remediationEstimate.mid.toLocaleString() + '</div><div class="estimate-note">Hybrid deployment</div></div><div class="estimate-item"><div class="estimate-label">High</div><div class="estimate-value">$' + data.remediationEstimate.high.toLocaleString() + '</div><div class="estimate-note">Full remediation</div></div></div><div class="remediation-note"><strong>Vendor-neutral assessment</strong> — IFG provides discovery only. Request competitive quotes through DIR contracts.</div></div></section>' + certInfo + '<section class="tls-section"><div class="section-header"><span class="section-icon">🔒</span><h2>TLS Configuration</h2></div><div class="tls-grid"><div class="tls-item"><div class="tls-label">Protocol</div><div class="tls-value">' + data.tlsConfig.version + '</div></div><div class="tls-item"><div class="tls-label">Key Exchange</div><div class="tls-value">' + data.tlsConfig.keyExchange + '</div></div><div class="tls-item"><div class="tls-label">Cipher Suite</div><div class="tls-value">' + data.tlsConfig.cipherSuite + '</div></div><div class="tls-item"><div class="tls-label">Key Size</div><div class="tls-value">' + data.tlsConfig.keySize + ' bits</div></div></div></section><section class="compliance-section"><div class="section-header"><span class="section-icon">📋</span><h2>Compliance Status</h2></div><div class="compliance-grid"><div class="compliance-card"><div class="compliance-framework">OMB M-23-02</div><div class="compliance-name">Crypto Inventory</div><div class="compliance-status">' + (data.compliance.ombM2302.status === 'NON-COMPLIANT' ? '🔴' : '🟡') + '</div><div class="compliance-deadline">Due: ' + data.compliance.ombM2302.deadline + '</div><span class="compliance-badge ' + data.compliance.ombM2302.status.toLowerCase().replace(' ','-').replace('_','-') + '">' + data.compliance.ombM2302.status.replace('_',' ') + '</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Software</div><div class="compliance-status">' + (data.compliance.cnsa2Software.status === 'NON-COMPLIANT' ? '🔴' : '🟡') + '</div><div class="compliance-deadline">Due: ' + data.compliance.cnsa2Software.deadline + '</div><span class="compliance-badge ' + data.compliance.cnsa2Software.status.toLowerCase().replace(' ','-').replace('_','-') + '">' + data.compliance.cnsa2Software.status.replace('_',' ') + '</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Full Migration</div><div class="compliance-status">🔴</div><div class="compliance-deadline">Due: ' + data.compliance.cnsa2Full.deadline + '</div><span class="compliance-badge non-compliant">Non-Compliant</span></div><div class="compliance-card"><div class="compliance-framework">NIST PQC</div><div class="compliance-name">FIPS 203/204/205</div><div class="compliance-status">⚪</div><div class="compliance-deadline">' + data.compliance.nistPqc.deadline + '</div><span class="compliance-badge not-implemented">Not Implemented</span></div></div></section><section class="pqc-section"><div class="section-header"><span class="section-icon">📚</span><h2>NIST PQC Standards</h2></div><div class="pqc-grid"><div class="pqc-card"><div class="pqc-icon">🔑</div><div class="pqc-name">ML-KEM</div><div class="pqc-fips">FIPS 203</div><div class="pqc-use">Key Encapsulation</div><div class="pqc-replaces">Replaces ECDHE, RSA-KEM</div></div><div class="pqc-card"><div class="pqc-icon">✍️</div><div class="pqc-name">ML-DSA</div><div class="pqc-fips">FIPS 204</div><div class="pqc-use">Digital Signatures</div><div class="pqc-replaces">Replaces RSA, ECDSA</div></div><div class="pqc-card"><div class="pqc-icon">🛡️</div><div class="pqc-name">SLH-DSA</div><div class="pqc-fips">FIPS 205</div><div class="pqc-use">Stateless Hash Signatures</div><div class="pqc-replaces">Conservative fallback</div></div></div></section><footer class="footer"><div class="footer-left"><strong>ACDI Platform v2.5</strong> | IFG Quantum Holdings<div class="footer-cta">Live TLS Assessment | <a href="mailto:info@ifgquantum.com">Contact for full internal scan</a></div></div><div class="footer-right">CBOM/SBOM Integration Ready<br>CDM Dashboard Compatible</div></footer></div></body></html>';
}

// ============================================================================
// CSV GENERATOR
// ============================================================================

function generateCsvReport(data) {
  var lines = [];
  lines.push('CBOM Live Report - ' + data.domain);
  lines.push('Generated,' + data.scanTimestamp);
  lines.push('Risk Score,' + data.riskScore + '/100');
  lines.push('Critical Issues,' + data.criticalCount);
  lines.push('High Risk Issues,' + data.highCount);
  lines.push('Days to CNSA 2.0,' + data.daysToCSNA2);
  lines.push('');
  lines.push('TLS CONFIGURATION');
  lines.push('Protocol,' + data.tlsConfig.version);
  lines.push('Key Exchange,' + data.tlsConfig.keyExchange);
  lines.push('Cipher Suite,' + data.tlsConfig.cipherSuite);
  lines.push('Key Size,' + data.tlsConfig.keySize);
  lines.push('');
  lines.push('CERTIFICATE');
  lines.push('Subject,"' + (data.certificate.subject || 'N/A') + '"');
  lines.push('Issuer,"' + (data.certificate.issuer || 'N/A') + '"');
  lines.push('Algorithm,' + (data.certificate.signatureAlgorithm || 'N/A'));
  lines.push('Valid From,' + (data.certificate.validFrom || 'N/A'));
  lines.push('Valid To,' + (data.certificate.validTo || 'N/A'));
  lines.push('');
  lines.push('CRYPTOGRAPHIC FINDINGS');
  lines.push('Severity,Algorithm,Type,PQ Security (bits),Recommendation');
  data.findings.forEach(function(f) {
    lines.push(f.severity + ',"' + f.algorithm + '","' + f.type + '",' + f.pqSecurity + ',"' + f.recommendation + '"');
  });
  lines.push('');
  lines.push('REMEDIATION ESTIMATES');
  lines.push('Low,$' + data.remediationEstimate.low);
  lines.push('Mid,$' + data.remediationEstimate.mid);
  lines.push('High,$' + data.remediationEstimate.high);
  lines.push('');
  lines.push('---');
  lines.push('ACDI Platform v2.5 | IFG Quantum Holdings');
  return lines.join('\n');
}

// ============================================================================
// API ROUTES
// ============================================================================

app.get('/', function(req, res) {
  res.json({
    service: 'ACDI CBOM API',
    version: '2.5.0',
    status: 'operational',
    mode: 'LIVE TLS SCANNING',
    endpoints: { 
      html: '/api/v1/report/:domain/html', 
      json: '/api/v1/report/:domain/json', 
      csv: '/api/v1/report/:domain/csv' 
    },
    vendor: 'IFG Quantum Holdings',
    note: 'Real-time cryptographic assessment'
  });
});

app.get('/api/v1/report/:domain/html', function(req, res) {
  var domain = req.params.domain;
  console.log('[SCAN] Starting: ' + domain);
  
  scanDomain(domain).then(function(scanResults) {
    console.log('[SCAN] Complete: ' + domain + ' | TLS: ' + scanResults.tlsVersion + ' | Cipher: ' + scanResults.cipherSuite);
    var data = analyzeResults(scanResults);
    console.log('[ANALYSIS] ' + domain + ' | Risk: ' + data.riskScore + ' | Critical: ' + data.criticalCount + ' | High: ' + data.highCount);
    var html = generateHtmlReport(data);
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  }).catch(function(err) {
    console.error('[ERROR] ' + domain + ': ' + err.message);
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
        version: '2.5.0', 
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
  console.log('===========================================');
  console.log('ACDI CBOM API v2.5 - LIVE SCANNING');
  console.log('Port: ' + PORT);
  console.log('Mode: Real-time TLS Assessment');
  console.log('===========================================');
});
