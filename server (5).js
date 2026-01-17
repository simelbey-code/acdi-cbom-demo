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
// ENHANCED TLS SCANNER WITH DEEP INSPECTION
// ============================================================================

function scanDomain(domain) {
  return new Promise(function(resolve, reject) {
    var results = {
      domain: domain,
      scanDate: new Date().toISOString().split('T')[0],
      scanTimestamp: new Date().toISOString(),
      tlsVersion: null,
      cipherSuite: null,
      cipherComponents: {
        keyExchange: null,
        authentication: null,
        encryption: null,
        mac: null
      },
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
        fingerprint: null,
        fingerprint256: null,
        san: null,
        chainLength: 0,
        chain: []
      },
      securityHeaders: {
        hsts: null,
        hstsMaxAge: null,
        hstsIncludeSubdomains: false,
        hstsPreload: false
      },
      protocols: [],
      error: null
    };

    // First, do HTTPS request to get security headers
    var headerReq = https.request({
      host: domain,
      port: 443,
      method: 'HEAD',
      rejectUnauthorized: false,
      timeout: 10000
    }, function(headerRes) {
      var hstsHeader = headerRes.headers['strict-transport-security'];
      if (hstsHeader) {
        results.securityHeaders.hsts = hstsHeader;
        var maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
        if (maxAgeMatch) {
          results.securityHeaders.hstsMaxAge = parseInt(maxAgeMatch[1]);
        }
        results.securityHeaders.hstsIncludeSubdomains = /includesubdomains/i.test(hstsHeader);
        results.securityHeaders.hstsPreload = /preload/i.test(hstsHeader);
      }
    });
    
    headerReq.on('error', function() {
      // Ignore header fetch errors, continue with TLS scan
    });
    
    headerReq.end();

    // TLS Connection for certificate and cipher analysis
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
          results.cipherStandardName = cipher.standardName || cipher.name;
          
          // Parse cipher suite components
          results.cipherComponents = parseCipherSuite(cipher.name, protocol);
          results.keyExchange = results.cipherComponents.keyExchange;
        }

        // Get full certificate chain
        var cert = socket.getPeerCertificate(true);
        if (cert) {
          // Parse certificate chain
          var chain = [];
          var currentCert = cert;
          var chainLength = 0;
          
          while (currentCert && chainLength < 5) {
            chain.push({
              subject: formatSubject(currentCert.subject),
              issuer: formatSubject(currentCert.issuer),
              validFrom: currentCert.valid_from,
              validTo: currentCert.valid_to,
              fingerprint256: currentCert.fingerprint256,
              isCA: currentCert.ca || false
            });
            chainLength++;
            
            if (currentCert.issuerCertificate && 
                currentCert.issuerCertificate !== currentCert &&
                currentCert.issuerCertificate.fingerprint256 !== currentCert.fingerprint256) {
              currentCert = currentCert.issuerCertificate;
            } else {
              break;
            }
          }
          
          // Parse SAN (Subject Alternative Names)
          var san = [];
          if (cert.subjectaltname) {
            san = cert.subjectaltname.split(', ').map(function(s) {
              return s.replace('DNS:', '');
            });
          }

          results.certificate = {
            subject: formatSubject(cert.subject),
            issuer: formatSubject(cert.issuer),
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            serialNumber: cert.serialNumber || null,
            signatureAlgorithm: parseSignatureAlgorithm(cert),
            publicKeyAlgorithm: extractPublicKeyAlgorithm(cert),
            publicKeySize: extractKeySize(cert),
            fingerprint: cert.fingerprint || null,
            fingerprint256: cert.fingerprint256 || null,
            san: san,
            chainLength: chainLength,
            chain: chain,
            bits: cert.bits || null,
            asn1Curve: cert.asn1Curve || null,
            nistCurve: mapToNistCurve(cert.asn1Curve)
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

function parseCipherSuite(cipherName, protocol) {
  var components = {
    keyExchange: 'Unknown',
    authentication: 'Unknown',
    encryption: 'Unknown',
    encryptionMode: 'Unknown',
    encryptionKeySize: null,
    mac: 'Unknown',
    prf: 'Unknown'
  };
  
  // TLS 1.3 cipher suites (simplified naming)
  if (protocol === 'TLSv1.3') {
    components.keyExchange = 'ECDHE (X25519/P-256)';
    components.authentication = 'Certificate';
    
    if (cipherName.indexOf('AES_256_GCM') !== -1) {
      components.encryption = 'AES-256-GCM';
      components.encryptionMode = 'GCM';
      components.encryptionKeySize = 256;
      components.mac = 'AEAD';
    } else if (cipherName.indexOf('AES_128_GCM') !== -1) {
      components.encryption = 'AES-128-GCM';
      components.encryptionMode = 'GCM';
      components.encryptionKeySize = 128;
      components.mac = 'AEAD';
    } else if (cipherName.indexOf('CHACHA20') !== -1) {
      components.encryption = 'ChaCha20-Poly1305';
      components.encryptionMode = 'AEAD';
      components.encryptionKeySize = 256;
      components.mac = 'Poly1305';
    }
    
    if (cipherName.indexOf('SHA384') !== -1) {
      components.prf = 'SHA-384';
    } else if (cipherName.indexOf('SHA256') !== -1) {
      components.prf = 'SHA-256';
    }
    
    return components;
  }
  
  // TLS 1.2 and below - parse the full cipher suite name
  // Format: TLS_<KeyExchange>_<Auth>_WITH_<Encryption>_<MAC>
  
  if (cipherName.indexOf('ECDHE') !== -1) {
    components.keyExchange = 'ECDHE';
    if (cipherName.indexOf('ECDSA') !== -1) {
      components.authentication = 'ECDSA';
    } else if (cipherName.indexOf('RSA') !== -1) {
      components.authentication = 'RSA';
    }
  } else if (cipherName.indexOf('DHE') !== -1) {
    components.keyExchange = 'DHE';
    if (cipherName.indexOf('RSA') !== -1) {
      components.authentication = 'RSA';
    }
  } else if (cipherName.indexOf('RSA') !== -1) {
    components.keyExchange = 'RSA';
    components.authentication = 'RSA';
  }
  
  // Encryption
  if (cipherName.indexOf('AES256') !== -1 || cipherName.indexOf('AES_256') !== -1) {
    components.encryptionKeySize = 256;
    if (cipherName.indexOf('GCM') !== -1) {
      components.encryption = 'AES-256-GCM';
      components.encryptionMode = 'GCM';
      components.mac = 'AEAD';
    } else if (cipherName.indexOf('CBC') !== -1) {
      components.encryption = 'AES-256-CBC';
      components.encryptionMode = 'CBC';
    } else {
      components.encryption = 'AES-256';
    }
  } else if (cipherName.indexOf('AES128') !== -1 || cipherName.indexOf('AES_128') !== -1) {
    components.encryptionKeySize = 128;
    if (cipherName.indexOf('GCM') !== -1) {
      components.encryption = 'AES-128-GCM';
      components.encryptionMode = 'GCM';
      components.mac = 'AEAD';
    } else {
      components.encryption = 'AES-128';
    }
  } else if (cipherName.indexOf('CHACHA20') !== -1) {
    components.encryption = 'ChaCha20-Poly1305';
    components.encryptionMode = 'AEAD';
    components.encryptionKeySize = 256;
    components.mac = 'Poly1305';
  } else if (cipherName.indexOf('3DES') !== -1) {
    components.encryption = '3DES';
    components.encryptionKeySize = 168;
  }
  
  // MAC (if not AEAD)
  if (components.mac === 'Unknown') {
    if (cipherName.indexOf('SHA384') !== -1) {
      components.mac = 'HMAC-SHA384';
    } else if (cipherName.indexOf('SHA256') !== -1) {
      components.mac = 'HMAC-SHA256';
    } else if (cipherName.indexOf('SHA') !== -1) {
      components.mac = 'HMAC-SHA1';
    }
  }
  
  return components;
}

function parseSignatureAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  // Check for EC curve
  if (cert.asn1Curve) {
    var nistName = mapToNistCurve(cert.asn1Curve);
    return 'ECDSA with ' + nistName;
  }
  
  // Check bits for RSA
  if (cert.bits && cert.bits >= 1024) {
    return 'RSA-' + cert.bits + ' with SHA-256';
  }
  
  return 'Unknown';
}

function mapToNistCurve(asn1Curve) {
  if (!asn1Curve) return null;
  
  var curveMap = {
    'prime256v1': 'P-256 (secp256r1)',
    'secp256r1': 'P-256 (secp256r1)',
    'secp384r1': 'P-384 (secp384r1)',
    'secp521r1': 'P-521 (secp521r1)',
    'X25519': 'Curve25519'
  };
  
  return curveMap[asn1Curve] || asn1Curve;
}

function extractPublicKeyAlgorithm(cert) {
  if (!cert) return 'Unknown';
  
  if (cert.asn1Curve) return 'EC (' + mapToNistCurve(cert.asn1Curve) + ')';
  
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
// ENHANCED ANALYSIS WITH CRYPTOGRAPHIC DEPTH
// ============================================================================

function analyzeResults(scanResults) {
  var findings = [];
  var riskScore = 0;
  var criticalCount = 0;
  var highCount = 0;
  var mediumCount = 0;

  var keyEx = scanResults.cipherComponents.keyExchange || scanResults.keyExchange || 'Unknown';
  var cipherSuite = scanResults.cipherSuite || '';
  var tlsVersion = scanResults.tlsVersion || 'Unknown';
  var certAlg = scanResults.certificate.signatureAlgorithm || 'Unknown';
  var keySize = scanResults.certificate.publicKeySize;
  var cipherComp = scanResults.cipherComponents;

  // =========================================================================
  // KEY EXCHANGE ANALYSIS - Primary HNDL (Harvest Now, Decrypt Later) Risk
  // =========================================================================
  
  var hndlRisk = 'HIGH';
  var hndlNote = '';
  
  if (keyEx.indexOf('ECDHE') !== -1 || keyEx.indexOf('X25519') !== -1) {
    var keyExDetail = keyEx;
    
    if (keyEx.indexOf('X25519') !== -1) {
      keyExDetail = 'ECDHE (X25519)';
      riskScore += 28;
      hndlNote = 'X25519 provides ~128-bit classical security. Vulnerable to Shor\'s algorithm on cryptographically relevant quantum computer (CRQC).';
    } else if (keyEx.indexOf('P-256') !== -1 || keyEx.indexOf('prime256v1') !== -1) {
      keyExDetail = 'ECDHE (P-256)';
      riskScore += 30;
      hndlNote = 'P-256 provides ~128-bit classical security. Vulnerable to quantum attack via Shor\'s algorithm.';
    } else if (keyEx.indexOf('P-384') !== -1) {
      keyExDetail = 'ECDHE (P-384)';
      riskScore += 28;
      hndlNote = 'P-384 provides ~192-bit classical security. Still vulnerable to Shor\'s algorithm.';
    } else {
      riskScore += 32;
      hndlNote = 'Elliptic curve key exchange provides forward secrecy but is quantum-vulnerable.';
    }
    
    findings.push({
      severity: 'CRITICAL',
      algorithm: keyExDetail,
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      pqSecurityNote: 'Shor\'s algorithm breaks ECDLP in polynomial time',
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: hndlNote,
      hndlRisk: 'HIGH',
      hndlExplanation: 'Data encrypted today can be stored and decrypted when CRQCs become available (estimated 2030-2035).'
    });
    criticalCount++;
    
  } else if (keyEx === 'DHE') {
    riskScore += 38;
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'DHE (Finite Field)',
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      pqSecurityNote: 'Shor\'s algorithm solves DLP efficiently',
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'Finite field Diffie-Hellman. Slower than ECDHE and equally quantum-vulnerable.',
      hndlRisk: 'HIGH',
      hndlExplanation: 'Vulnerable to harvest now, decrypt later attacks.'
    });
    criticalCount++;
    
  } else if (keyEx === 'RSA' || keyEx.indexOf('RSA') !== -1 && keyEx.indexOf('ECDHE') === -1) {
    riskScore += 48;
    findings.push({
      severity: 'CRITICAL',
      algorithm: 'RSA Key Transport',
      type: 'Key Exchange (' + tlsVersion + ')',
      pqSecurity: 0,
      pqSecurityNote: 'Shor\'s algorithm factors RSA modulus in polynomial time',
      recommendation: 'ML-KEM-768 (FIPS 203)',
      note: 'Static RSA key exchange provides NO forward secrecy. All past sessions compromised if private key is obtained.',
      hndlRisk: 'CRITICAL',
      hndlExplanation: 'Immediate priority: no forward secrecy means historical traffic is at risk even from classical attacks.'
    });
    criticalCount++;
  }

  // =========================================================================
  // CERTIFICATE / SIGNATURE ALGORITHM - Authentication Risk
  // =========================================================================
  
  if (certAlg.indexOf('ECDSA') !== -1) {
    var curveInfo = scanResults.certificate.nistCurve || 'P-256';
    var ecRisk = 18;
    var ecNote = '';
    
    if (curveInfo.indexOf('P-384') !== -1) {
      ecRisk = 16;
      ecNote = 'P-384 ECDSA provides 192-bit classical security.';
    } else if (curveInfo.indexOf('P-521') !== -1) {
      ecRisk = 14;
      ecNote = 'P-521 ECDSA provides 256-bit classical security.';
    } else {
      ecNote = 'P-256 ECDSA provides 128-bit classical security.';
    }
    
    riskScore += ecRisk;
    findings.push({
      severity: 'HIGH',
      algorithm: 'ECDSA Certificate (' + curveInfo + ')',
      type: 'Digital Signature / Authentication',
      pqSecurity: 0,
      pqSecurityNote: 'ECDSA broken by Shor\'s algorithm',
      recommendation: 'ML-DSA-65 (FIPS 204)',
      note: ecNote + ' Signature forgery possible with CRQC.',
      hndlRisk: 'MEDIUM',
      hndlExplanation: 'Signature algorithms are real-time risk (not HNDL) - threat emerges when CRQCs exist.'
    });
    highCount++;
    
  } else if (certAlg.indexOf('RSA') !== -1) {
    var rsaSize = keySize || 2048;
    var rsaRisk = 20;
    var rsaNote = '';
    
    if (rsaSize >= 4096) {
      rsaRisk = 16;
      rsaNote = 'RSA-4096 provides ~140-bit classical security.';
    } else if (rsaSize >= 3072) {
      rsaRisk = 18;
      rsaNote = 'RSA-3072 provides ~128-bit classical security (NIST minimum through 2030).';
    } else if (rsaSize >= 2048) {
      rsaRisk = 20;
      rsaNote = 'RSA-2048 provides ~112-bit classical security. Consider upgrade to 3072+.';
    } else {
      rsaRisk = 35;
      rsaNote = 'RSA key size below 2048 is critically weak even against classical attacks.';
    }
    
    riskScore += rsaRisk;
    findings.push({
      severity: rsaSize < 2048 ? 'CRITICAL' : 'HIGH',
      algorithm: 'RSA-' + rsaSize + ' Certificate',
      type: 'Digital Signature / Authentication',
      pqSecurity: 0,
      pqSecurityNote: 'RSA factoring solved by Shor\'s algorithm',
      recommendation: 'ML-DSA-65 (FIPS 204) or SLH-DSA-128 (FIPS 205)',
      note: rsaNote,
      hndlRisk: 'MEDIUM',
      hndlExplanation: 'Real-time authentication risk when CRQCs available.'
    });
    if (rsaSize < 2048) criticalCount++; else highCount++;
  }

  // =========================================================================
  // TLS VERSION ANALYSIS
  // =========================================================================
  
  if (tlsVersion === 'TLSv1.3') {
    riskScore -= 5;
    // No finding needed - TLS 1.3 is current best practice
  } else if (tlsVersion === 'TLSv1.2') {
    riskScore += 5;
    findings.push({
      severity: 'MEDIUM',
      algorithm: tlsVersion,
      type: 'Protocol Version',
      pqSecurity: null,
      recommendation: 'Upgrade to TLS 1.3',
      note: 'TLS 1.2 is acceptable but TLS 1.3 provides better security properties and performance.'
    });
    mediumCount++;
  } else if (tlsVersion === 'TLSv1.1' || tlsVersion === 'TLSv1' || tlsVersion === 'SSLv3') {
    riskScore += 20;
    findings.push({
      severity: 'CRITICAL',
      algorithm: tlsVersion,
      type: 'Protocol Version',
      pqSecurity: 0,
      recommendation: 'Immediate upgrade to TLS 1.3',
      note: 'Deprecated protocol with known vulnerabilities. POODLE, BEAST, and other attacks apply.'
    });
    criticalCount++;
  }

  // =========================================================================
  // SYMMETRIC ENCRYPTION - Quantum-Resistant Analysis
  // =========================================================================
  
  var encAlg = cipherComp.encryption || '';
  var encKeySize = cipherComp.encryptionKeySize || 0;
  
  if (encAlg.indexOf('AES-256') !== -1 || encAlg.indexOf('AES256') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: encAlg,
      type: 'Symmetric Encryption',
      pqSecurity: 128,
      pqSecurityNote: 'Grover\'s algorithm reduces security to √N, giving 128-bit post-quantum security',
      recommendation: 'No change required',
      note: 'AES-256 remains secure against quantum attacks. Grover provides only quadratic speedup.'
    });
  } else if (encAlg.indexOf('AES-128') !== -1 || encAlg.indexOf('AES128') !== -1) {
    riskScore += 5;
    findings.push({
      severity: 'MEDIUM',
      algorithm: encAlg,
      type: 'Symmetric Encryption',
      pqSecurity: 64,
      pqSecurityNote: 'Grover reduces to 64-bit security - below recommended minimum',
      recommendation: 'Upgrade to AES-256',
      note: 'AES-128 provides only 64-bit post-quantum security due to Grover\'s algorithm.'
    });
    mediumCount++;
  } else if (encAlg.indexOf('ChaCha20') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'ChaCha20-Poly1305',
      type: 'Symmetric Encryption (AEAD)',
      pqSecurity: 128,
      pqSecurityNote: '256-bit key provides 128-bit post-quantum security',
      recommendation: 'No change required',
      note: 'ChaCha20 is quantum-resistant. Excellent for mobile and embedded systems.'
    });
  } else if (encAlg.indexOf('3DES') !== -1) {
    riskScore += 25;
    findings.push({
      severity: 'CRITICAL',
      algorithm: '3DES',
      type: 'Symmetric Encryption',
      pqSecurity: 0,
      recommendation: 'Immediate upgrade to AES-256-GCM',
      note: 'Triple DES is deprecated. Sweet32 birthday attack and poor post-quantum security.'
    });
    criticalCount++;
  }

  // =========================================================================
  // MAC / HASH ANALYSIS
  // =========================================================================
  
  var mac = cipherComp.mac || '';
  
  if (mac === 'AEAD' || mac === 'Poly1305') {
    findings.push({
      severity: 'LOW',
      algorithm: cipherComp.encryptionMode === 'GCM' ? 'GCM (AEAD)' : mac,
      type: 'Authentication Tag',
      pqSecurity: 128,
      pqSecurityNote: 'AEAD modes provide strong authentication',
      recommendation: 'No change required',
      note: 'Authenticated encryption provides integrity and authenticity in single pass.'
    });
  } else if (mac.indexOf('SHA384') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'HMAC-SHA384',
      type: 'Message Authentication',
      pqSecurity: 192,
      recommendation: 'No change required',
      note: 'SHA-384 provides strong post-quantum security for HMAC.'
    });
  } else if (mac.indexOf('SHA256') !== -1) {
    findings.push({
      severity: 'LOW',
      algorithm: 'HMAC-SHA256',
      type: 'Message Authentication',
      pqSecurity: 128,
      recommendation: 'Acceptable',
      note: 'SHA-256 HMAC is quantum-resistant.'
    });
  } else if (mac.indexOf('SHA1') !== -1) {
    riskScore += 12;
    findings.push({
      severity: 'HIGH',
      algorithm: 'HMAC-SHA1',
      type: 'Message Authentication',
      pqSecurity: 80,
      recommendation: 'Upgrade to HMAC-SHA256 or AEAD cipher',
      note: 'SHA-1 is deprecated for signatures. HMAC-SHA1 is less critical but should be upgraded.'
    });
    highCount++;
  }

  // =========================================================================
  // HSTS ANALYSIS
  // =========================================================================
  
  if (scanResults.securityHeaders.hsts) {
    var hstsMaxAge = scanResults.securityHeaders.hstsMaxAge;
    var hstsNote = 'HSTS enabled';
    var hstsSeverity = 'LOW';
    
    if (hstsMaxAge < 31536000) { // Less than 1 year
      hstsSeverity = 'MEDIUM';
      hstsNote = 'HSTS max-age is less than recommended 1 year (31536000 seconds).';
      riskScore += 3;
      mediumCount++;
    }
    
    findings.push({
      severity: hstsSeverity,
      algorithm: 'HSTS',
      type: 'Transport Security Header',
      pqSecurity: null,
      recommendation: hstsMaxAge >= 31536000 ? 'Well configured' : 'Increase max-age to 31536000+',
      note: hstsNote + (scanResults.securityHeaders.hstsIncludeSubdomains ? ' includeSubDomains enabled.' : '') + (scanResults.securityHeaders.hstsPreload ? ' Preload enabled.' : '')
    });
  } else {
    riskScore += 8;
    findings.push({
      severity: 'MEDIUM',
      algorithm: 'HSTS',
      type: 'Transport Security Header',
      pqSecurity: null,
      recommendation: 'Enable HSTS with min 1 year max-age',
      note: 'HTTP Strict Transport Security not detected. Vulnerable to SSL stripping attacks.'
    });
    mediumCount++;
  }

  // =========================================================================
  // CERTIFICATE CHAIN ANALYSIS
  // =========================================================================
  
  var chainLen = scanResults.certificate.chainLength || 0;
  if (chainLen > 0) {
    var chainNote = chainLen + '-certificate chain: ';
    if (chainLen === 1) {
      chainNote = 'Single certificate (self-signed or incomplete chain)';
      riskScore += 5;
    } else if (chainLen === 2) {
      chainNote = 'Leaf → Root (missing intermediate)';
    } else if (chainLen === 3) {
      chainNote = 'Leaf → Intermediate → Root (standard chain)';
    } else {
      chainNote = chainLen + ' certificates in chain';
    }
  }

  // =========================================================================
  // NORMALIZE RISK SCORE
  // =========================================================================
  
  if (riskScore < 0) riskScore = 0;
  if (riskScore > 100) riskScore = 100;
  
  // Minimum scores based on quantum vulnerability
  if (criticalCount > 0 && riskScore < 50) riskScore = 50 + (criticalCount * 5);
  if (highCount > 0 && criticalCount === 0 && riskScore < 40) riskScore = 40 + (highCount * 3);
  
  if (riskScore > 100) riskScore = 100;

  // =========================================================================
  // COMPLIANCE MAPPING
  // =========================================================================

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
    mediumCount: mediumCount,
    findings: findings,
    tlsConfig: {
      version: tlsVersion,
      cipherSuite: cipherSuite,
      keyExchange: keyEx,
      authentication: cipherComp.authentication,
      encryption: cipherComp.encryption,
      encryptionKeySize: cipherComp.encryptionKeySize,
      mac: cipherComp.mac,
      keySize: keySize || 'N/A'
    },
    certificate: scanResults.certificate,
    securityHeaders: scanResults.securityHeaders,
    compliance: {
      ombM2302: { status: 'NON-COMPLIANT', deadline: 'Dec 2025', note: 'Cryptographic inventory required' },
      cnsa2Software: { status: criticalCount > 0 ? 'NON-COMPLIANT' : 'AT RISK', deadline: '2027', note: 'Software/firmware must use PQC' },
      cnsa2Full: { status: 'NON-COMPLIANT', deadline: '2033', note: 'All systems fully migrated' },
      nistPqc: { status: 'NOT IMPLEMENTED', deadline: 'Ongoing', note: 'FIPS 203, 204, 205 adoption' },
      fips1403: { status: keySize >= 2048 ? 'PARTIAL' : 'NON-COMPLIANT', deadline: 'Active', note: 'Cryptographic module validation' }
    },
    remediationEstimate: calculateRemediation(riskScore, criticalCount, highCount),
    error: scanResults.error
  };
}

function calculateRemediation(riskScore, criticalCount, highCount) {
  // Per-endpoint estimates based on risk and findings
  var baseMultiplier = riskScore / 50;
  
  var low = Math.round(25000 * baseMultiplier);
  var mid = Math.round(75000 * baseMultiplier);
  var high = Math.round(150000 * baseMultiplier);
  
  low += criticalCount * 12000 + highCount * 6000;
  mid += criticalCount * 30000 + highCount * 15000;
  high += criticalCount * 60000 + highCount * 30000;
  
  low = Math.round(low / 5000) * 5000;
  mid = Math.round(mid / 5000) * 5000;
  high = Math.round(high / 5000) * 5000;
  
  if (low < 25000) low = 25000;
  if (mid < 75000) mid = 75000;
  if (high < 150000) high = 150000;
  
  return { 
    low: low, 
    mid: mid, 
    high: high,
    scope: 'per-endpoint',
    departmentLow: low * 10,
    departmentMid: mid * 10,
    departmentHigh: high * 10,
    enterpriseLow: low * 50,
    enterpriseMid: mid * 50,
    enterpriseHigh: high * 50
  };
}

// ============================================================================
// ENHANCED HTML REPORT WITH CRYPTOGRAPHIC DETAILS
// ============================================================================

function generateHtmlReport(data) {
  var statusClass = data.riskScore >= 75 ? 'critical' : (data.riskScore >= 50 ? 'warning' : 'info');
  var statusText = data.riskScore >= 75 ? 'CRITICAL' : (data.riskScore >= 50 ? 'HIGH RISK' : 'MODERATE');
  var statusMessage = data.riskScore >= 75 ? 'Immediate action required' : (data.riskScore >= 50 ? 'Remediation recommended' : 'Monitor and plan migration');

  var findingsHtml = data.findings.map(function(f) {
    var sevClass = f.severity.toLowerCase();
    if (sevClass === 'medium') sevClass = 'warning';
    var securityClass = f.pqSecurity === 0 ? 'zero' : (f.pqSecurity === null ? 'na' : 'full');
    var securityIcon = f.pqSecurity === 0 ? '⚠️' : (f.pqSecurity === null ? '➖' : '✓');
    var pqText = f.pqSecurity === null ? 'N/A' : f.pqSecurity + ' bits';
    var recLabel = f.pqSecurity === 0 || f.pqSecurity === null ? (f.recommendation.indexOf('No change') !== -1 ? 'Status' : 'Replace With') : 'Status';
    var recStyle = f.pqSecurity > 0 ? 'style="color: var(--accent-green);"' : '';
    var noteHtml = f.note ? '<div class="recommendation-note">' + f.note + '</div>' : '';
    var pqNoteHtml = f.pqSecurityNote ? '<div class="pq-note">' + f.pqSecurityNote + '</div>' : '';
    var hndlHtml = f.hndlRisk ? '<div class="hndl-badge hndl-' + f.hndlRisk.toLowerCase() + '">HNDL Risk: ' + f.hndlRisk + '</div>' : '';
    
    return '<div class="finding-card"><div class="finding-left"><span class="severity-badge ' + sevClass + '">' + f.severity + '</span>' + hndlHtml + '</div><div class="finding-details"><h3>' + f.algorithm + '</h3><div class="type">' + f.type + '</div><span class="pq-security ' + securityClass + '">' + securityIcon + ' PQ Security: ' + pqText + '</span>' + pqNoteHtml + '</div><div class="recommendation"><div class="recommendation-label">' + recLabel + '</div><div class="recommendation-value" ' + recStyle + '>' + f.recommendation + '</div>' + noteHtml + '</div></div>';
  }).join('');

  var errorBanner = '';
  if (data.error) {
    errorBanner = '<div class="error-banner">⚠️ Scan Note: ' + data.error + '</div>';
  }

  // Certificate chain visualization
  var chainHtml = '';
  if (data.certificate.chain && data.certificate.chain.length > 0) {
    chainHtml = '<div class="chain-section"><div class="chain-title">Certificate Chain (' + data.certificate.chainLength + ' certificates)</div><div class="chain-viz">';
    data.certificate.chain.forEach(function(cert, i) {
      var certType = i === 0 ? 'Leaf' : (i === data.certificate.chain.length - 1 ? 'Root' : 'Intermediate');
      chainHtml += '<div class="chain-cert"><div class="chain-cert-type">' + certType + '</div><div class="chain-cert-subject">' + cert.subject + '</div><div class="chain-cert-issuer">Issued by: ' + cert.issuer + '</div></div>';
      if (i < data.certificate.chain.length - 1) {
        chainHtml += '<div class="chain-arrow">↓</div>';
      }
    });
    chainHtml += '</div></div>';
  }

  // HSTS status
  var hstsHtml = '';
  if (data.securityHeaders) {
    var hstsStatus = data.securityHeaders.hsts ? '✓ Enabled' : '✗ Not Detected';
    var hstsClass = data.securityHeaders.hsts ? 'enabled' : 'disabled';
    hstsHtml = '<div class="tls-item"><div class="tls-label">HSTS</div><div class="tls-value ' + hstsClass + '">' + hstsStatus + '</div></div>';
  }

  // Cipher breakdown
  var cipherBreakdownHtml = '';
  if (data.tlsConfig.encryption) {
    cipherBreakdownHtml = '<div class="cipher-breakdown"><div class="cipher-title">Cipher Suite Breakdown</div><div class="cipher-grid"><div class="cipher-item"><span class="cipher-label">Key Exchange</span><span class="cipher-value pq-vulnerable">' + data.tlsConfig.keyExchange + '</span><span class="cipher-pq">PQ: Vulnerable</span></div><div class="cipher-item"><span class="cipher-label">Authentication</span><span class="cipher-value pq-vulnerable">' + (data.tlsConfig.authentication || 'Certificate') + '</span><span class="cipher-pq">PQ: Vulnerable</span></div><div class="cipher-item"><span class="cipher-label">Encryption</span><span class="cipher-value pq-safe">' + data.tlsConfig.encryption + '</span><span class="cipher-pq">PQ: ' + (data.tlsConfig.encryptionKeySize >= 256 ? 'Safe (128-bit)' : 'Marginal (64-bit)') + '</span></div><div class="cipher-item"><span class="cipher-label">MAC</span><span class="cipher-value pq-safe">' + data.tlsConfig.mac + '</span><span class="cipher-pq">PQ: Safe</span></div></div></div>';
  }

  var certInfo = '';
  if (data.certificate && data.certificate.subject) {
    certInfo = '<section class="cert-section"><div class="section-header"><span class="section-icon">📜</span><h2>Certificate Details</h2></div><div class="cert-grid"><div class="cert-item"><div class="cert-label">Subject</div><div class="cert-value">' + data.certificate.subject + '</div></div><div class="cert-item"><div class="cert-label">Issuer</div><div class="cert-value">' + data.certificate.issuer + '</div></div><div class="cert-item"><div class="cert-label">Signature Algorithm</div><div class="cert-value">' + (data.certificate.signatureAlgorithm || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Public Key</div><div class="cert-value">' + (data.certificate.publicKeyAlgorithm || 'N/A') + ' ' + (data.certificate.publicKeySize || '') + '-bit</div></div><div class="cert-item"><div class="cert-label">Valid From</div><div class="cert-value">' + (data.certificate.validFrom || 'N/A') + '</div></div><div class="cert-item"><div class="cert-label">Valid To</div><div class="cert-value">' + (data.certificate.validTo || 'N/A') + '</div></div></div>' + chainHtml + '</section>';
  }

  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CBOM Report - ' + data.domain + '</title><style>@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700;800&display=swap");:root{--bg-primary:#f8fafc;--bg-secondary:#f1f5f9;--bg-card:#ffffff;--bg-card-hover:#f8fafc;--text-primary:#0f172a;--text-secondary:#475569;--text-muted:#64748b;--accent-cyan:#0891b2;--accent-blue:#2563eb;--accent-green:#059669;--accent-yellow:#d97706;--accent-orange:#ea580c;--accent-red:#dc2626;--accent-purple:#7c3aed;--border-color:rgba(0,0,0,0.08);--glow-cyan:0 4px 12px rgba(8,145,178,0.15);--glow-red:0 4px 12px rgba(220,38,38,0.15)}*{margin:0;padding:0;box-sizing:border-box}body{font-family:"Inter",-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;min-height:100vh}.container{max-width:1280px;margin:0 auto;padding:2rem}.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:2rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border-color)}.logo-section{display:flex;align-items:center;gap:1rem}.logo-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--accent-cyan) 0%,var(--accent-blue) 100%);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;box-shadow:var(--glow-cyan)}.logo-text h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;background:linear-gradient(135deg,var(--accent-blue) 0%,var(--accent-cyan) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.logo-text p{font-size:0.875rem;color:var(--text-muted)}.export-buttons{display:flex;gap:0.75rem;flex-wrap:wrap}.export-btn{padding:0.625rem 1rem;background:var(--bg-card);border:1px solid var(--border-color);border-radius:8px;color:var(--text-secondary);font-size:0.8125rem;font-weight:500;cursor:pointer;transition:all 0.2s ease;text-decoration:none;display:flex;align-items:center;gap:0.5rem}.export-btn:hover{background:var(--bg-card-hover);color:var(--text-primary);border-color:var(--accent-cyan)}.error-banner{background:rgba(217,119,6,0.1);border:1px solid rgba(217,119,6,0.3);border-radius:8px;padding:0.75rem 1rem;margin-bottom:1rem;font-size:0.875rem;color:var(--accent-yellow)}.status-banner{background:linear-gradient(135deg,rgba(220,38,38,0.08) 0%,rgba(220,38,38,0.03) 100%);border:1px solid rgba(220,38,38,0.2);border-radius:12px;padding:1rem 1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}.status-banner.warning{background:linear-gradient(135deg,rgba(234,88,12,0.08) 0%,rgba(234,88,12,0.03) 100%);border-color:rgba(234,88,12,0.2)}.status-banner.info{background:linear-gradient(135deg,rgba(8,145,178,0.08) 0%,rgba(8,145,178,0.03) 100%);border-color:rgba(8,145,178,0.2)}.status-badge{background:var(--accent-red);color:white;padding:0.375rem 0.875rem;border-radius:6px;font-size:0.75rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase}.status-badge.warning{background:var(--accent-orange);color:#fff}.status-badge.info{background:var(--accent-cyan);color:#fff}.status-text{flex:1}.status-text strong{color:var(--text-primary)}.status-text span{color:var(--text-secondary);font-size:0.875rem}.target-domain{font-family:"JetBrains Mono",monospace;background:var(--bg-card);padding:0.5rem 1rem;border-radius:8px;font-size:0.875rem;color:var(--accent-blue);border:1px solid var(--border-color);font-weight:600}.scan-meta{font-size:0.75rem;color:var(--text-muted);display:flex;align-items:center;gap:0.5rem}.live-dot{width:8px;height:8px;background:var(--accent-green);border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.metrics-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1.25rem;margin-bottom:2rem}.metric-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.5rem;position:relative;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.05)}.metric-card::before{content:"";position:absolute;top:0;left:0;right:0;height:3px}.metric-card.critical::before{background:var(--accent-red)}.metric-card.warning::before{background:var(--accent-orange)}.metric-card.info::before{background:var(--accent-cyan)}.metric-card.success::before{background:var(--accent-green)}.metric-label{font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem}.metric-value{font-size:2.5rem;font-weight:800;line-height:1;margin-bottom:0.25rem}.metric-card.critical .metric-value{color:var(--accent-red)}.metric-card.warning .metric-value{color:var(--accent-orange)}.metric-card.info .metric-value{color:var(--accent-cyan)}.metric-card.success .metric-value{color:var(--accent-green)}.metric-suffix{font-size:1rem;color:var(--text-muted);font-weight:500}.metric-sub{font-size:0.8125rem;color:var(--text-secondary)}.metric-sub strong{color:var(--text-primary)}.risk-legend{display:flex;gap:0.5rem;margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border-color);flex-wrap:wrap}.legend-item{display:flex;align-items:center;gap:0.25rem;font-size:0.625rem;color:var(--text-muted)}.legend-dot{width:6px;height:6px;border-radius:50%}.legend-dot.critical{background:var(--accent-red)}.legend-dot.high{background:var(--accent-orange)}.legend-dot.medium{background:var(--accent-yellow)}.legend-dot.low{background:var(--accent-green)}.deadline-date{font-size:0.6875rem;color:var(--text-muted);margin-top:0.25rem;font-family:"JetBrains Mono",monospace}.section-header{display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;flex-wrap:wrap}.section-header h2{font-size:1.125rem;font-weight:700}.section-icon{font-size:1.25rem}.findings-section,.remediation-section,.compliance-section,.action-section,.tls-section,.pqc-section,.cert-section{margin-bottom:2rem}.findings-list{display:flex;flex-direction:column;gap:1rem}.finding-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;display:grid;grid-template-columns:auto 1fr auto;gap:1.25rem;align-items:start;transition:all 0.2s ease;box-shadow:0 1px 3px rgba(0,0,0,0.05)}.finding-card:hover{border-color:rgba(0,0,0,0.15)}.finding-left{display:flex;flex-direction:column;gap:0.5rem;align-items:center}.severity-badge{padding:0.5rem 0.875rem;border-radius:8px;font-size:0.6875rem;font-weight:700;letter-spacing:0.05em;text-transform:uppercase;min-width:80px;text-align:center}.severity-badge.critical{background:rgba(220,38,38,0.1);color:var(--accent-red);border:1px solid rgba(220,38,38,0.2)}.severity-badge.high{background:rgba(234,88,12,0.1);color:var(--accent-orange);border:1px solid rgba(234,88,12,0.2)}.severity-badge.medium,.severity-badge.warning{background:rgba(217,119,6,0.1);color:var(--accent-yellow);border:1px solid rgba(217,119,6,0.2)}.severity-badge.low{background:rgba(5,150,105,0.1);color:var(--accent-green);border:1px solid rgba(5,150,105,0.2)}.hndl-badge{font-size:0.5625rem;padding:0.25rem 0.5rem;border-radius:4px;font-weight:600;text-transform:uppercase}.hndl-high,.hndl-critical{background:rgba(220,38,38,0.1);color:var(--accent-red)}.hndl-medium{background:rgba(217,119,6,0.1);color:var(--accent-yellow)}.hndl-low{background:rgba(5,150,105,0.1);color:var(--accent-green)}.finding-details h3{font-size:1rem;font-weight:600;margin-bottom:0.25rem;font-family:"JetBrains Mono",monospace;color:var(--text-primary)}.finding-details .type{font-size:0.8125rem;color:var(--text-muted);margin-bottom:0.5rem}.pq-security{display:inline-flex;align-items:center;gap:0.375rem;padding:0.25rem 0.625rem;background:var(--bg-secondary);border-radius:4px;font-size:0.75rem;font-family:"JetBrains Mono",monospace}.pq-security.zero{color:var(--accent-red);background:rgba(220,38,38,0.08)}.pq-security.full{color:var(--accent-green);background:rgba(5,150,105,0.08)}.pq-security.na{color:var(--text-muted)}.pq-note{font-size:0.6875rem;color:var(--text-muted);margin-top:0.375rem;font-style:italic}.recommendation{text-align:right}.recommendation-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.25rem}.recommendation-value{font-size:0.875rem;color:var(--accent-blue);font-family:"JetBrains Mono",monospace;font-weight:500}.recommendation-note{font-size:0.6875rem;color:var(--text-muted);margin-top:0.375rem;max-width:280px}.cipher-breakdown{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;margin-bottom:1.5rem}.cipher-title{font-size:0.875rem;font-weight:600;margin-bottom:1rem;color:var(--text-primary)}.cipher-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}.cipher-item{text-align:center;padding:0.75rem;background:var(--bg-secondary);border-radius:8px}.cipher-label{display:block;font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.375rem}.cipher-value{display:block;font-size:0.8125rem;font-family:"JetBrains Mono",monospace;font-weight:600;margin-bottom:0.25rem}.cipher-value.pq-vulnerable{color:var(--accent-red)}.cipher-value.pq-safe{color:var(--accent-green)}.cipher-pq{display:block;font-size:0.625rem;color:var(--text-muted)}.remediation-card{background:linear-gradient(135deg,rgba(5,150,105,0.05) 0%,rgba(8,145,178,0.03) 100%);border:1px solid rgba(5,150,105,0.2);border-radius:12px;padding:1.5rem}.vendor-neutral-badge{background:var(--accent-green);color:white;padding:0.25rem 0.5rem;border-radius:4px;font-size:0.625rem;font-weight:700;text-transform:uppercase;letter-spacing:0.05em}.remediation-estimate{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1rem}.estimate-item{text-align:center;padding:1rem;background:var(--bg-card);border-radius:8px;border:1px solid var(--border-color)}.estimate-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.375rem}.estimate-value{font-size:1.25rem;font-weight:700;color:var(--text-primary)}.estimate-note{font-size:0.6875rem;color:var(--text-muted)}.remediation-note{font-size:0.8125rem;color:var(--text-secondary);padding-top:1rem;border-top:1px solid var(--border-color)}.remediation-note strong{color:var(--accent-green)}.scope-label{font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:1rem}.scope-divider{height:1px;background:var(--border-color);margin:1.25rem 0}.enterprise-note{display:flex;flex-direction:column;gap:0.5rem;margin-bottom:1rem}.enterprise-row{display:flex;justify-content:space-between;align-items:center;font-size:0.8125rem}.enterprise-label{color:var(--text-secondary)}.enterprise-range{font-family:"JetBrains Mono",monospace;font-weight:600;color:var(--text-primary)}.compliance-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem}.compliance-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1rem;text-align:center}.compliance-framework{font-size:0.625rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.375rem}.compliance-name{font-size:0.8125rem;font-weight:600;margin-bottom:0.5rem}.compliance-status{font-size:1.25rem;margin-bottom:0.375rem}.compliance-deadline{font-size:0.6875rem;color:var(--text-muted);margin-bottom:0.375rem}.compliance-badge{display:inline-block;padding:0.2rem 0.5rem;border-radius:4px;font-size:0.625rem;font-weight:600;text-transform:uppercase}.compliance-badge.non-compliant{background:rgba(220,38,38,0.1);color:var(--accent-red)}.compliance-badge.at-risk{background:rgba(234,88,12,0.1);color:var(--accent-orange)}.compliance-badge.partial{background:rgba(217,119,6,0.1);color:var(--accent-yellow)}.compliance-badge.not-implemented{background:rgba(100,116,139,0.1);color:var(--text-muted)}.tls-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem}.tls-item{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1rem;text-align:center}.tls-label{font-size:0.6875rem;color:var(--text-muted);margin-bottom:0.375rem;text-transform:uppercase}.tls-value{font-size:0.875rem;font-weight:600;font-family:"JetBrains Mono",monospace;color:var(--accent-blue)}.tls-value.enabled{color:var(--accent-green)}.tls-value.disabled{color:var(--accent-red)}.cert-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.cert-item{background:var(--bg-secondary);border-radius:8px;padding:1rem}.cert-label{font-size:0.6875rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem}.cert-value{font-size:0.8125rem;color:var(--text-primary);word-break:break-all}.chain-section{margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--border-color)}.chain-title{font-size:0.875rem;font-weight:600;margin-bottom:1rem}.chain-viz{display:flex;flex-direction:column;align-items:center;gap:0.5rem}.chain-cert{background:var(--bg-secondary);border-radius:8px;padding:0.75rem 1rem;text-align:center;min-width:300px}.chain-cert-type{font-size:0.625rem;color:var(--text-muted);text-transform:uppercase;margin-bottom:0.25rem}.chain-cert-subject{font-size:0.8125rem;font-weight:600;color:var(--text-primary)}.chain-cert-issuer{font-size:0.6875rem;color:var(--text-muted)}.chain-arrow{color:var(--text-muted);font-size:1rem}.pqc-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.pqc-card{background:var(--bg-card);border:1px solid var(--border-color);border-radius:12px;padding:1.25rem;text-align:center}.pqc-icon{font-size:2rem;margin-bottom:0.75rem}.pqc-name{font-size:1rem;font-weight:700;margin-bottom:0.25rem}.pqc-fips{font-size:0.75rem;color:var(--accent-blue);font-family:"JetBrains Mono",monospace;margin-bottom:0.5rem}.pqc-use{font-size:0.8125rem;color:var(--text-secondary);margin-bottom:0.25rem}.pqc-replaces{font-size:0.6875rem;color:var(--text-muted)}.footer{border-top:1px solid var(--border-color);padding-top:1.5rem;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:1rem}.footer-left{font-size:0.875rem;color:var(--text-secondary)}.footer-left strong{color:var(--accent-blue)}.footer-right{font-size:0.8125rem;color:var(--text-muted);text-align:right}.footer-cta{margin-top:0.5rem;font-size:0.75rem;color:var(--text-muted)}.footer-cta a{color:var(--accent-blue);text-decoration:none}.footer-cta a:hover{text-decoration:underline}@media print{.export-buttons{display:none}}@media(max-width:1024px){.metrics-grid{grid-template-columns:repeat(2,1fr)}.compliance-grid{grid-template-columns:repeat(3,1fr)}.tls-grid{grid-template-columns:repeat(3,1fr)}.cipher-grid{grid-template-columns:repeat(2,1fr)}.cert-grid{grid-template-columns:1fr}}@media(max-width:768px){.container{padding:1rem}.header{flex-direction:column;gap:1rem}.status-banner{flex-direction:column;text-align:center}.metrics-grid{grid-template-columns:1fr}.finding-card{grid-template-columns:1fr;text-align:center}.finding-left{flex-direction:row;justify-content:center}.recommendation{text-align:center}.compliance-grid{grid-template-columns:1fr}.tls-grid{grid-template-columns:1fr}.cipher-grid{grid-template-columns:1fr}.pqc-grid{grid-template-columns:1fr}}</style></head><body><div class="container"><header class="header"><div class="logo-section"><div class="logo-icon">🔐</div><div class="logo-text"><h1>CBOM Live</h1><p>Cryptographic Bill of Materials</p></div></div><div class="export-buttons"><a href="/api/v1/report/' + data.domain + '/csv" class="export-btn">📊 CSV</a><a href="/api/v1/report/' + data.domain + '/json" class="export-btn">📄 JSON</a><button class="export-btn" onclick="window.print()">🖨️ PDF</button><span class="export-btn" style="cursor:default;opacity:0.7">📦 SBOM</span></div></header>' + errorBanner + '<div class="status-banner ' + statusClass + '"><span class="status-badge ' + statusClass + '">' + statusText + '</span><div class="status-text"><strong>' + statusMessage + '</strong><span> — Post-quantum cryptography migration required</span></div><div class="target-domain">' + data.domain + '</div><div class="scan-meta"><span class="live-dot"></span>Live Scan: ' + data.scanDate + '</div></div><div class="metrics-grid"><div class="metric-card ' + statusClass + '"><div class="metric-label">Risk Score</div><div class="metric-value">' + data.riskScore + '<span class="metric-suffix">/100</span></div><div class="metric-sub"><strong>' + statusText + '</strong></div><div class="risk-legend"><div class="legend-item"><span class="legend-dot critical"></span>75+ Critical</div><div class="legend-item"><span class="legend-dot high"></span>50-74 High</div><div class="legend-item"><span class="legend-dot medium"></span>25-49 Med</div><div class="legend-item"><span class="legend-dot low"></span>0-24 Low</div></div></div><div class="metric-card ' + (data.criticalCount > 0 ? 'critical' : 'success') + '"><div class="metric-label">Critical</div><div class="metric-value">' + data.criticalCount + '</div><div class="metric-sub">Quantum-vulnerable</div></div><div class="metric-card ' + (data.highCount > 0 ? 'warning' : 'success') + '"><div class="metric-label">High</div><div class="metric-value">' + data.highCount + '</div><div class="metric-sub">Need attention</div></div><div class="metric-card info"><div class="metric-label">CNSA 2.0</div><div class="metric-value">' + data.daysToCSNA2 + '</div><div class="metric-sub">days to deadline</div><div class="deadline-date">Dec 31, 2026</div></div></div>' + cipherBreakdownHtml + '<section class="findings-section"><div class="section-header"><span class="section-icon">🔍</span><h2>Cryptographic Findings</h2></div><div class="findings-list">' + findingsHtml + '</div></section><section class="remediation-section"><div class="section-header"><span class="section-icon">💰</span><h2>Estimated Remediation</h2><span class="vendor-neutral-badge">Vendor Neutral</span></div><div class="remediation-card"><div class="scope-label">Per Endpoint/Application</div><div class="remediation-estimate"><div class="estimate-item"><div class="estimate-label">Low</div><div class="estimate-value">$' + data.remediationEstimate.low.toLocaleString() + '</div><div class="estimate-note">Basic migration</div></div><div class="estimate-item"><div class="estimate-label">Mid</div><div class="estimate-value">$' + data.remediationEstimate.mid.toLocaleString() + '</div><div class="estimate-note">Hybrid deployment</div></div><div class="estimate-item"><div class="estimate-label">High</div><div class="estimate-value">$' + data.remediationEstimate.high.toLocaleString() + '</div><div class="estimate-note">Full remediation</div></div></div><div class="scope-divider"></div><div class="enterprise-note"><div class="enterprise-row"><span class="enterprise-label">Department (10-50 systems):</span><span class="enterprise-range">$' + data.remediationEstimate.departmentLow.toLocaleString() + ' – $' + data.remediationEstimate.departmentHigh.toLocaleString() + '</span></div><div class="enterprise-row"><span class="enterprise-label">Agency-wide (50+ systems):</span><span class="enterprise-range">$' + data.remediationEstimate.enterpriseLow.toLocaleString() + ' – $' + data.remediationEstimate.enterpriseHigh.toLocaleString() + '</span></div></div><div class="remediation-note"><strong>Vendor-neutral estimates</strong> — IFG provides discovery and assessment only. Actual costs vary by environment complexity. Request competitive quotes through DIR cooperative contracts.</div></div></section>' + certInfo + '<section class="tls-section"><div class="section-header"><span class="section-icon">🔒</span><h2>TLS Configuration</h2></div><div class="tls-grid"><div class="tls-item"><div class="tls-label">Protocol</div><div class="tls-value">' + data.tlsConfig.version + '</div></div><div class="tls-item"><div class="tls-label">Key Exchange</div><div class="tls-value">' + data.tlsConfig.keyExchange + '</div></div><div class="tls-item"><div class="tls-label">Encryption</div><div class="tls-value">' + (data.tlsConfig.encryption || 'N/A') + '</div></div><div class="tls-item"><div class="tls-label">MAC</div><div class="tls-value">' + (data.tlsConfig.mac || 'N/A') + '</div></div>' + hstsHtml + '</div></section><section class="compliance-section"><div class="section-header"><span class="section-icon">📋</span><h2>Compliance Status</h2></div><div class="compliance-grid"><div class="compliance-card"><div class="compliance-framework">OMB M-23-02</div><div class="compliance-name">Crypto Inventory</div><div class="compliance-status">🔴</div><div class="compliance-deadline">Dec 2025</div><span class="compliance-badge non-compliant">Non-Compliant</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Software</div><div class="compliance-status">' + (data.compliance.cnsa2Software.status === 'NON-COMPLIANT' ? '🔴' : '🟡') + '</div><div class="compliance-deadline">2027</div><span class="compliance-badge ' + data.compliance.cnsa2Software.status.toLowerCase().replace(' ','-').replace('_','-') + '">' + data.compliance.cnsa2Software.status.replace('_',' ') + '</span></div><div class="compliance-card"><div class="compliance-framework">CNSA 2.0</div><div class="compliance-name">Full Migration</div><div class="compliance-status">🔴</div><div class="compliance-deadline">2033</div><span class="compliance-badge non-compliant">Non-Compliant</span></div><div class="compliance-card"><div class="compliance-framework">NIST PQC</div><div class="compliance-name">FIPS 203/204/205</div><div class="compliance-status">⚪</div><div class="compliance-deadline">Ongoing</div><span class="compliance-badge not-implemented">Not Implemented</span></div><div class="compliance-card"><div class="compliance-framework">FIPS 140-3</div><div class="compliance-name">Module Validation</div><div class="compliance-status">' + (data.compliance.fips1403.status === 'PARTIAL' ? '🟡' : '🔴') + '</div><div class="compliance-deadline">Active</div><span class="compliance-badge ' + data.compliance.fips1403.status.toLowerCase().replace('_','-') + '">' + data.compliance.fips1403.status.replace('_',' ') + '</span></div></div></section><section class="pqc-section"><div class="section-header"><span class="section-icon">📚</span><h2>NIST PQC Standards Reference</h2></div><div class="pqc-grid"><div class="pqc-card"><div class="pqc-icon">🔑</div><div class="pqc-name">ML-KEM</div><div class="pqc-fips">FIPS 203</div><div class="pqc-use">Key Encapsulation Mechanism</div><div class="pqc-replaces">Replaces ECDHE, RSA-KEM, DH</div></div><div class="pqc-card"><div class="pqc-icon">✍️</div><div class="pqc-name">ML-DSA</div><div class="pqc-fips">FIPS 204</div><div class="pqc-use">Digital Signatures (Lattice)</div><div class="pqc-replaces">Replaces RSA, ECDSA, EdDSA</div></div><div class="pqc-card"><div class="pqc-icon">🛡️</div><div class="pqc-name">SLH-DSA</div><div class="pqc-fips">FIPS 205</div><div class="pqc-use">Stateless Hash-Based Signatures</div><div class="pqc-replaces">Conservative alternative to ML-DSA</div></div></div></section><footer class="footer"><div class="footer-left"><strong>ACDI Platform v2.6</strong> | IFG Quantum Holdings<div class="footer-cta">Live TLS Assessment | <a href="mailto:info@ifgquantum.com">Contact for internal network scan</a></div></div><div class="footer-right">CBOM/SBOM Integration<br>CDM Dashboard Compatible</div></footer></div></body></html>';
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
  lines.push('Medium Issues,' + data.mediumCount);
  lines.push('Days to CNSA 2.0,' + data.daysToCSNA2);
  lines.push('');
  lines.push('TLS CONFIGURATION');
  lines.push('Protocol,' + data.tlsConfig.version);
  lines.push('Key Exchange,' + data.tlsConfig.keyExchange);
  lines.push('Authentication,' + (data.tlsConfig.authentication || 'N/A'));
  lines.push('Encryption,' + (data.tlsConfig.encryption || 'N/A'));
  lines.push('Encryption Key Size,' + (data.tlsConfig.encryptionKeySize || 'N/A'));
  lines.push('MAC,' + (data.tlsConfig.mac || 'N/A'));
  lines.push('Cipher Suite,' + data.tlsConfig.cipherSuite);
  lines.push('');
  lines.push('SECURITY HEADERS');
  lines.push('HSTS,' + (data.securityHeaders.hsts ? 'Enabled' : 'Not Detected'));
  lines.push('HSTS Max-Age,' + (data.securityHeaders.hstsMaxAge || 'N/A'));
  lines.push('HSTS includeSubDomains,' + data.securityHeaders.hstsIncludeSubdomains);
  lines.push('HSTS Preload,' + data.securityHeaders.hstsPreload);
  lines.push('');
  lines.push('CERTIFICATE');
  lines.push('Subject,"' + (data.certificate.subject || 'N/A') + '"');
  lines.push('Issuer,"' + (data.certificate.issuer || 'N/A') + '"');
  lines.push('Signature Algorithm,' + (data.certificate.signatureAlgorithm || 'N/A'));
  lines.push('Public Key Algorithm,' + (data.certificate.publicKeyAlgorithm || 'N/A'));
  lines.push('Public Key Size,' + (data.certificate.publicKeySize || 'N/A'));
  lines.push('Valid From,' + (data.certificate.validFrom || 'N/A'));
  lines.push('Valid To,' + (data.certificate.validTo || 'N/A'));
  lines.push('Chain Length,' + (data.certificate.chainLength || 'N/A'));
  lines.push('');
  lines.push('CRYPTOGRAPHIC FINDINGS');
  lines.push('Severity,Algorithm,Type,PQ Security (bits),HNDL Risk,Recommendation');
  data.findings.forEach(function(f) {
    lines.push(f.severity + ',"' + f.algorithm + '","' + f.type + '",' + (f.pqSecurity === null ? 'N/A' : f.pqSecurity) + ',' + (f.hndlRisk || 'N/A') + ',"' + f.recommendation + '"');
  });
  lines.push('');
  lines.push('REMEDIATION ESTIMATES');
  lines.push('Low,$' + data.remediationEstimate.low);
  lines.push('Mid,$' + data.remediationEstimate.mid);
  lines.push('High,$' + data.remediationEstimate.high);
  lines.push('');
  lines.push('---');
  lines.push('ACDI Platform v2.6 | IFG Quantum Holdings');
  lines.push('For cryptographic review contact: Dr. Soundes Marzougui');
  return lines.join('\n');
}

// ============================================================================
// API ROUTES
// ============================================================================

app.get('/', function(req, res) {
  res.json({
    service: 'ACDI CBOM API',
    version: '2.6.0',
    status: 'operational',
    mode: 'LIVE TLS SCANNING',
    features: [
      'Real-time TLS handshake analysis',
      'Certificate chain inspection',
      'Cipher suite decomposition',
      'HSTS detection',
      'Post-quantum security assessment',
      'HNDL (Harvest Now Decrypt Later) risk classification'
    ],
    endpoints: { 
      html: '/api/v1/report/:domain/html', 
      json: '/api/v1/report/:domain/json', 
      csv: '/api/v1/report/:domain/csv' 
    },
    compliance: ['OMB M-23-02', 'CNSA 2.0', 'NIST PQC (FIPS 203/204/205)', 'FIPS 140-3'],
    vendor: 'IFG Quantum Holdings'
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
        version: '2.6.0', 
        mode: 'LIVE',
        vendor: 'IFG Quantum Holdings',
        cryptographicAdvisor: 'Dr. Soundes Marzougui',
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
  console.log('ACDI CBOM API v2.6 - ENHANCED');
  console.log('Port: ' + PORT);
  console.log('Features:');
  console.log('  - Real-time TLS scanning');
  console.log('  - Certificate chain analysis');
  console.log('  - Cipher suite decomposition');
  console.log('  - HSTS detection');
  console.log('  - HNDL risk classification');
  console.log('  - FIPS 140-3 compliance check');
  console.log('===========================================');
});
