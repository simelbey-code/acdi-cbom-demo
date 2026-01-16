# ACDI CBOM Demo

**Automated Cryptographic Discovery & Intelligence - Cryptographic Bill of Materials**

External TLS assessment demo for post-quantum cryptography compliance evaluation.

## Overview

ACDI CBOM Light provides instant cryptographic vulnerability assessment for any domain's external TLS configuration. This demo showcases the vendor-neutral discovery capabilities of the ACDI platform.

## Features

- 🔍 **Real-time TLS Scanning** - Analyze any domain's cryptographic posture
- 📊 **Risk Scoring** - Quantified vulnerability assessment (0-100 scale)
- ⏱️ **CNSA 2.0 Countdown** - Days remaining to compliance deadline
- 💰 **Remediation Estimates** - Vendor-neutral cost projections
- 📋 **Compliance Mapping** - OMB M-23-02, CNSA 2.0, NIST PQC status
- 📦 **SBOM/CBOM Ready** - Federal software bill of materials integration

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/report/:domain/html` | Interactive HTML dashboard |
| `GET /api/v1/report/:domain/json` | Machine-readable JSON report |
| `GET /api/v1/report/:domain/csv` | Spreadsheet-compatible export |

## Usage

```bash
# View HTML report
https://your-deployment.railway.app/api/v1/report/dir.texas.gov/html

# Get JSON data
https://your-deployment.railway.app/api/v1/report/example.com/json

# Download CSV
https://your-deployment.railway.app/api/v1/report/example.com/csv
```

## Deployment

### Railway (Recommended)

1. Connect this repo to Railway
2. Railway auto-detects Node.js and deploys
3. No environment variables required

### Local Development

```bash
npm install
npm start
# Server runs on http://localhost:3000
```

## Vendor Neutral

IFG Quantum Holdings does not sell remediation services. ACDI provides discovery and assessment only, allowing agencies to:

- Obtain competitive vendor quotes
- Use existing DIR cooperative contracts
- Avoid vendor lock-in

## Compliance Standards

- **OMB M-23-02** - Cryptographic inventory requirements
- **CNSA 2.0** - NSA Commercial National Security Algorithm Suite
- **NIST PQC** - Post-Quantum Cryptography standards (FIPS 203, 204, 205)

## About

**ACDI Platform v2.3** | [IFG Quantum Holdings](https://ifgquantum.com)

For full internal assessment capabilities, contact info@ifgquantum.com
