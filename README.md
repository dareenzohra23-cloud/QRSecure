# QR-Secure Enterprise: Cryptographically Signed QR Credential Authentication Platform

[![Security Architecture](https://img.shields.io/badge/Security-PKI%20%2B%20Digital%20Signatures-10b981.svg)](#cryptographic-architecture)
[![Cryptography](https://img.shields.io/badge/Algorithms-RSA--2048%20%2B%20SHA--256-blue.svg)](#cryptographic-architecture)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](#technologies-used)
[![Framework](https://img.shields.io/badge/Backend-Flask-000000.svg)](#technologies-used)
[![Tests](https://img.shields.io/badge/Unit%20Tests-11%2F11%20Passed-brightgreen.svg)](#automated-test-suite)

> **Enterprise Security Model**: *«A QR code may be duplicated or visually inspected by anyone, but its embedded payload is strictly considered authentic only if its asymmetric cryptographic digital signature is validated against the trusted Root Certificate Authority's public key.»*

---

## Table of Contents
1. [Platform Overview](#1-platform-overview)
2. [Problem Statement & Threat Model](#2-problem-statement--threat-model)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Architecture](#4-cryptographic-architecture)
5. [Database Schema](#5-database-schema)
6. [Core Algorithms & Standards](#6-core-algorithms--standards)
7. [Enterprise Security Mechanisms](#7-enterprise-security-mechanisms)
8. [Automated Test Suite](#8-automated-test-suite)
9. [Converting QR-Secure into a Mobile App (100% Free)](#9-converting-qr-secure-into-a-mobile-app-100-free)
10. [Installation & Deployment](#10-installation--deployment)
11. [API Reference](#11-api-reference)

---

## 1. Platform Overview

**QR-Secure Enterprise** is an identity authentication and data integrity verification platform. It issues and audits cryptographically signed QR credentials to prevent tampering and counterfeiting across organizations.

### Key Capabilities
* **Cryptographic Issuance**: Canonicalizes credential schemas, computes SHA-256 fingerprints, and signs payloads with an isolated RSA-2048 private key.
* **Multi-Format Verification**: Validates physical credentials via device cameras, image uploads, and direct JSON payload inspection.
* **Defense-in-Depth Validation**: 
  1. RSA-2048 digital signature verification.
  2. Byte-level SHA-256 integrity verification.
  3. Real-time Certificate Revocation List (CRL) blacklisting.
  4. Temporal validity enforcement (`issued_at` to `expires_at`).
  5. Cryptographic nonce replay protection for single-use access passes.
* **Root Certificate Authority (CA) Management**: Full public key lifecycle management, SubjectPublicKeyInfo export, fingerprint derivation, and seamless key rotation.

---

## 2. Problem Statement & Threat Model

### The Vulnerability of Standard QR Codes
Standard 2D barcodes possess **no cryptographic binding to the issuing authority**. A standard QR code simply stores a raw ASCII string. 

**Attack Vector**:
1. An attacker scans an authentic employee or student badge (`{"id": "EMP-1001", "name": "Alice"}`).
2. The attacker modifies the identity (`{"id": "EMP-9999", "name": "Attacker"}`).
3. The attacker generates a replacement QR code with free online generators.
4. Conventional scanner applications display the falsified data unquestioningly.

### The QR-Secure Solution
QR-Secure introduces an **Asymmetric Digital Signature** into the payload. The private key remains isolated on the server and is never exposed. When an attacker alters even a single bit of the data, the recomputed SHA-256 digest fails mathematical validation against the public key, immediately triggering **TAMPER DETECTED**.

```
ISSUANCE PIPELINE:
Raw Identity Data ──► Canonicalize (RFC 8785) ──► SHA-256 Digest ──► RSA-2048 Sign ──► Scannable QR Matrix

VERIFICATION PIPELINE:
Scanned Matrix ──► Extract Payload & Signature ──► Recompute SHA-256 ──► RSA Verify (Public Key)
                                                                               │
                                                                   ┌───────────┴───────────┐
                                                                   ▼                       ▼
                                                              [SUCCESS]                [FAILURE]
                                                        Check Expiry & CRL        ❌ TAMPER DETECTED
```

---

## 3. System Architecture

```
qr-secure/
├── app.py                      # Application factory and server entry point
├── config.py                   # Platform configuration and security parameters
├── requirements.txt            # Python dependencies
├── .gitignore                  # Enforces private key non-exposure
├── README.md                   # Technical documentation
│
├── crypto/                     # Asymmetric Cryptography Engine
│   ├── hashing.py              # Canonicalization & SHA-256 hashing
│   ├── key_manager.py          # RSA-2048 keypair generation & rotation
│   ├── signer.py               # RSA-SHA256 PKCS#1 v1.5 digital signing
│   └── verifier.py             # Public key mathematical verification
│
├── qr/                         # Matrix Generation & Parsing
│   ├── generator.py            # Payload assembly & QR image rendering
│   └── validator.py            # 5-stage verification & audit engine
│
├── auth/                       # Access Control & Session Security
│   ├── password.py             # Salted PBKDF2/scrypt password hashing
│   └── authentication.py       # RBAC session security (@login_required, @role_required)
│
├── database/                   # Embedded SQLite Persistence
│   ├── database.py             # Schema initialization & connection management
│   └── models.py               # Queries for credentials, revocations, and audit logs
│
├── routes/                     # REST API & View Controllers
│   ├── auth_routes.py          # Authentication endpoints
│   ├── dashboard_routes.py     # Real-time telemetry & operational statistics
│   ├── qr_routes.py            # Credential issuance & revocation routes
│   ├── verify_routes.py        # Camera & image verification API
│   └── authority_routes.py     # Root CA inspection & key rotation
│
├── templates/                  # Responsive Dark Cybersecurity Interface
│   ├── base.html               # Enterprise layout & navigation
│   ├── login.html              # Authenticated portal access
│   ├── dashboard.html          # Operational analytics & live audit feed
│   ├── generate.html           # Multi-template issuance engine
│   ├── verify.html             # Multi-mode verification workstation
│   ├── authority.html          # Root CA & key lifecycle management
│   └── revoked.html            # Central Revocation Registry (CRL)
│
├── static/
│   ├── css/style.css           # Cybersecurity UI design system
│   └── js/main.js              # Client clipboard, toasts, and UI helpers
│
└── tests/
    └── test_qr_secure.py       # Automated unit & integration test suite
```

---

## 4. Cryptographic Architecture

### A. Asymmetric Key Generation (RSA 2048-bit)
* Modulus: 2048 bits ($n = p \times q$).
* Public Exponent: $e = 65537$.
* The private key is serialized to **PKCS#8 PEM format** with file permissions restricted to `0600` (owner read/write only).
* The public key is exported in **SubjectPublicKeyInfo PEM format** for open distribution to verifier nodes.
* Key Fingerprint:
  $$\text{Fingerprint} = \text{SHA256}(\text{DER}(\text{Public Key}))$$

### B. Payload Structure & Canonicalization (RFC 8785)
To ensure identical binary representation across different programming languages and client operating systems, the payload is deterministically serialized:
```json
{
  "version": "1.0",
  "qr_id": "QR-2026-00001",
  "issuer": "QR-Secure Authority",
  "type": "STUDENT_ID",
  "data": {
    "name": "Jane Doe",
    "usn": "1VTXX001",
    "branch": "Cyber Security",
    "institution": "Global Institute of Technology"
  },
  "issued_at": "2026-10-10T06:30:00Z",
  "expires_at": "2027-10-10T06:30:00Z",
  "signature_algorithm": "RSA-2048 / SHA-256",
  "signature": "LtLa+6Im..."
}
```

---

## 5. Database Schema

* `users`: Stores administrative and operator credentials (`username`, salted `password_hash`, `role`).
* `qr_codes`: Comprehensive registry of every issued credential (`qr_id`, `type`, `payload_hash`, `signature`, `status`).
* `revocations`: Centralized Certificate Revocation List (`qr_id`, `reason`, `revoked_by`, `revoked_at`).
* `verification_logs`: Immutable audit trail recording every verification event with timestamp, result, and method.
* `authority`: Manages active Root CA certificates, public key PEMs, fingerprints, and key rotation history.

---

## 6. Core Algorithms & Standards

1. **RSA-2048 / SHA-256 Signature Verification (PKCS#1 v1.5)**:
   * Compliant with **RFC 3447**.
   * Signature Generation: $s = \text{Sign}(K_{\text{priv}}, \text{SHA-256}(M))$.
   * Signature Verification: $\text{Verify}(K_{\text{pub}}, \text{SHA-256}(M), s) \in \{\text{True}, \text{False}\}$.
2. **SHA-256 Cryptographic Hash**:
   * Compliant with **FIPS PUB 180-4**.
   * Provides 128 bits of security against collision attacks and 256 bits against pre-image attacks.
3. **JSON Canonicalization Scheme (JCS)**:
   * Compliant with **RFC 8785**.
   * Eliminates key order ambiguity and whitespace discrepancies.

---

## 7. Enterprise Security Mechanisms

* **Strict Private Key Isolation**: Private keys are maintained server-side and never transmitted across network requests.
* **Role-Based Access Control (RBAC)**:
  * `ADMIN`: Credential issuance, revocation authority, keypair rotation, dashboard analytics.
  * `VERIFIER`: Camera scanning, image file analysis, verification audit review.
* **Replay Protection**: Single-use credentials embed a cryptographic nonce to prevent ticket reuse.
* **Salted Password Storage**: Passwords hashed using PBKDF2 with SHA-256 and unique per-user salts.

---

## 8. Automated Test Suite

Run the automated test suite with `pytest`:

```bash
pytest tests/test_qr_secure.py -v
```

All 11 enterprise security tests pass:
```
tests/test_qr_secure.py::test_1_correct_signature_verification PASSED    [  9%]
tests/test_qr_secure.py::test_2_incorrect_signature_rejection PASSED     [ 18%]
tests/test_qr_secure.py::test_3_modified_payload_detection PASSED        [ 27%]
tests/test_qr_secure.py::test_4_expired_qr_rejection PASSED              [ 36%]
tests/test_qr_secure.py::test_5_revoked_qr_rejection PASSED              [ 45%]
tests/test_qr_secure.py::test_6_invalid_qr_format_rejection PASSED       [ 54%]
tests/test_qr_secure.py::test_7_wrong_public_key_rejection PASSED        [ 63%]
tests/test_qr_secure.py::test_8_duplicate_qr_id_rejection PASSED         [ 72%]
tests/test_qr_secure.py::test_9_password_hashing_verification PASSED     [ 81%]
tests/test_qr_secure.py::test_10_unauthorized_access_rejection PASSED    [ 90%]
tests/test_qr_secure.py::test_11_replay_attack_detection PASSED          [100%]

============================== 11 passed in 0.68s ==============================
```

---

## 9. Converting QR-Secure into a Mobile App (100% Free)

You can convert QR-Secure into a real mobile app on Android and iOS using **100% free, open-source resources**:

### Method A: Progressive Web App (PWA) — Fastest & 100% Free
QR-Secure can be installed directly on any smartphone home screen without going through the app store:
1. When visiting the URL on Chrome (Android) or Safari (iOS), the user taps **"Install App"** or **"Add to Home Screen"**.
2. It launches in standalone fullscreen mode without the browser search bar.
3. It has full native camera access to scan QR codes directly.

### Method B: Wrap into an Android APK with Capacitor (Free)
1. Install [Node.js](https://nodejs.org/) (Free) and [Android Studio](https://developer.android.com/studio) (Free).
2. Install Capacitor:
   ```bash
   npm install @capacitor/core @capacitor/cli @capacitor/android
   npx cap init "QRSecure" "com.qrsecure.app"
   npx cap add android
   ```
3. Point Capacitor to your deployed server URL in `capacitor.config.json`:
   ```json
   {
     "appId": "com.qrsecure.app",
     "appName": "QR-Secure",
     "webDir": "www",
     "server": {
       "url": "https://your-qr-secure-app.onrender.com",
       "cleartext": true
     }
   }
   ```
4. Run `npx cap open android` — Android Studio will open and build an installable `.apk` file for free!

---

## 10. Installation & Deployment

### Quick Start (Local)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run unit tests
pytest tests/test_qr_secure.py -v

# 3. Start the application
python3 app.py
```

* Navigate to: **`http://127.0.0.1:5000`**
* **Default Admin**: `admin` / `admin123`
* **Default Verifier**: `verifier` / `verifier123`

### Free Cloud Deployment (e.g., Render.com)
1. Push this repository to GitHub.
2. Sign in to [Render.com](https://render.com/) (100% free tier).
3. Click **New +** $\rightarrow$ **Web Service** $\rightarrow$ Connect your GitHub repo.
4. Set Build Command: `pip install -r requirements.txt`
5. Set Start Command: `python app.py`
6. Click **Deploy**. Render provides a free HTTPS domain (e.g. `https://qr-secure.onrender.com`) accessible from any smartphone camera worldwide!

---

## 11. API Reference

* `POST /api/qr/generate`: Generates and cryptographically signs a QR code payload.
* `POST /api/verify`: Verifies raw QR payloads or images against the active authority.
* `POST /api/qr/revoke`: Enters a QR ID into the active revocation blacklist.
* `GET /api/dashboard/stats`: Returns real-time cryptographic audit statistics.
* `GET /api/authority/public-key`: Exports the active authority public key in PEM format.
* `POST /api/authority/rotate-keys`: Generates a new root RSA keypair and issues a new certificate.
