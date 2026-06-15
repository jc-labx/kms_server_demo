# SecuServes KMS Demo

A **reference Key Management Server (KMS)** implemented as a single Python script using the standard library plus [`cryptography`].

> **Status:** demo / reference implementation  
> **Version for this GitHub update:** 0.3.0

## What it does

This project exposes a small HTTPS API and CLI for common KMS workflows:

- Generate keys: **RSA**, **EC**, **Ed25519**, and **AES**
- Store key material encrypted at rest with **AES-256-GCM** under a master key
- Serve **public keys** for asymmetric keys
- **Wrap/export** symmetric keys to a recipient RSA public key using **RSA-OAEP**
- Keep private keys server-side for **sign** and **decrypt** operations
- Rotate keys with **versioned records**
- Revoke or delete keys (soft delete + optional hard delete)
- Maintain a **tamper-evident audit log** using **hash-chained JSONL**
- Support **mTLS client auth** and **per-client ACLs**

## Important security note

This repository is intentionally presented as a **learning / demo implementation**. It is **not production hardened**.

## Repository contents

```text
kms_server_demo.py
kms_server_demo_v0_3_0.py
README.md
LICENSE
requirements.txt
.gitignore
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
CHANGELOG.md
REVIEW_NOTES.md
GITHUB_DESCRIPTION.txt
GITHUB_TOPICS.txt
PATCH_SUMMARY_v0.3.0.md
v0.3.0_RELEASE_CHECKLIST.md
VALIDATION_v0.3.0.md
```

## Requirements

- Python **3.10+**
- `cryptography`

Install dependency:

```bash
python -m pip install -r requirements.txt
```

## Quick start

```bash
export KMS_MASTER_PASSWORD='change-me-to-a-long-random-secret'
python kms_server_demo.py init --db kms.db --audit audit.jsonl
python kms_server_demo.py serve --host 0.0.0.0 --port 8443 --db kms.db --audit audit.jsonl --tls-cert server.crt --tls-key server.key --tls-ca client_ca.pem
```

# Security Policy

This repository is a demo/reference implementation. Security reports are still welcome, especially for authentication/authorization flaws, key handling mistakes, cryptographic misuse, audit log integrity issues, and accidental secret disclosure.


## Disclaimer

This project is intended for **education, prototyping, and controlled internal demos**.
