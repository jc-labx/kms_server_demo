#!/usr/bin/env python3
"""
Basic Key Management Server implemented using only Python stdlib + 'cryptography' library.

Core features:
- Key generation (RSA / EC / Ed25519 / AES)
- Storage & protection (AES-256-GCM encrypt-at-rest under a master key)
- Distribution (public keys; wrapping/export of symmetric keys via recipient RSA-OAEP)
- Rotation (versioned keys)
- Revocation & deletion (soft delete with optional hard delete)
- Tamper-evident audit log (hash-chained JSONL)
- mTLS client authentication (server verifies client certs)
- Per-client ACLs (authorize each operation per key or key-name)
- "decrypt" and "sign" operations where private keys never leave the server

SECURITY NOTES
- This is a reference implementation; do not treat it as production hardened.
- Python's built-in http.server is not recommended for production use.

QUICKSTART (mTLS)
  # 0) Install dependency
  pip install cryptography

  # 1) Set master password (encrypts keys at rest)
  export KMS_MASTER_PASSWORD='change-me-very-long'

  # 2) Initialize DB and audit log
  python secuserves_kms.py init --db kms.db --audit audit.jsonl

  # 3) Run HTTPS with mTLS (server cert+key + CA used to verify client certs)
  python secuserves_kms.py serve --host 0.0.0.0 --port 8443 --db kms.db --audit audit.jsonl \
     --tls-cert server.crt --tls-key server.key --tls-ca client_ca.pem

  # 4) Register a client certificate and grant permissions
  python secuserves_kms.py add-client --db kms.db --cert client.crt --name app1
  python secuserves_kms.py grant --db kms.db --client app1 --scope '*' --perm keys.list,keys.get

  # 5) Create a key (requires client cert + ACL)
  curl --cert client.crt --key client.key --cacert server_ca.pem \
    -X POST https://localhost:8443/v1/keys \
    -H 'Content-Type: application/json' \
    -d '{"name":"demo-rsa","type":"rsa","size":3072}'

  # 6) Sign data (private key stays server-side)
  curl --cert client.crt --key client.key --cacert server_ca.pem \
    -X POST https://localhost:8443/v1/keys/<KEY_ID>/sign \
    -H 'Content-Type: application/json' \
    -d '{"data_b64":"SGVsbG8"}'

"""

from __future__ import annotations

from pathlib import Path

import argparse
import base64
import datetime as _dt
import json
import os
import secrets
import sqlite3
import ssl
import sys
import threading
import uuid
import traceback
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, ed25519, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# --------------------------- Utilities ---------------------------

def iso_utc_now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def const_time_equal(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def sha256_hex(data: bytes) -> str:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize().hex()


# ----------------------- Master key handling ----------------------

@dataclass
class MasterKeyConfig:
    salt_path: str
    iterations: int = 600_000


class MasterKeyManager:
    """Derive an AES-256-GCM master key from a password + stored salt."""

    def __init__(self, cfg: MasterKeyConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._key: Optional[bytes] = None

    def _load_or_create_salt(self) -> bytes:
        if os.path.exists(self.cfg.salt_path):
            with open(self.cfg.salt_path, "rb") as f:
                salt = f.read()
            if len(salt) != 16:
                raise ValueError("Invalid master salt file (expected 16 bytes)")
            return salt
        salt = os.urandom(16)
        with open(self.cfg.salt_path, "wb") as f:
            f.write(salt)
        return salt

    def _derive(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.cfg.iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    def get_key(self) -> bytes:
        with self._lock:
            if self._key is not None:
                return self._key
            pw = os.environ.get("KMS_MASTER_PASSWORD")
            if not pw:
                raise RuntimeError("KMS_MASTER_PASSWORD env var must be set (strong passphrase).")
            salt = self._load_or_create_salt()
            self._key = self._derive(pw, salt)
            return self._key

    def encrypt_blob(self, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        key = self.get_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ct

    def decrypt_blob(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        key = self.get_key()
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)


# ----------------------------- DB -----------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ktype TEXT NOT NULL,
    version INTEGER NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    rotated_from TEXT,
    exportable INTEGER NOT NULL DEFAULT 0,
    public_pem TEXT,
    nonce BLOB,
    material_enc BLOB
);
CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(name);
CREATE INDEX IF NOT EXISTS idx_keys_state ON keys(state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_name_version ON keys(name, version);

CREATE TABLE IF NOT EXISTS clients (
    client_fp TEXT PRIMARY KEY,
    name TEXT UNIQUE,
    subject TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acls (
    client_fp TEXT NOT NULL,
    scope TEXT NOT NULL,
    perm TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (client_fp, scope, perm),
    FOREIGN KEY (client_fp) REFERENCES clients(client_fp)
);
CREATE INDEX IF NOT EXISTS idx_acls_client ON acls(client_fp);
"""


class KmsDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        return con

    def _ensure_schema(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA)

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        with self._lock, self._connect() as con:
            con.execute(sql, params)
            con.commit()

    def executescript(self, sql: str) -> None:
        with self._lock, self._connect() as con:
            con.executescript(sql)
            con.commit()

    def fetchone(self, sql: str, params: Tuple[Any, ...] = ()):
        with self._lock, self._connect() as con:
            cur = con.execute(sql, params)
            return cur.fetchone()

    def fetchall(self, sql: str, params: Tuple[Any, ...] = ()):
        with self._lock, self._connect() as con:
            cur = con.execute(sql, params)
            return cur.fetchall()

    def transaction(self, fn):
        """Run fn(connection) inside a single IMMEDIATE transaction under the DB lock."""
        with self._lock:
            con = self._connect()
            try:
                con.execute("BEGIN IMMEDIATE")
                result = fn(con)
                con.commit()
                return result
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()


# -------------------------- Audit log --------------------------

class AuditLogger:
    """Append-only JSONL with hash chaining for tamper evidence."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64
        try:
            last = ""
            with open(self.path, "rb") as f:
                for line in f:
                    if line.strip():
                        last = line.decode("utf-8")
            if not last:
                return "0" * 64
            obj = json.loads(last)
            return obj.get("entry_hash", "0" * 64)
        except Exception:
            return "0" * 64

    def append(self, actor: str, action: str, key_id: str = "", details: Optional[dict] = None) -> dict:
        details = details or {}
        with self._lock:
            record = {
                "ts": iso_utc_now(),
                "actor": actor,
                "action": action,
                "key_id": key_id,
                "details": details,
                "prev_hash": self._prev_hash,
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
            entry_hash = sha256_hex(canonical)
            record["entry_hash"] = entry_hash
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            self._prev_hash = entry_hash
            return record

    def verify(self) -> Tuple[bool, Optional[str]]:
        prev = "0" * 64
        if not os.path.exists(self.path):
            return True, None
        with open(self.path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                obj = json.loads(line)
                if obj.get("prev_hash") != prev:
                    return False, f"Broken prev_hash at line {idx}"
                record = {k: obj[k] for k in obj.keys() if k != "entry_hash"}
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
                calc = sha256_hex(canonical)
                if obj.get("entry_hash") != calc:
                    return False, f"Hash mismatch at line {idx}"
                prev = obj["entry_hash"]
        return True, None


# -------------------------- KMS core --------------------------

ALLOWED_KEY_TYPES = {"rsa", "ec", "ed25519", "aes"}
ALLOWED_STATES = {"ACTIVE", "RETIRED", "REVOKED", "DELETED"}

# Permission constants
PERMS = {
    "keys.list",
    "keys.get",
    "keys.public",
    "keys.create",
    "keys.wrap",
    "keys.rotate",
    "keys.revoke",
    "keys.delete",
    "keys.sign",
    "keys.decrypt",
    "clients.list",
    "clients.read",
}

MAX_JSON_BODY_BYTES = 1024 * 1024  # 1 MiB safety limit for demo requests


def bearer_fallback_enabled() -> bool:
    return os.environ.get("KMS_ALLOW_BEARER_FALLBACK", "").strip().lower() in {"1", "true", "yes"}


def generate_key_material(ktype: str, size: int | None = None, curve: str | None = None) -> Tuple[bytes, Optional[str]]:
    """Return (private_or_secret_material_bytes, public_pem_or_None)."""
    ktype = ktype.lower()
    if ktype == "aes":
        bits = int(size or 256)
        if bits not in (128, 192, 256):
            raise ValueError("AES size must be 128/192/256")
        key = AESGCM.generate_key(bit_length=bits)
        return key, None

    if ktype == "rsa":
        key_size = int(size or 3072)
        if key_size < 2048:
            raise ValueError("RSA size must be >= 2048")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return priv_bytes, pub_pem

    if ktype == "ec":
        curve_name = (curve or "secp256r1").lower()
        if curve_name in ("secp256r1", "prime256v1", "p-256"):
            curve_obj = ec.SECP256R1()
        elif curve_name in ("secp384r1", "p-384"):
            curve_obj = ec.SECP384R1()
        elif curve_name in ("secp521r1", "p-521"):
            curve_obj = ec.SECP521R1()
        else:
            raise ValueError("Unsupported curve (use secp256r1/secp384r1/secp521r1)")
        priv = ec.generate_private_key(curve_obj)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return priv_bytes, pub_pem

    if ktype == "ed25519":
        priv = ed25519.Ed25519PrivateKey.generate()
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return priv_bytes, pub_pem

    raise ValueError("Unsupported key type")


def wrap_symmetric_key_for_recipient(sym_key: bytes, recipient_rsa_public_pem: str) -> bytes:
    pub = load_pem_public_key(recipient_rsa_public_pem.encode("utf-8"))
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("recipient_rsa_public_pem must be an RSA public key")
    return pub.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# -------------------------- ACL helpers --------------------------

@dataclass
class ClientIdentity:
    fp: str
    name: str
    subject: str


def scope_for_key(key_id: str) -> str:
    return f"key:{key_id}"


def scope_for_name(name: str) -> str:
    return f"name:{name}"


def normalize_perms(perms_csv: str) -> list[str]:
    perms = []
    for p in (perms_csv or "").split(","):
        p = p.strip()
        if p:
            perms.append(p)
    return perms


def acl_allows(db: KmsDB, client_fp: str, perm: str, key_id: str | None = None, key_name: str | None = None) -> bool:
    if perm not in PERMS:
        return False
    scopes = ["*"]
    if key_id:
        scopes.append(scope_for_key(key_id))
    if key_name:
        scopes.append(scope_for_name(key_name))
    q_marks = ",".join(["?"] * len(scopes))
    row = db.fetchone(
        f"SELECT 1 FROM acls WHERE client_fp=? AND perm=? AND scope IN ({q_marks}) LIMIT 1",
        (client_fp, perm, *scopes),
    )
    return row is not None


# ------------------------ HTTP Server ------------------------

class ThreadingHTTPServer(ThreadingMixIn):
    daemon_threads = True


class KMSHandler(BaseHTTPRequestHandler):
    server_version = "SecuServesKMS/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], iso_utc_now(), format % args))

    # ---------- Response helpers ----------
    def _json(self, status: int, body: Any) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        if length > MAX_JSON_BODY_BYTES:
            raise ValueError(f"JSON body too large (max {MAX_JSON_BODY_BYTES} bytes)")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid JSON body")

    def _server_error(self, exc: Exception) -> None:
        print(f"[KMS] internal server error handling {self.command} {self.path}: {exc}", file=sys.stderr)
        traceback.print_exc()
        self._error(500, "internal server error")

    # ---------- mTLS identity ----------
    def _peer_cert_der(self) -> Optional[bytes]:
        try:
            if isinstance(self.connection, ssl.SSLSocket):
                return self.connection.getpeercert(binary_form=True)
        except Exception:
            return None
        return None

    def _client_from_mtls(self) -> Optional[ClientIdentity]:
        if not getattr(self.server, "mtls_required", False):
            return None
        der = self._peer_cert_der()
        if not der:
            return None
        fp = sha256_hex(der)
        subject = ""
        try:
            cert = x509.load_der_x509_certificate(der)
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = ""
        row = self.server.db.fetchone("SELECT client_fp,name,subject,enabled FROM clients WHERE client_fp=?", (fp,))
        if not row or int(row["enabled"]) != 1:
            return None
        return ClientIdentity(fp=fp, name=row["name"] or fp, subject=row["subject"] or subject)

    # ---------- Auth & ACL ----------
    def _actor(self) -> str:
        ci = self._client_from_mtls()
        if ci:
            return f"mtls:{ci.name}:{ci.fp[:12]}"
        # Optional bearer fallback (for local dev only). If mTLS is required, we do not allow bearer.
        if getattr(self.server, "mtls_required", False) or not bearer_fallback_enabled():
            return ""
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            return hdr[len("Bearer "):].strip()
        return ""

    def _require_client(self) -> ClientIdentity:
        ci = self._client_from_mtls()
        if not ci:
            self._error(HTTPStatus.UNAUTHORIZED, "mTLS client certificate required (and must be registered/enabled)")
            raise PermissionError("mtls required")
        return ci

    def _require_perm(self, perm: str, key_id: str | None = None, key_name: str | None = None) -> ClientIdentity:
        ci = self._require_client() if getattr(self.server, "mtls_required", False) else None
        if ci:
            allowed = acl_allows(self.server.db, ci.fp, perm, key_id=key_id, key_name=key_name)
            if not allowed:
                self._error(HTTPStatus.FORBIDDEN, f"ACL denied: {perm}")
                raise PermissionError("acl denied")
            return ci
        # bearer-mode legacy: disabled by default, only for local development
        if not bearer_fallback_enabled():
            self._error(HTTPStatus.UNAUTHORIZED, "mTLS client auth required unless KMS_ALLOW_BEARER_FALLBACK=true is set for local development")
            raise PermissionError("bearer fallback disabled")
        tokens = getattr(self.server, "tokens", [])
        actor = self._actor()
        if not tokens:
            self._error(HTTPStatus.UNAUTHORIZED, "No API tokens configured")
            raise PermissionError("no tokens")
        if not any(const_time_equal(actor, t) for t in tokens):
            self._error(HTTPStatus.UNAUTHORIZED, "Invalid or missing bearer token")
            raise PermissionError("bad token")
        return ClientIdentity(fp="", name=actor, subject="")

    # ---------- Routing ----------
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")

            if path == "" or path == "/healthz":
                self._json(200, {"status": "ok", "ts": iso_utc_now()})
                return

            if path == "/v1/clients":
                ci = self._require_perm("clients.list")
                rows = self.server.db.fetchall("SELECT client_fp,name,subject,enabled,created_at,updated_at FROM clients ORDER BY name")
                self.server.audit.append(self._actor() or f"mtls:{ci.name}", "clients.list")
                self._json(200, {"clients": [dict(r) for r in rows]})
                return

            if path == "/v1/keys":
                ci = self._require_perm("keys.list")
                rows = self.server.db.fetchall(
                    "SELECT key_id,name,ktype,version,state,created_at,updated_at,rotated_from,exportable FROM keys ORDER BY name,version"
                )
                self._json(200, {"keys": [dict(r) for r in rows]})
                self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.list")
                return

            parts = path.split("/")
            if len(parts) >= 4 and parts[1] == "v1" and parts[2] == "keys":
                key_id = parts[3]

                if len(parts) == 4:
                    row = self.server.db.fetchone(
                        "SELECT key_id,name,ktype,version,state,created_at,updated_at,rotated_from,exportable,public_pem FROM keys WHERE key_id=?",
                        (key_id,),
                    )
                    if not row:
                        self._error(404, "key not found")
                        return
                    ci = self._require_perm("keys.get", key_id=key_id, key_name=row["name"])
                    self._json(200, dict(row))
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.get", key_id)
                    return

                if len(parts) == 5 and parts[4] == "public":
                    row = self.server.db.fetchone(
                        "SELECT key_id,name,ktype,public_pem,state FROM keys WHERE key_id=?",
                        (key_id,),
                    )
                    if not row:
                        self._error(404, "key not found")
                        return
                    ci = self._require_perm("keys.public", key_id=key_id, key_name=row["name"])
                    if row["ktype"] == "aes":
                        self._error(400, "symmetric keys do not have public material")
                        return
                    self._json(200, {"key_id": key_id, "public_pem": row["public_pem"], "state": row["state"]})
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.public", key_id)
                    return

            self._error(404, "not found")

        except PermissionError:
            return
        except sqlite3.IntegrityError:
            self._error(409, "database integrity conflict")
        except Exception as e:
            self._server_error(e)

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")

            if path == "/v1/keys":
                body = self._read_json()
                name = str(body.get("name") or "").strip()
                ktype = str(body.get("type") or "").lower().strip()
                size = body.get("size")
                curve = body.get("curve")
                exportable = bool(body.get("exportable", False))

                if not name:
                    self._error(400, "name is required")
                    return
                if ktype not in ALLOWED_KEY_TYPES:
                    self._error(400, f"type must be one of {sorted(ALLOWED_KEY_TYPES)}")
                    return

                # authorize create by name scope
                ci = self._require_perm("keys.create", key_name=name)

                def _create_tx(con):
                    row = con.execute("SELECT MAX(version) AS v FROM keys WHERE name=?", (name,)).fetchone()
                    next_version = int(row["v"] or 0) + 1
                    key_id = str(uuid.uuid4())
                    material, public_pem = generate_key_material(ktype, size=size, curve=curve)
                    aad = f"{key_id}:{next_version}".encode("utf-8")
                    nonce, ct = self.server.mkm.encrypt_blob(material, aad)
                    now = iso_utc_now()
                    con.execute(
                        "INSERT INTO keys(key_id,name,ktype,version,state,created_at,updated_at,rotated_from,exportable,public_pem,nonce,material_enc) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            key_id,
                            name,
                            ktype,
                            next_version,
                            "ACTIVE",
                            now,
                            now,
                            None,
                            1 if exportable else 0,
                            public_pem,
                            nonce,
                            ct,
                        ),
                    )
                    return key_id, next_version, public_pem

                key_id, next_version, public_pem = self.server.db.transaction(_create_tx)
                self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.create", key_id, {"name": name, "type": ktype, "version": next_version})
                self._json(201, {"key_id": key_id, "name": name, "type": ktype, "version": next_version, "state": "ACTIVE", "public_pem": public_pem})
                return

            parts = path.split("/")
            if len(parts) >= 5 and parts[1] == "v1" and parts[2] == "keys":
                key_id = parts[3]
                action = parts[4]

                # load base row (needed for ACL by name)
                base = self.server.db.fetchone("SELECT key_id,name,ktype,version,state,exportable,public_pem,nonce,material_enc FROM keys WHERE key_id=?", (key_id,))
                if not base:
                    self._error(404, "key not found")
                    return

                if action == "wrap":
                    ci = self._require_perm("keys.wrap", key_id=key_id, key_name=base["name"])
                    body = self._read_json()
                    recipient_pem = body.get("recipient_rsa_public_pem")
                    if not recipient_pem:
                        self._error(400, "recipient_rsa_public_pem is required")
                        return
                    if base["state"] != "ACTIVE":
                        self._error(409, f"key is not ACTIVE (state={base['state']})")
                        return
                    if base["ktype"] != "aes":
                        self._error(400, "wrap is only supported for symmetric (aes) keys")
                        return
                    if int(base["exportable"] or 0) != 1:
                        self._error(403, "key is marked non-exportable")
                        return
                    aad = f"{base['key_id']}:{base['version']}".encode("utf-8")
                    sym = self.server.mkm.decrypt_blob(base["nonce"], base["material_enc"], aad)
                    wrapped = wrap_symmetric_key_for_recipient(sym, recipient_pem)
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.wrap", key_id)
                    self._json(200, {"key_id": key_id, "wrapped_key_b64": b64e(wrapped), "alg": "RSA-OAEP-SHA256"})
                    return

                if action == "rotate":
                    ci = self._require_perm("keys.rotate", key_id=key_id, key_name=base["name"])
                    body = self._read_json()
                    if base["state"] not in ("ACTIVE", "RETIRED"):
                        self._error(409, f"cannot rotate key in state={base['state']}")
                        return
                    name = base["name"]
                    ktype = base["ktype"]
                    size = body.get("size")
                    curve = body.get("curve")

                    def _rotate_tx(con):
                        current = con.execute(
                            "SELECT key_id,name,ktype,version,state,exportable FROM keys WHERE key_id=?",
                            (key_id,),
                        ).fetchone()
                        if not current:
                            raise ValueError("key not found")
                        if current["state"] not in ("ACTIVE", "RETIRED"):
                            raise ValueError(f"cannot rotate key in state={current['state']}")
                        row2 = con.execute("SELECT MAX(version) AS v FROM keys WHERE name=?", (name,)).fetchone()
                        next_version = int(row2["v"] or 0) + 1

                        new_id = str(uuid.uuid4())
                        material, public_pem = generate_key_material(ktype, size=size, curve=curve)
                        aad = f"{new_id}:{next_version}".encode("utf-8")
                        nonce, ct = self.server.mkm.encrypt_blob(material, aad)

                        now = iso_utc_now()
                        if current["state"] == "ACTIVE":
                            con.execute("UPDATE keys SET state=?, updated_at=? WHERE key_id=?", ("RETIRED", now, key_id))

                        con.execute(
                            "INSERT INTO keys(key_id,name,ktype,version,state,created_at,updated_at,rotated_from,exportable,public_pem,nonce,material_enc) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                new_id,
                                name,
                                ktype,
                                next_version,
                                "ACTIVE",
                                now,
                                now,
                                key_id,
                                int(current["exportable"]),
                                public_pem,
                                nonce,
                                ct,
                            ),
                        )
                        return new_id, next_version

                    new_id, next_version = self.server.db.transaction(_rotate_tx)
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.rotate", key_id, {"new_key_id": new_id, "new_version": next_version})
                    self._json(201, {"old_key_id": key_id, "new_key_id": new_id, "name": name, "type": ktype, "version": next_version})
                    return

                if action == "revoke":
                    ci = self._require_perm("keys.revoke", key_id=key_id, key_name=base["name"])
                    if base["state"] == "REVOKED":
                        self._json(200, {"key_id": key_id, "state": "REVOKED"})
                        return
                    now = iso_utc_now()
                    self.server.db.execute("UPDATE keys SET state=?, updated_at=? WHERE key_id=?", ("REVOKED", now, key_id))
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.revoke", key_id)
                    self._json(200, {"key_id": key_id, "state": "REVOKED"})
                    return

                if action == "sign":
                    ci = self._require_perm("keys.sign", key_id=key_id, key_name=base["name"])
                    if base["state"] != "ACTIVE":
                        self._error(409, f"key is not ACTIVE (state={base['state']})")
                        return
                    if base["ktype"] not in ("rsa", "ec", "ed25519"):
                        self._error(400, "sign is only supported for asymmetric keys (rsa/ec/ed25519)")
                        return
                    body = self._read_json()
                    data_b64 = body.get("data_b64")
                    if not data_b64:
                        self._error(400, "data_b64 is required")
                        return
                    data = b64d(data_b64)
                    alg = (body.get("alg") or "").strip().upper()
                    hash_name = (body.get("hash") or "sha256").lower()
                    prehashed = bool(body.get("prehashed", False))

                    aad = f"{base['key_id']}:{base['version']}".encode("utf-8")
                    priv_bytes = self.server.mkm.decrypt_blob(base["nonce"], base["material_enc"], aad)
                    priv = serialization.load_der_private_key(priv_bytes, password=None)

                    h = {
                        "sha256": hashes.SHA256(),
                        "sha384": hashes.SHA384(),
                        "sha512": hashes.SHA512(),
                    }.get(hash_name)
                    if base["ktype"] == "rsa":
                        if alg in ("", "RSASSA-PSS", "RSAPSS", "PSS"):
                            chosen_hash = h or hashes.SHA256()
                            pad = padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH)
                            signer_hash = utils.Prehashed(chosen_hash) if prehashed else chosen_hash
                            sig = priv.sign(data, pad, signer_hash)
                            used = f"RSASSA-PSS-{hash_name.upper()}" + ("-PREHASH" if prehashed else "")
                        elif alg in ("PKCS1V15", "RSASSA-PKCS1V15"):
                            chosen_hash = h or hashes.SHA256()
                            signer_hash = utils.Prehashed(chosen_hash) if prehashed else chosen_hash
                            sig = priv.sign(data, padding.PKCS1v15(), signer_hash)
                            used = f"RSASSA-PKCS1V15-{hash_name.upper()}" + ("-PREHASH" if prehashed else "")
                        else:
                            self._error(400, "Unsupported RSA alg (use RSASSA-PSS or PKCS1V15)")
                            return
                    elif base["ktype"] == "ec":
                        chosen_hash = h or hashes.SHA256()
                        signer_hash = utils.Prehashed(chosen_hash) if prehashed else chosen_hash
                        sig = priv.sign(data, ec.ECDSA(signer_hash))
                        used = f"ECDSA-{hash_name.upper()}" + ("-PREHASH" if prehashed else "")
                    else:  # ed25519
                        if prehashed:
                            self._error(400, "Ed25519 does not support prehashed mode here")
                            return
                        sig = priv.sign(data)
                        used = "Ed25519"

                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.sign", key_id, {"alg": used, "len": len(data)})
                    self._json(200, {"key_id": key_id, "signature_b64": b64e(sig), "alg": used})
                    return

                if action == "decrypt":
                    ci = self._require_perm("keys.decrypt", key_id=key_id, key_name=base["name"])
                    if base["state"] != "ACTIVE":
                        self._error(409, f"key is not ACTIVE (state={base['state']})")
                        return
                    if base["ktype"] != "rsa":
                        self._error(400, "decrypt is only supported for RSA private keys")
                        return
                    body = self._read_json()
                    ct_b64 = body.get("ciphertext_b64")
                    if not ct_b64:
                        self._error(400, "ciphertext_b64 is required")
                        return
                    ciphertext = b64d(ct_b64)
                    oaep_hash = (body.get("hash") or "sha256").lower()
                    h = {
                        "sha1": hashes.SHA1(),
                        "sha256": hashes.SHA256(),
                        "sha384": hashes.SHA384(),
                        "sha512": hashes.SHA512(),
                    }.get(oaep_hash)
                    if not h:
                        self._error(400, "Unsupported OAEP hash")
                        return

                    aad = f"{base['key_id']}:{base['version']}".encode("utf-8")
                    priv_bytes = self.server.mkm.decrypt_blob(base["nonce"], base["material_enc"], aad)
                    priv = serialization.load_der_private_key(priv_bytes, password=None)
                    pt = priv.decrypt(
                        ciphertext,
                        padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None),
                    )
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.decrypt", key_id, {"hash": oaep_hash, "ct_len": len(ciphertext)})
                    self._json(200, {"key_id": key_id, "plaintext_b64": b64e(pt), "alg": f"RSA-OAEP-{oaep_hash.upper()}"})
                    return

            self._error(404, "not found")

        except PermissionError:
            return
        except ValueError as ve:
            self._error(400, str(ve))
        except sqlite3.IntegrityError:
            self._error(409, "database integrity conflict")
        except Exception as e:
            self._server_error(e)

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            parts = path.split("/")
            if len(parts) == 4 and parts[1] == "v1" and parts[2] == "keys":
                key_id = parts[3]
                row = self.server.db.fetchone("SELECT key_id,name,state FROM keys WHERE key_id=?", (key_id,))
                if not row:
                    self._error(404, "key not found")
                    return
                ci = self._require_perm("keys.delete", key_id=key_id, key_name=row["name"])
                qs = parse_qs(parsed.query or "")
                hard = (qs.get("hard", ["false"])[0].lower() == "true")
                now = iso_utc_now()
                if hard:
                    self.server.db.execute("DELETE FROM keys WHERE key_id=?", (key_id,))
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.delete.hard", key_id)
                    self._json(200, {"key_id": key_id, "deleted": "hard"})
                else:
                    self.server.db.execute(
                        "UPDATE keys SET state=?, updated_at=?, nonce=NULL, material_enc=NULL WHERE key_id=?",
                        ("DELETED", now, key_id),
                    )
                    self.server.audit.append(self._actor() or f"mtls:{ci.name}", "keys.delete.soft", key_id)
                    self._json(200, {"key_id": key_id, "deleted": "soft"})
                return

            self._error(404, "not found")

        except PermissionError:
            return
        except sqlite3.IntegrityError:
            self._error(409, "database integrity conflict")
        except Exception as e:
            self._server_error(e)


# ------------------------ CLI: client/ACL mgmt ------------------------


def read_cert_info(cert_path: str) -> Tuple[str, str]:
    data = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(data)
    fp = cert.fingerprint(hashes.SHA256()).hex()
    subj = cert.subject.rfc4514_string()
    return fp, subj


def resolve_client_fp(db: KmsDB, identifier: str) -> str:
    """identifier can be client name or fp."""
    identifier = identifier.strip()
    if len(identifier) == 64 and all(c in "0123456789abcdef" for c in identifier.lower()):
        return identifier.lower()
    row = db.fetchone("SELECT client_fp FROM clients WHERE name=?", (identifier,))
    if not row:
        raise ValueError("Unknown client (use add-client or specify fingerprint)")
    return row["client_fp"]


def cmd_add_client(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    fp, subj = read_cert_info(args.cert)
    now = iso_utc_now()
    name = args.name or fp
    db.execute(
        "INSERT OR REPLACE INTO clients(client_fp,name,subject,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)",
        (fp, name, subj, 1, now, now),
    )
    print(json.dumps({"client_fp": fp, "name": name, "subject": subj, "enabled": True}, indent=2))


def cmd_disable_client(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    fp = resolve_client_fp(db, args.client)
    now = iso_utc_now()
    db.execute("UPDATE clients SET enabled=0, updated_at=? WHERE client_fp=?", (now, fp))
    print(json.dumps({"client_fp": fp, "enabled": False}, indent=2))


def cmd_list_clients(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    rows = db.fetchall("SELECT client_fp,name,subject,enabled,created_at,updated_at FROM clients ORDER BY name")
    print(json.dumps({"clients": [dict(r) for r in rows]}, indent=2))


def cmd_grant(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    fp = resolve_client_fp(db, args.client)
    scope = args.scope
    perms = normalize_perms(args.perm)
    for p in perms:
        if p not in PERMS:
            raise ValueError(f"Unknown permission: {p}")
    now = iso_utc_now()
    for p in perms:
        db.execute(
            "INSERT OR REPLACE INTO acls(client_fp,scope,perm,created_at) VALUES(?,?,?,?)",
            (fp, scope, p, now),
        )
    print(json.dumps({"client_fp": fp, "scope": scope, "granted": perms}, indent=2))


def cmd_revoke(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    fp = resolve_client_fp(db, args.client)
    scope = args.scope
    perms = normalize_perms(args.perm)
    if not perms:
        # remove all perms for scope
        db.execute("DELETE FROM acls WHERE client_fp=? AND scope=?", (fp, scope))
        print(json.dumps({"client_fp": fp, "scope": scope, "revoked": "ALL"}, indent=2))
        return
    for p in perms:
        db.execute("DELETE FROM acls WHERE client_fp=? AND scope=? AND perm=?", (fp, scope, p))
    print(json.dumps({"client_fp": fp, "scope": scope, "revoked": perms}, indent=2))


def cmd_list_acls(args: argparse.Namespace) -> None:
    db = KmsDB(args.db)
    fp = resolve_client_fp(db, args.client)
    rows = db.fetchall("SELECT client_fp,scope,perm,created_at FROM acls WHERE client_fp=? ORDER BY scope,perm", (fp,))
    print(json.dumps({"client_fp": fp, "acls": [dict(r) for r in rows]}, indent=2))


# ------------------------ CLI: server/admin ------------------------

def parse_tokens() -> list[str]:
    raw = os.environ.get("KMS_API_TOKENS", "").strip()
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


def cmd_init(args: argparse.Namespace) -> None:
    KmsDB(args.db)
    mkm = MasterKeyManager(MasterKeyConfig(salt_path=args.master_salt))
    _ = mkm.get_key()
    audit = AuditLogger(args.audit)
    audit.append("system", "init", details={"db": args.db, "audit": args.audit, "salt": args.master_salt})
    ok, err = audit.verify()
    print(json.dumps({"initialized": True, "audit_ok": ok, "audit_error": err}, indent=2))


def cmd_verify_audit(args: argparse.Namespace) -> None:
    audit = AuditLogger(args.audit)
    ok, err = audit.verify()
    if ok:
        print(json.dumps({"audit_intact": True}, indent=2))
    else:
        print(json.dumps({"audit_intact": False, "error": err}, indent=2))
        sys.exit(2)


def cmd_serve(args: argparse.Namespace) -> None:
    from http.server import HTTPServer

    db = KmsDB(args.db)
    mkm = MasterKeyManager(MasterKeyConfig(salt_path=args.master_salt))
    audit = AuditLogger(args.audit)

    class _Server(ThreadingHTTPServer, HTTPServer):
        pass

    httpd = _Server((args.host, args.port), KMSHandler)
    httpd.db = db
    httpd.mkm = mkm
    httpd.audit = audit
    httpd.tokens = parse_tokens()
    httpd.allow_bearer_fallback = bearer_fallback_enabled()

    # TLS + mTLS configuration
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        if args.tls_ca:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=args.tls_ca)
            httpd.mtls_required = True
        else:
            httpd.mtls_required = False
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        httpd.mtls_required = False
        scheme = "http"

    audit.append("system", "server.start", details={"host": args.host, "port": args.port, "scheme": scheme, "mtls": httpd.mtls_required, "bearer_fallback": httpd.allow_bearer_fallback})
    print(f"SecuServes KMS listening on {scheme}://{args.host}:{args.port} (db={args.db}, mtls={httpd.mtls_required}, bearer_fallback={httpd.allow_bearer_fallback})")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        audit.append("system", "server.stop")


# ------------------------ Argparse ------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SecuServes - Basic Key Management Server (mTLS + ACL + sign/decrypt)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default="kms.db", help="SQLite DB path")
    common.add_argument("--audit", default="audit.jsonl", help="Audit JSONL path")
    common.add_argument("--master-salt", default="master.salt", help="Master salt file path")

    p_init = sub.add_parser("init", parents=[common], help="Initialize DB and audit log")
    p_init.set_defaults(func=cmd_init)

    p_srv = sub.add_parser("serve", parents=[common], help="Run HTTP(S) server (mTLS recommended; bearer fallback disabled by default)")
    p_srv.add_argument("--host", default="127.0.0.1")
    p_srv.add_argument("--port", type=int, default=8443)
    p_srv.add_argument("--tls-cert", default="", help="Path to TLS certificate (PEM)")
    p_srv.add_argument("--tls-key", default="", help="Path to TLS private key (PEM)")
    p_srv.add_argument("--tls-ca", default="", help="CA bundle (PEM) used to verify *client* certificates (enables mTLS)")
    p_srv.set_defaults(func=cmd_serve)

    p_ver = sub.add_parser("verify-audit", parents=[common], help="Verify audit chain integrity")
    p_ver.set_defaults(func=cmd_verify_audit)

    p_addc = sub.add_parser("add-client", parents=[common], help="Register a client certificate (for mTLS)")
    p_addc.add_argument("--cert", required=True, help="Client certificate PEM (public cert)")
    p_addc.add_argument("--name", default="", help="Friendly client name")
    p_addc.set_defaults(func=cmd_add_client)

    p_disc = sub.add_parser("disable-client", parents=[common], help="Disable a client (name or fingerprint)")
    p_disc.add_argument("--client", required=True, help="Client name or SHA256 fingerprint hex")
    p_disc.set_defaults(func=cmd_disable_client)

    p_lc = sub.add_parser("list-clients", parents=[common], help="List registered clients")
    p_lc.set_defaults(func=cmd_list_clients)

    p_gr = sub.add_parser("grant", parents=[common], help="Grant ACL permissions to a client")
    p_gr.add_argument("--client", required=True, help="Client name or fingerprint")
    p_gr.add_argument(
        "--scope",
        required=True,
        help="Scope: '*' for all keys, or 'name:<keyname>', or 'key:<uuid>'",
    )
    p_gr.add_argument("--perm", required=True, help=f"Comma-separated perms. Known: {', '.join(sorted(PERMS))}")
    p_gr.set_defaults(func=cmd_grant)

    p_rv = sub.add_parser("revoke", parents=[common], help="Revoke ACL permissions from a client")
    p_rv.add_argument("--client", required=True, help="Client name or fingerprint")
    p_rv.add_argument("--scope", required=True, help="Scope: '*', 'name:<keyname>', or 'key:<uuid>'")
    p_rv.add_argument("--perm", default="", help="Comma-separated perms. Omit to revoke ALL perms for the scope")
    p_rv.set_defaults(func=cmd_revoke)

    p_la = sub.add_parser("list-acls", parents=[common], help="List ACLs for a client")
    p_la.add_argument("--client", required=True, help="Client name or fingerprint")
    p_la.set_defaults(func=cmd_list_acls)

    return p


def main() -> None:
    args = build_arg_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()