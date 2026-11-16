"""SecureShare — Minimal Pure-White Encrypted File-Sharing Application with Live Real-Time Sync."""
import hashlib
import io
import json
import logging
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from flask import (Flask, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, send_file, session,
                   stream_with_context, url_for)
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"  # Outside static/, stores AES-256-GCM encrypted blobs by random hex ID.
DB_PATH = BASE_DIR / "instance" / "app.sqlite3"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "docx", "csv", "zip", "json", "md"}
MAX_BYTES = 50 * 1024 * 1024
USER_QUOTA_BYTES = 250 * 1024 * 1024  # 250 MB per-account vault quota

TEMPLATE_DIR = BASE_DIR / "templates" if (BASE_DIR / "templates").is_dir() else BASE_DIR
STATIC_DIR = BASE_DIR / "static" if (BASE_DIR / "static").is_dir() else BASE_DIR
app = Flask(
    __name__,
    instance_path=str(BASE_DIR / "instance"),
    template_folder=str(TEMPLATE_DIR),
    static_folder=str(STATIC_DIR),
)
secret = os.environ.get("FLASK_SECRET_KEY")
if not secret:
    secret = "dev-only-" + secrets.token_hex(32)
    app.logger.warning("Using temporary development secret; set FLASK_SECRET_KEY for stable sessions.")

master_key_material = os.environ.get("VAULT_MASTER_KEY") or secret
app.config.update(
    SECRET_KEY=secret,
    VAULT_MASTER_KEY=master_key_material,
    MAX_CONTENT_LENGTH=MAX_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # local HTTP only; enable HTTPS in deployment
)
CSRFProtect(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Cryptographic Engine: AES-256-GCM Envelope Encryption + SHA-256 Integrity
# ---------------------------------------------------------------------------
def derive_vault_key(salt: bytes) -> bytes:
    """Derive a 256-bit AES key from VAULT_MASTER_KEY and a per-file 16-byte salt using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secureshare-aes256gcm-v2",
    )
    return hkdf.derive(app.config["VAULT_MASTER_KEY"].encode("utf-8"))


def encrypt_payload(plaintext: bytes) -> tuple[bytes, str]:
    """
    Compute SHA-256 of plaintext and encrypt using AES-256-GCM.
    Format on disk: [4B magic b'CV02'][16B salt][12B nonce][ciphertext + 16B GCM tag]
    """
    sha256_hex = hashlib.sha256(plaintext).hexdigest()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_vault_key(salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, b"CV02")
    blob = b"CV02" + salt + nonce + ciphertext
    return blob, sha256_hex


def decrypt_payload(blob: bytes, is_encrypted: int) -> bytes:
    """Decrypt an AES-256-GCM vault blob (or return raw bytes for legacy unencrypted files)."""
    if not is_encrypted or not blob.startswith(b"CV02"):
        return blob
    if len(blob) < 4 + 16 + 12 + 16:
        raise ValueError("Corrupted encrypted blob header.")
    salt = blob[4:20]
    nonce = blob[20:32]
    ciphertext = blob[32:]
    key = derive_vault_key(salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, b"CV02")


def human_size(num_bytes: int) -> str:
    """Format byte counts into readable KB / MB strings."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


app.jinja_env.filters["human_size"] = human_size


# ---------------------------------------------------------------------------
# Database & Schema Migration
# ---------------------------------------------------------------------------
_DB_INITIALIZED = False


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15.0)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA synchronous = NORMAL")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY,
          owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          storage_name TEXT NOT NULL UNIQUE,
          original_name TEXT NOT NULL,
          size INTEGER NOT NULL CHECK(size >= 0),
          extension TEXT NOT NULL,
          sha256_hash TEXT NOT NULL DEFAULT '',
          is_encrypted INTEGER NOT NULL DEFAULT 1,
          category_tag TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
          download_count INTEGER NOT NULL DEFAULT 0,
          uploaded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS file_shares (
          id INTEGER PRIMARY KEY,
          file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
          owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          share_token TEXT UNIQUE,
          passcode_hash TEXT,
          max_downloads INTEGER NOT NULL DEFAULT 0,
          download_count INTEGER NOT NULL DEFAULT 0,
          expires_at TEXT,
          is_revoked INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          actor_username TEXT NOT NULL,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL DEFAULT 'INFO',
          details TEXT NOT NULL,
          ip_address TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
    """)
    existing_cols = {row["name"] for row in db.execute("PRAGMA table_info(files)").fetchall()}
    migrations = [
        ("sha256_hash", "ALTER TABLE files ADD COLUMN sha256_hash TEXT NOT NULL DEFAULT ''"),
        ("is_encrypted", "ALTER TABLE files ADD COLUMN is_encrypted INTEGER NOT NULL DEFAULT 0"),
        ("category_tag", "ALTER TABLE files ADD COLUMN category_tag TEXT NOT NULL DEFAULT 'CONFIDENTIAL'"),
        ("download_count", "ALTER TABLE files ADD COLUMN download_count INTEGER NOT NULL DEFAULT 0"),
    ]
    for col_name, ddl in migrations:
        if col_name not in existing_cols:
            db.execute(ddl)
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    """Create or migrate the database tables."""
    init_db()
    print(f"Database initialized and migrated at {DB_PATH}")


def log_security_event(event_type: str, details: str, severity: str = "INFO",
                       user_id: int | None = None, username: str | None = None):
    """Record a security event in SQLite and application logs."""
    actor_id = user_id if user_id is not None else (g.user["id"] if getattr(g, "user", None) else None)
    actor_name = username or (g.user["username"] if getattr(g, "user", None) else "anonymous")
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        db = get_db()
        db.execute(
            """INSERT INTO audit_logs(user_id, actor_username, event_type, severity, details, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (actor_id, actor_name, event_type, severity, details, ip_addr, now_iso),
        )
        db.commit()
    except Exception as exc:
        app.logger.warning("Could not write audit log: %s", exc)
    app.logger.info("[%s] %s user=%s ip=%s :: %s", severity, event_type, actor_name, ip_addr, details)


# ---------------------------------------------------------------------------
# Request Lifecycle, Cache-Busting & Security Headers
# ---------------------------------------------------------------------------
@app.before_request
def load_user():
    global _DB_INITIALIZED
    if not _DB_INITIALIZED:
        init_db()
        _DB_INITIALIZED = True
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute("SELECT id, username, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        if g.user is None:
            session.clear()


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Prevent stale browser caching so every visit/navigation fetches live state
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


def login_required():
    if g.user is None:
        flash("Please sign in to access your workspace.", "error")
        return redirect(url_for("login"))


def is_expired(expires_at_str: str | None) -> bool:
    if not expires_at_str:
        return False
    try:
        exp = datetime.fromisoformat(expires_at_str)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp
    except ValueError:
        return False


def compute_user_sync_state(db, uid: int, username: str) -> dict:
    """Build a lightweight state fingerprint & payload for real-time automatic UI updates."""
    files = db.execute(
        "SELECT id, original_name, size, extension, sha256_hash, category_tag, download_count, uploaded_at FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC",
        (uid,),
    ).fetchall()

    total_bytes = sum(f["size"] for f in files)
    quota_pct = min(100.0, round((total_bytes / USER_QUOTA_BYTES) * 100, 1)) if USER_QUOTA_BYTES else 0.0

    shared_with_me_rows = db.execute(
        """SELECT fs.id AS share_id, fs.created_at AS shared_at, fs.expires_at,
                  fs.max_downloads, fs.download_count AS share_downloads,
                  f.id AS file_id, f.original_name, f.size, f.extension,
                  f.sha256_hash, f.category_tag, u.username AS owner_username
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           JOIN users u ON u.id = fs.owner_id
           WHERE fs.recipient_id = ? AND fs.is_revoked = 0
           ORDER BY fs.created_at DESC""",
        (uid,),
    ).fetchall()
    active_shared_with_me = [dict(r) for r in shared_with_me_rows if not is_expired(r["expires_at"])]
    for item in active_shared_with_me:
        item["human_size"] = human_size(item["size"])

    my_shares_rows = db.execute(
        """SELECT fs.id, fs.file_id, fs.share_token, fs.passcode_hash,
                  fs.max_downloads, fs.download_count, fs.expires_at, fs.created_at,
                  f.original_name, u.username AS recipient_username
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           LEFT JOIN users u ON u.id = fs.recipient_id
           WHERE fs.owner_id = ? AND fs.is_revoked = 0
           ORDER BY fs.created_at DESC""",
        (uid,),
    ).fetchall()

    audit_rows = db.execute(
        """SELECT id, event_type, severity, details, ip_address, created_at
           FROM audit_logs
           WHERE user_id = ? OR actor_username = ?
           ORDER BY id DESC LIMIT 25""",
        (uid, username),
    ).fetchall()

    files_list = []
    for f in files:
        d = dict(f)
        d["human_size"] = human_size(f["size"])
        files_list.append(d)

    my_shares_list = []
    for s in my_shares_rows:
        d = dict(s)
        d["has_passcode"] = bool(s["passcode_hash"])
        d.pop("passcode_hash", None)
        my_shares_list.append(d)

    audit_list = [dict(a) for a in audit_rows]

    raw_sig = json.dumps(
        {
            "f": [(f["id"], f["download_count"], f["uploaded_at"]) for f in files_list],
            "in": [(s["share_id"], s["share_downloads"]) for s in active_shared_with_me],
            "out": [(s["id"], s["download_count"]) for s in my_shares_list],
            "log": audit_list[0]["id"] if audit_list else 0,
        },
        sort_keys=True,
    )
    version_hash = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()[:16]

    return {
        "version": version_hash,
        "server_time": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        "metrics": {
            "files_count": len(files_list),
            "used_human": human_size(total_bytes),
            "quota_human": human_size(USER_QUOTA_BYTES),
            "quota_pct": quota_pct,
            "my_shares_count": len(my_shares_list),
            "shared_with_me_count": len(active_shared_with_me),
        },
        "files": files_list,
        "shared_with_me": active_shared_with_me,
        "my_shares": my_shares_list,
        "audit_events": audit_list,
    }


# ---------------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 40 or not username.isalnum():
            flash("Username must be 3–40 letters or numbers.", "error")
        elif len(password) < 12:
            flash("Password must be at least 12 characters long.", "error")
        else:
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                cur = get_db().execute(
                    "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                    (username, generate_password_hash(password), now_iso),
                )
                get_db().commit()
                log_security_event(
                    "ACCOUNT_CREATED",
                    f"Account '{username}' registered with salted password hash.",
                    severity="SUCCESS",
                    user_id=cur.lastrowid,
                    username=username,
                )
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                log_security_event("REGISTER_CONFLICT", f"Duplicate registration attempt for '{username}'.", severity="WARN")
                flash("That username is already taken.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            log_security_event(
                "AUTH_SUCCESS",
                f"Session started for '{username}'.",
                severity="SUCCESS",
                user_id=user["id"],
                username=username,
            )
            return redirect(url_for("dashboard"))
        log_security_event(
            "AUTH_FAILURE",
            f"Failed sign-in attempt for username='{username or 'empty'}'.",
            severity="ALERT",
            username=username or "unknown",
        )
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    if g.user:
        log_security_event("SESSION_ENDED", f"User '{g.user['username']}' signed out.", severity="INFO")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Workspace Dashboard & Real-Time Live Sync Endpoints
# ---------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    if (response := login_required()) is not None:
        return response
    db = get_db()
    uid = g.user["id"]

    q = request.args.get("q", "").strip()
    tag_filter = request.args.get("tag", "").strip().upper()

    sql = "SELECT * FROM files WHERE owner_id = ?"
    params: list = [uid]
    if q:
        sql += " AND (original_name LIKE ? OR sha256_hash LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if tag_filter and tag_filter in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
        sql += " AND category_tag = ?"
        params.append(tag_filter)
    sql += " ORDER BY uploaded_at DESC"
    files = db.execute(sql, tuple(params)).fetchall()

    total_bytes_row = db.execute("SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner_id = ?", (uid,)).fetchone()
    used_bytes = total_bytes_row["total"] if total_bytes_row else 0
    quota_pct = min(100.0, round((used_bytes / USER_QUOTA_BYTES) * 100, 1)) if USER_QUOTA_BYTES else 0.0

    shared_with_me = db.execute(
        """SELECT fs.id AS share_id, fs.created_at AS shared_at, fs.expires_at,
                  fs.max_downloads, fs.download_count AS share_downloads,
                  f.id AS file_id, f.original_name, f.size, f.extension,
                  f.sha256_hash, f.category_tag, u.username AS owner_username
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           JOIN users u ON u.id = fs.owner_id
           WHERE fs.recipient_id = ? AND fs.is_revoked = 0
           ORDER BY fs.created_at DESC""",
        (uid,),
    ).fetchall()
    active_shared_with_me = [row for row in shared_with_me if not is_expired(row["expires_at"])]

    my_shares = db.execute(
        """SELECT fs.*, f.original_name, u.username AS recipient_username
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           LEFT JOIN users u ON u.id = fs.recipient_id
           WHERE fs.owner_id = ? AND fs.is_revoked = 0
           ORDER BY fs.created_at DESC""",
        (uid,),
    ).fetchall()

    audit_events = db.execute(
        """SELECT * FROM audit_logs
           WHERE user_id = ? OR actor_username = ?
           ORDER BY id DESC LIMIT 25""",
        (uid, g.user["username"]),
    ).fetchall()

    other_users = db.execute("SELECT username FROM users WHERE id != ? ORDER BY username ASC", (uid,)).fetchall()
    initial_sync = compute_user_sync_state(db, uid, g.user["username"])

    return render_template(
        "dashboard.html",
        files=files,
        shared_with_me=active_shared_with_me,
        my_shares=my_shares,
        audit_events=audit_events,
        other_users=other_users,
        used_bytes=used_bytes,
        quota_bytes=USER_QUOTA_BYTES,
        quota_pct=quota_pct,
        max_mb=MAX_BYTES // (1024 * 1024),
        allowed=", ".join(sorted(ALLOWED_EXTENSIONS)),
        search_query=q,
        tag_filter=tag_filter,
        initial_version=initial_sync["version"],
    )


@app.get("/api/live-state")
def api_live_state():
    """Return full real-time workspace state JSON so the UI updates automatically without page reload."""
    if g.user is None:
        return jsonify({"error": "unauthorized"}), 401
    state = compute_user_sync_state(get_db(), g.user["id"], g.user["username"])
    return jsonify(state)


@app.get("/api/stream")
def api_stream():
    """Server-Sent Events (SSE) stream that pushes instant notifications when files or shares change."""
    if g.user is None:
        return jsonify({"error": "unauthorized"}), 401
    uid = g.user["id"]
    uname = g.user["username"]

    @stream_with_context
    def event_generator():
        last_version = None
        # Stream for up to 25 seconds per connection; EventSource automatically reconnects
        for _ in range(12):
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            try:
                state = compute_user_sync_state(conn, uid, uname)
            finally:
                conn.close()
            if state["version"] != last_version:
                last_version = state["version"]
                yield f"data: {json.dumps(state)}\n\n"
            time.sleep(2)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# File Upload (Supports both AJAX Instant Upload & Standard Form POST)
# ---------------------------------------------------------------------------
@app.post("/upload")
def upload():
    if (response := login_required()) is not None:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "Authentication required."}), 401
        return response

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        msg = "Select a file to encrypt and upload."
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for("dashboard"))

    display_name = secure_filename(uploaded.filename)
    ext = Path(display_name).suffix.lower().lstrip(".")
    if not display_name or ext not in ALLOWED_EXTENSIONS:
        log_security_event("UPLOAD_REJECTED", f"Blocked disallowed file extension '.{ext}' ({display_name}).", severity="WARN")
        msg = f"File type '.{ext or 'unknown'}' is not allowed."
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for("dashboard"))

    category_tag = request.form.get("category_tag", "CONFIDENTIAL").strip().upper()
    if category_tag not in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
        category_tag = "CONFIDENTIAL"

    plaintext = uploaded.read()
    size = len(plaintext)

    db = get_db()
    used_row = db.execute("SELECT COALESCE(SUM(size), 0) AS total FROM files WHERE owner_id = ?", (g.user["id"],)).fetchone()
    if (used_row["total"] if used_row else 0) + size > USER_QUOTA_BYTES:
        log_security_event("QUOTA_EXCEEDED", f"Upload of {human_size(size)} exceeded storage quota.", severity="WARN")
        msg = "Storage quota exceeded (250 MB limit)."
        if is_ajax:
            return jsonify({"ok": False, "error": msg}), 400
        flash(msg, "error")
        return redirect(url_for("dashboard"))

    encrypted_blob, sha256_hex = encrypt_payload(plaintext)
    storage_name = secrets.token_hex(24)
    path = UPLOAD_DIR / storage_name
    path.write_bytes(encrypted_blob)

    try:
        db.execute(
            """INSERT INTO files(owner_id, storage_name, original_name, size, extension,
                                 sha256_hash, is_encrypted, category_tag, uploaded_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
            (
                g.user["id"],
                storage_name,
                display_name,
                size,
                ext,
                sha256_hex,
                category_tag,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        db.commit()
    except Exception:
        path.unlink(missing_ok=True)
        raise

    log_security_event(
        "FILE_UPLOADED",
        f"Encrypted '{display_name}' ({human_size(size)}, AES-256-GCM, SHA256={sha256_hex[:12]}…).",
        severity="SUCCESS",
    )
    success_msg = f"Encrypted and uploaded '{display_name}' (SHA-256: {sha256_hex[:16]}…)."
    if is_ajax:
        state = compute_user_sync_state(db, g.user["id"], g.user["username"])
        return jsonify({"ok": True, "message": success_msg, "state": state})

    flash(success_msg, "success")
    return redirect(url_for("dashboard"))


def owned_file(file_id: int):
    row = get_db().execute("SELECT * FROM files WHERE id = ? AND owner_id = ?", (file_id, g.user["id"])).fetchone()
    if row is None:
        log_security_event("UNAUTHORIZED_ACCESS", f"Denied access to file_id={file_id}.", severity="ALERT")
        abort(404)
    return row


def stream_decrypted_file(file_row):
    """Read, decrypt, and verify SHA-256 integrity of a stored file before streaming to client."""
    disk_path = UPLOAD_DIR / file_row["storage_name"]
    if not disk_path.exists():
        abort(404)
    raw_blob = disk_path.read_bytes()
    try:
        plaintext = decrypt_payload(raw_blob, file_row["is_encrypted"])
    except Exception:
        log_security_event(
            "INTEGRITY_TAMPER_ALERT",
            f"AES-GCM authentication tag verification failed for '{file_row['original_name']}'!",
            severity="ALERT",
        )
        flash("File failed AES-256-GCM authentication check (tampering detected).", "error")
        abort(400)

    computed_hash = hashlib.sha256(plaintext).hexdigest()
    if file_row["sha256_hash"] and computed_hash != file_row["sha256_hash"]:
        log_security_event(
            "HASH_MISMATCH_ALERT",
            f"SHA-256 mismatch on '{file_row['original_name']}'!",
            severity="ALERT",
        )
        abort(400)

    get_db().execute("UPDATE files SET download_count = download_count + 1 WHERE id = ?", (file_row["id"],))
    get_db().commit()

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=file_row["original_name"],
        mimetype="application/octet-stream",
    )


@app.get("/files/<int:file_id>/download")
def download(file_id: int):
    if (response := login_required()) is not None:
        return response
    row = owned_file(file_id)
    log_security_event("FILE_DOWNLOADED", f"Owner decrypted & downloaded '{row['original_name']}'.", severity="INFO")
    return stream_decrypted_file(row)


@app.post("/files/<int:file_id>/verify")
def verify_integrity(file_id: int):
    """On-demand cryptographic integrity & authenticity verification check."""
    if (response := login_required()) is not None:
        return response
    row = owned_file(file_id)
    disk_path = UPLOAD_DIR / row["storage_name"]
    if not disk_path.exists():
        flash("Storage object missing from disk.", "error")
        return redirect(url_for("dashboard"))

    try:
        plaintext = decrypt_payload(disk_path.read_bytes(), row["is_encrypted"])
        live_hash = hashlib.sha256(plaintext).hexdigest()
        expected = row["sha256_hash"] or live_hash
        if live_hash == expected:
            log_security_event(
                "INTEGRITY_VERIFIED",
                f"Verified '{row['original_name']}' — AES-GCM tag & SHA-256 ({live_hash[:12]}…) intact.",
                severity="SUCCESS",
            )
            flash(f"Integrity verified: '{row['original_name']}' (SHA-256: {live_hash[:16]}…).", "success")
        else:
            log_security_event("INTEGRITY_FAILED", f"SHA-256 mismatch for '{row['original_name']}'!", severity="ALERT")
            flash("Integrity alert: SHA-256 checksum does not match recorded baseline.", "error")
    except Exception:
        log_security_event("INTEGRITY_FAILED", f"AES-256-GCM tag failure on '{row['original_name']}'!", severity="ALERT")
        flash("Tamper alert: AES-256-GCM authentication tag failed verification.", "error")
    return redirect(url_for("dashboard"))


@app.post("/files/<int:file_id>/delete")
def delete_file(file_id: int):
    if (response := login_required()) is not None:
        return response
    row = owned_file(file_id)
    (UPLOAD_DIR / row["storage_name"]).unlink(missing_ok=True)
    get_db().execute("DELETE FROM files WHERE id = ? AND owner_id = ?", (file_id, g.user["id"]))
    get_db().commit()
    log_security_event("FILE_DELETED", f"Deleted '{row['original_name']}' (id={file_id}).", severity="WARN")
    flash(f"Deleted '{row['original_name']}'.", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Secure File Sharing: Peer-to-Peer Grants & Expiring Passcode Links
# ---------------------------------------------------------------------------
@app.post("/files/<int:file_id>/share")
def create_share(file_id: int):
    if (response := login_required()) is not None:
        return response
    file_row = owned_file(file_id)
    share_mode = request.form.get("share_mode", "link").strip().lower()
    expiry_hours = int(request.form.get("expiry_hours", "24") or "24")
    max_downloads = max(0, int(request.form.get("max_downloads", "0") or "0"))
    passcode = request.form.get("passcode", "").strip()

    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=expiry_hours)).isoformat() if expiry_hours > 0 else None
    passcode_hash = generate_password_hash(passcode) if passcode else None

    db = get_db()
    if share_mode == "user":
        recipient_username = request.form.get("recipient_username", "").strip()
        recipient = db.execute("SELECT id, username FROM users WHERE username = ?", (recipient_username,)).fetchone()
        if not recipient:
            flash(f"User '{recipient_username}' was not found.", "error")
            return redirect(url_for("dashboard"))
        if recipient["id"] == g.user["id"]:
            flash("You already own this file.", "error")
            return redirect(url_for("dashboard"))

        db.execute(
            """INSERT INTO file_shares(file_id, owner_id, recipient_id, max_downloads, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (file_row["id"], g.user["id"], recipient["id"], max_downloads, expires_at, now.isoformat()),
        )
        db.commit()
        log_security_event(
            "USER_SHARE_GRANTED",
            f"Shared '{file_row['original_name']}' with user '{recipient['username']}'.",
            severity="SUCCESS",
        )
        flash(f"Shared '{file_row['original_name']}' with '{recipient['username']}'. It will appear on their dashboard automatically.", "success")
    else:
        token = secrets.token_urlsafe(24)
        db.execute(
            """INSERT INTO file_shares(file_id, owner_id, share_token, passcode_hash, max_downloads, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (file_row["id"], g.user["id"], token, passcode_hash, max_downloads, expires_at, now.isoformat()),
        )
        db.commit()
        share_url = url_for("access_share_link", token=token, _external=True)
        log_security_event(
            "SHARE_LINK_CREATED",
            f"Created expiring share link for '{file_row['original_name']}' (max_dl={max_downloads or 'unlimited'}).",
            severity="SUCCESS",
        )
        flash(f"Share link created: {share_url}", "success")

    return redirect(url_for("dashboard"))


@app.get("/shared/<int:share_id>/download")
def download_peer_share(share_id: int):
    """Download a file shared directly with the signed-in recipient."""
    if (response := login_required()) is not None:
        return response
    db = get_db()
    share = db.execute(
        """SELECT fs.*, f.original_name
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           WHERE fs.id = ? AND fs.recipient_id = ? AND fs.is_revoked = 0""",
        (share_id, g.user["id"]),
    ).fetchone()
    if not share:
        abort(404)
    if is_expired(share["expires_at"]):
        flash("This shared file access has expired.", "error")
        return redirect(url_for("dashboard"))
    if share["max_downloads"] > 0 and share["download_count"] >= share["max_downloads"]:
        flash("Maximum download limit reached for this shared file.", "error")
        return redirect(url_for("dashboard"))

    file_row = db.execute("SELECT * FROM files WHERE id = ?", (share["file_id"],)).fetchone()
    if not file_row:
        abort(404)

    db.execute("UPDATE file_shares SET download_count = download_count + 1 WHERE id = ?", (share_id,))
    db.commit()
    log_security_event(
        "SHARED_FILE_DOWNLOADED",
        f"User '{g.user['username']}' downloaded shared file '{file_row['original_name']}'.",
        severity="INFO",
    )
    return stream_decrypted_file(file_row)


@app.route("/s/<token>", methods=["GET", "POST"])
def access_share_link(token: str):
    """Access or download a file via a tokenized share link (with optional passcode protection)."""
    db = get_db()
    share = db.execute(
        """SELECT fs.*, f.original_name, f.size, f.extension, f.sha256_hash,
                  f.category_tag, u.username AS owner_username
           FROM file_shares fs
           JOIN files f ON f.id = fs.file_id
           JOIN users u ON u.id = fs.owner_id
           WHERE fs.share_token = ? AND fs.is_revoked = 0""",
        (token,),
    ).fetchone()
    if not share:
        abort(404)

    expired = is_expired(share["expires_at"])
    limit_reached = share["max_downloads"] > 0 and share["download_count"] >= share["max_downloads"]

    if request.method == "POST":
        if expired or limit_reached:
            flash("This share link is no longer active.", "error")
            return redirect(url_for("access_share_link", token=token))

        if share["passcode_hash"]:
            supplied_passcode = request.form.get("passcode", "")
            if not check_password_hash(share["passcode_hash"], supplied_passcode):
                log_security_event(
                    "SHARE_PASSCODE_FAILED",
                    f"Invalid passcode entered for token={token[:8]}… ('{share['original_name']}').",
                    severity="WARN",
                )
                flash("Invalid passcode.", "error")
                return render_template("share_access.html", share=share, expired=expired, limit_reached=limit_reached)

        file_row = db.execute("SELECT * FROM files WHERE id = ?", (share["file_id"],)).fetchone()
        if not file_row:
            abort(404)

        db.execute("UPDATE file_shares SET download_count = download_count + 1 WHERE id = ?", (share["id"],))
        db.commit()
        log_security_event(
            "LINK_SHARE_DOWNLOADED",
            f"Share link download completed for '{file_row['original_name']}' (token={token[:8]}…).",
            severity="INFO",
        )
        return stream_decrypted_file(file_row)

    return render_template("share_access.html", share=share, expired=expired, limit_reached=limit_reached)


@app.post("/shares/<int:share_id>/revoke")
def revoke_share(share_id: int):
    if (response := login_required()) is not None:
        return response
    db = get_db()
    share = db.execute(
        "SELECT * FROM file_shares WHERE id = ? AND owner_id = ?",
        (share_id, g.user["id"]),
    ).fetchone()
    if not share:
        abort(404)
    db.execute("UPDATE file_shares SET is_revoked = 1 WHERE id = ?", (share_id,))
    db.commit()
    log_security_event("SHARE_REVOKED", f"Revoked share grant id={share_id}.", severity="WARN")
    flash("Share access revoked.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def too_large(_error):
    flash(f"File exceeds the {MAX_BYTES // (1024 * 1024)} MB upload limit.", "error")
    return redirect(url_for("dashboard" if g.user else "login"))


@app.errorhandler(500)
def server_error(_error):
    app.logger.exception("Unhandled application error")
    return "The request could not be completed. Please try again.", 500


if __name__ == "__main__":
    app.run(debug=False, threaded=True)
