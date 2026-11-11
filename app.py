"""Local educational secure file-sharing application."""
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"  # Outside static/, addressed only by random IDs.
DB_PATH = BASE_DIR / "instance" / "app.sqlite3"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "docx", "csv"}
MAX_BYTES = 50 * 1024 * 1024

app = Flask(__name__, instance_path=str(BASE_DIR / "instance"))
secret = os.environ.get("FLASK_SECRET_KEY")
if not secret:
    secret = "dev-only-" + secrets.token_hex(32)
    app.logger.warning("Using temporary development secret; set FLASK_SECRET_KEY for stable sessions.")
app.config.update(SECRET_KEY=secret, MAX_CONTENT_LENGTH=MAX_BYTES,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=False)  # local HTTP only; enable HTTPS in deployment
CSRFProtect(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
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
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          storage_name TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL,
          size INTEGER NOT NULL CHECK(size >= 0), extension TEXT NOT NULL, uploaded_at TEXT NOT NULL
        );
    """)
    db.commit()


@app.cli.command("init-db")
def init_db_command():
    """Create the database tables."""
    init_db()
    print(f"Database initialized at {DB_PATH}")


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if g.user is None:
            session.clear()


def login_required():
    if g.user is None:
        flash("Please log in to continue.", "error")
        return redirect(url_for("login"))


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
            flash("Use a password with at least 12 characters.", "error")
        else:
            try:
                get_db().execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                    (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat()))
                get_db().commit()
                app.logger.info("Account created for username=%s", username)
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is unavailable.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = user["id"]
            app.logger.info("Login succeeded for username=%s", username)
            return redirect(url_for("dashboard"))
        app.logger.warning("Login failed for username=%s", username)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if (response := login_required()) is not None:
        return response
    files = get_db().execute("SELECT * FROM files WHERE owner_id=? ORDER BY uploaded_at DESC", (g.user["id"],)).fetchall()
    return render_template("dashboard.html", files=files, max_mb=MAX_BYTES // (1024 * 1024), allowed=", ".join(sorted(ALLOWED_EXTENSIONS)))


@app.post("/upload")
def upload():
    if (response := login_required()) is not None:
        return response
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("dashboard"))
    display_name = secure_filename(uploaded.filename)
    ext = Path(display_name).suffix.lower().lstrip(".")
    if not display_name or ext not in ALLOWED_EXTENSIONS:
        flash("That file type is not allowed.", "error")
        return redirect(url_for("dashboard"))
    storage_name = secrets.token_hex(24)
    path = UPLOAD_DIR / storage_name
    uploaded.save(path)  # Flask enforces MAX_CONTENT_LENGTH while reading.
    size = path.stat().st_size
    try:
        get_db().execute("INSERT INTO files(owner_id,storage_name,original_name,size,extension,uploaded_at) VALUES(?,?,?,?,?,?)",
            (g.user["id"], storage_name, display_name, size, ext, datetime.now(timezone.utc).isoformat()))
        get_db().commit()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    app.logger.info("File uploaded user_id=%s file_id=%s bytes=%s", g.user["id"], storage_name, size)
    flash("File uploaded.", "success")
    return redirect(url_for("dashboard"))


def owned_file(file_id):
    row = get_db().execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    return row


@app.get("/files/<int:file_id>/download")
def download(file_id):
    if (response := login_required()) is not None:
        return response
    row = owned_file(file_id)
    return send_from_directory(UPLOAD_DIR, row["storage_name"], as_attachment=True, download_name=row["original_name"])


@app.post("/files/<int:file_id>/delete")
def delete_file(file_id):
    if (response := login_required()) is not None:
        return response
    row = owned_file(file_id)
    (UPLOAD_DIR / row["storage_name"]).unlink(missing_ok=True)
    get_db().execute("DELETE FROM files WHERE id=? AND owner_id=?", (file_id, g.user["id"]))
    get_db().commit()
    app.logger.info("File deleted user_id=%s file_id=%s", g.user["id"], file_id)
    flash("File deleted.", "success")
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
    app.run(debug=False)

