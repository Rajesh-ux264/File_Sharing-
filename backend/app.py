import os
import re
import json
import sqlite3
import uuid
import time
import hashlib
import zipfile
from io import BytesIO
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file, send_from_directory, g
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.utils import secure_filename

load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
UPLOAD_DIR   = BASE_DIR / "uploads"
DATA_DIR     = BASE_DIR / "data"
DB_PATH      = DATA_DIR / "fileshare.db"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".cmd", ".msi", ".ps1"}
MAX_MB = int(os.getenv("MAX_FILE_SIZE_MB", 100))

# ── App ────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.config["JWT_SECRET_KEY"]           = os.getenv("SECRET_KEY", "change_me_in_production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False
app.config["MAX_CONTENT_LENGTH"]       = MAX_MB * 1024 * 1024

jwt = JWTManager(app)

# ── Database ───────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                created_at  INTEGER DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS files (
                id            TEXT PRIMARY KEY,
                owner_id      TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name   TEXT NOT NULL,
                mime_type     TEXT NOT NULL,
                size          INTEGER NOT NULL,
                share_token   TEXT UNIQUE,
                share_expires INTEGER,
                tags          TEXT DEFAULT '[]',
                summary       TEXT DEFAULT '',
                file_hash     TEXT,
                content_text  TEXT DEFAULT '',
                created_at    INTEGER DEFAULT (strftime('%s','now')),
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id          TEXT PRIMARY KEY,
                file_id     TEXT NOT NULL,
                file_name   TEXT NOT NULL,
                accessor    TEXT DEFAULT 'anonymous',
                ip_address  TEXT,
                access_type TEXT DEFAULT 'download',
                accessed_at INTEGER DEFAULT (strftime('%s','now')),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );
        """)
        # Migrate existing tables — add new columns if missing
        existing = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
        migrations = {
            "tags":           "TEXT DEFAULT '[]'",
            "summary":        "TEXT DEFAULT ''",
            "file_hash":      "TEXT",
            "content_text":   "TEXT DEFAULT ''",
            "download_count": "INTEGER DEFAULT 0",
            "is_public":      "INTEGER DEFAULT 0",
        }
        for col, definition in migrations.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE files ADD COLUMN {col} {definition}")
        conn.commit()

# ── Utility functions ──────────────────────────────────────────────────────
def compute_hash(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_text(file_path: Path, mime_type: str) -> str:
    ext = file_path.suffix.lower()
    try:
        if mime_type == "application/pdf" or ext == ".pdf":
            import pdfplumber
            parts = []
            with pdfplumber.open(str(file_path)) as pdf:
                for page in pdf.pages[:10]:
                    t = page.extract_text()
                    if t:
                        parts.append(t)
            return "\n".join(parts)[:50000]
        elif mime_type.startswith("text/") or ext in (
            ".txt", ".md", ".csv", ".log", ".json", ".xml", ".html", ".py", ".js", ".ts"
        ):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(50000)
    except Exception:
        pass
    return ""


def detect_tags(filename: str, mime_type: str, content_text: str = "") -> list:
    tags = set()
    name  = filename.lower()
    text  = content_text[:5000].lower()
    ext   = Path(filename).suffix.lower()
    combined = name + " " + text

    # Type tags
    if mime_type.startswith("image/") or ext in (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"):
        tags.add("image")
    elif mime_type.startswith("video/") or ext in (".mp4", ".mov", ".avi", ".mkv"):
        tags.add("video")
    elif mime_type.startswith("audio/") or ext in (".mp3", ".wav", ".ogg", ".flac"):
        tags.add("audio")
    elif ext in (".zip", ".rar", ".7z", ".tar", ".gz"):
        tags.add("archive")
    elif ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".rs", ".html", ".css"):
        tags.add("code")
    elif ext in (".xls", ".xlsx", ".csv"):
        tags.add("spreadsheet")
    elif ext in (".ppt", ".pptx"):
        tags.add("presentation")
    elif ext == ".pdf" or "pdf" in mime_type:
        tags.add("pdf")
    elif mime_type.startswith("text/"):
        tags.add("text")

    # Content / name keyword tags
    keyword_map = {
        "invoice":  ["invoice", "bill to", "amount due", "tax invoice", "total due"],
        "receipt":  ["receipt", "order confirmation", "thank you for your purchase"],
        "notes":    ["notes", "meeting notes", "action items", "agenda", "minutes"],
        "report":   ["report", "executive summary", "findings", "analysis", "conclusion"],
        "resume":   ["resume", "curriculum vitae", "work experience", "education", "skills"],
        "contract": ["contract", "agreement", "terms and conditions", "parties agree"],
        "budget":   ["budget", "expenses", "revenue", "forecast", "profit"],
        "photo":    ["photo", "picture", "screenshot"],
    }
    for tag, keywords in keyword_map.items():
        if any(kw in combined for kw in keywords):
            tags.add(tag)

    return sorted(tags)


def generate_summary(text: str, max_chars: int = 300) -> str:
    if not text or len(text.strip()) < 50:
        return ""
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars].rfind(' ')
    return text[:cut if cut > 0 else max_chars] + "..."

# ── Helpers ────────────────────────────────────────────────────────────────
def allowed_ext(filename):
    return Path(filename).suffix.lower() not in BLOCKED_EXTENSIONS

def row_to_dict(row):
    return dict(row) if row else None

def parse_tags(raw):
    try:
        return json.loads(raw or "[]")
    except Exception:
        return []

def log_access(db, file_id, file_name, accessor, access_type="download"):
    ip = request.headers.get("X-Real-IP") or request.remote_addr or "unknown"
    db.execute(
        "INSERT INTO access_logs (id, file_id, file_name, accessor, ip_address, access_type) "
        "VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), file_id, file_name, accessor, ip, access_type)
    )
    db.execute("UPDATE files SET download_count = download_count + 1 WHERE id=?", (file_id,))
    db.commit()

# ── Frontend ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(str(FRONTEND_DIR), "index.html")

@app.route("/dashboard.html")
def dashboard():
    return send_from_directory(str(FRONTEND_DIR), "dashboard.html")

@app.route("/share.html")
def share_page():
    return send_from_directory(str(FRONTEND_DIR), "share.html")

# ── Health ─────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "ts": int(time.time() * 1000)})

# ── Auth ───────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email=? OR username=?", (email, username)).fetchone():
        return jsonify({"error": "Username or email already taken"}), 409

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    hashed  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id = str(uuid.uuid4())
    db.execute("INSERT INTO users (id, username, email, password) VALUES (?,?,?,?)",
               (user_id, username, email, hashed))
    db.commit()

    token = create_access_token(identity=user_id, additional_claims={"username": username})
    return jsonify({"token": token, "username": username}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db   = get_db()
    user = row_to_dict(db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone())
    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid email or password"}), 401

    token = create_access_token(identity=user["id"],
                                additional_claims={"username": user["username"]})
    return jsonify({"token": token, "username": user["username"]})


@app.route("/api/auth/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()
    db   = get_db()
    user = row_to_dict(db.execute(
        "SELECT id, username, email, created_at FROM users WHERE id=?", (user_id,)
    ).fetchone())
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)

# ── Files ──────────────────────────────────────────────────────────────────
@app.route("/api/files")
@jwt_required()
def list_files():
    user_id = get_jwt_identity()
    db   = get_db()
    rows = db.execute(
        "SELECT id, original_name, mime_type, size, share_token, share_expires, "
        "tags, summary, download_count, is_public, created_at FROM files WHERE owner_id=? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["tags"] = parse_tags(r.get("tags"))
        result.append(r)
    return jsonify(result)


@app.route("/api/files/search")
@jwt_required()
def search_files():
    user_id = get_jwt_identity()
    query   = request.args.get("q", "").strip()
    if not query:
        return jsonify([])

    db   = get_db()
    like = f"%{query}%"
    rows = db.execute(
        "SELECT id, original_name, mime_type, size, share_token, share_expires, "
        "tags, summary, content_text, created_at "
        "FROM files WHERE owner_id=? "
        "AND (original_name LIKE ? OR content_text LIKE ? OR tags LIKE ?) "
        "ORDER BY created_at DESC LIMIT 50",
        (user_id, like, like, like)
    ).fetchall()

    results = []
    for row in rows:
        r = dict(row)
        r["tags"] = parse_tags(r.get("tags"))
        # Build a content snippet around the match
        content = r.pop("content_text", "") or ""
        snippet = ""
        if query.lower() in content.lower():
            idx   = content.lower().find(query.lower())
            start = max(0, idx - 80)
            end   = min(len(content), idx + 160)
            snippet = ("..." if start else "") + content[start:end] + ("..." if end < len(content) else "")
        r["snippet"] = snippet
        results.append(r)
    return jsonify(results)


@app.route("/api/files/upload", methods=["POST"])
@jwt_required()
def upload_files():
    user_id  = get_jwt_identity()
    uploaded = request.files.getlist("files")
    force    = request.args.get("force") == "true"

    if not uploaded or all(f.filename == "" for f in uploaded):
        return jsonify({"error": "No files uploaded"}), 400

    db      = get_db()
    results = []

    for f in uploaded:
        if not f.filename:
            continue
        if not allowed_ext(f.filename):
            return jsonify({"error": f"File type not allowed: {f.filename}"}), 400

        original = f.filename
        ext      = Path(secure_filename(original)).suffix
        stored   = str(uuid.uuid4()) + ext
        dest     = UPLOAD_DIR / stored

        f.save(str(dest))
        size      = dest.stat().st_size
        file_hash = compute_hash(dest)

        # Duplicate detection
        if not force:
            dup = row_to_dict(db.execute(
                "SELECT id, original_name, created_at FROM files WHERE owner_id=? AND file_hash=?",
                (user_id, file_hash)
            ).fetchone())
            if dup:
                dest.unlink()
                return jsonify({
                    "duplicate":  True,
                    "filename":   original,
                    "existing":   dup,
                }), 409

        mime      = f.content_type or "application/octet-stream"
        content   = extract_text(dest, mime)
        tags      = detect_tags(original, mime, content)
        summary   = generate_summary(content)
        is_public = 1 if request.form.get("is_public") == "true" else 0

        fid = str(uuid.uuid4())
        db.execute(
            "INSERT INTO files "
            "(id, owner_id, original_name, stored_name, mime_type, size, "
            " tags, summary, file_hash, content_text, is_public) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (fid, user_id, original, stored, mime, size,
             json.dumps(tags), summary, file_hash, content[:50000], is_public)
        )
        results.append({
            "id": fid, "original_name": original,
            "mime_type": mime, "size": size,
            "tags": tags, "summary": summary,
        })

    db.commit()
    return jsonify(results), 201


@app.route("/api/files/public")
@jwt_required()
def public_files():
    db   = get_db()
    rows = db.execute(
        "SELECT f.id, f.original_name, f.mime_type, f.size, f.tags, "
        "f.download_count, f.created_at, u.username AS owner_name "
        "FROM files f JOIN users u ON f.owner_id = u.id "
        "WHERE f.is_public = 1 ORDER BY f.created_at DESC"
    ).fetchall()
    result = []
    for row in rows:
        r = dict(row)
        r["tags"] = parse_tags(r.get("tags"))
        result.append(r)
    return jsonify(result)


@app.route("/api/files/public/<file_id>/download")
@jwt_required()
def download_public_file(file_id):
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND is_public=1", (file_id,)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found or not public"}), 404
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"error": "File data missing"}), 404
    username = get_jwt().get("username", "unknown")
    log_access(db, file_id, row["original_name"], username, "download")
    return send_file(str(path), as_attachment=True, download_name=row["original_name"])


@app.route("/api/toggle-visibility", methods=["POST"])
@jwt_required()
def toggle_visibility():
    user_id = get_jwt_identity()
    data    = request.get_json(silent=True) or {}
    file_id = data.get("file_id")
    if not file_id:
        return jsonify({"error": "file_id required"}), 400
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found"}), 404
    new_val = 0 if row.get("is_public", 0) else 1
    db.execute("UPDATE files SET is_public=? WHERE id=?", (new_val, file_id))
    db.commit()
    return jsonify({"is_public": bool(new_val)})


@app.route("/api/files/<file_id>/download")
@jwt_required()
def download_file(file_id):
    user_id = get_jwt_identity()
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found"}), 404
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"error": "File data missing"}), 404
    username = get_jwt().get("username", "unknown")
    log_access(db, file_id, row["original_name"], username)
    return send_file(str(path), as_attachment=True, download_name=row["original_name"])


@app.route("/api/files/<file_id>/share", methods=["POST"])
@jwt_required()
def create_share(file_id):
    user_id = get_jwt_identity()
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found"}), 404

    data       = request.get_json(silent=True) or {}
    expires_in = data.get("expiresIn")
    token      = uuid.uuid4().hex
    expires    = int(time.time()) + int(expires_in) * 3600 if expires_in else None

    db.execute("UPDATE files SET share_token=?, share_expires=? WHERE id=?",
               (token, expires, file_id))
    db.commit()
    return jsonify({"share_token": token, "share_expires": expires})


@app.route("/api/files/<file_id>/share", methods=["DELETE"])
@jwt_required()
def revoke_share(file_id):
    user_id = get_jwt_identity()
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT id FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found"}), 404
    db.execute("UPDATE files SET share_token=NULL, share_expires=NULL WHERE id=?", (file_id,))
    db.commit()
    return jsonify({"message": "Share link revoked"})


@app.route("/api/files/shared/<token>")
def public_download(token):
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE share_token=?", (token,)
    ).fetchone())
    if not row:
        return jsonify({"error": "Share link not found"}), 404
    if row["share_expires"] and int(time.time()) > row["share_expires"]:
        return jsonify({"error": "Share link has expired"}), 410
    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"error": "File data missing"}), 404
    log_access(db, row["id"], row["original_name"], "public (shared link)")
    return send_file(str(path), as_attachment=True, download_name=row["original_name"])


@app.route("/api/files/shared/<token>/info")
def public_info(token):
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT f.original_name, f.mime_type, f.size, f.share_expires, u.username "
        "FROM files f JOIN users u ON f.owner_id=u.id WHERE f.share_token=?",
        (token,)
    ).fetchone())
    if not row:
        return jsonify({"error": "Share link not found"}), 404
    if row["share_expires"] and int(time.time()) > row["share_expires"]:
        return jsonify({"error": "Share link has expired"}), 410
    return jsonify(row)


@app.route("/api/files/<file_id>", methods=["DELETE"])
@jwt_required()
def delete_file(file_id):
    user_id = get_jwt_identity()
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, user_id)
    ).fetchone())
    if not row:
        return jsonify({"error": "File not found"}), 404
    path = UPLOAD_DIR / row["stored_name"]
    if path.exists():
        path.unlink()
    db.execute("DELETE FROM files WHERE id=?", (file_id,))
    db.commit()
    return jsonify({"message": "File deleted"})


@app.route("/api/files/compress-batch", methods=["POST"])
@jwt_required()
def compress_batch():
    user_id  = get_jwt_identity()
    data     = request.get_json(silent=True) or {}
    file_ids = data.get("file_ids", [])

    if not file_ids:
        return jsonify({"error": "No files selected"}), 400
    if len(file_ids) > 20:
        return jsonify({"error": "Maximum 20 files per batch"}), 400

    db   = get_db()
    rows = db.execute(
        f"SELECT * FROM files WHERE id IN ({','.join(['?']*len(file_ids))}) AND owner_id=?",
        (*file_ids, user_id)
    ).fetchall()

    if not rows:
        return jsonify({"error": "No files found"}), 404

    total_original = 0
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for row in rows:
            r    = dict(row)
            path = UPLOAD_DIR / r["stored_name"]
            if path.exists():
                zf.write(str(path), r["original_name"])
                total_original += path.stat().st_size

    compressed_size = buf.tell()
    buf.seek(0)

    username = get_jwt().get("username", "unknown")
    for row in rows:
        r = dict(row)
        log_access(db, r["id"], r["original_name"], username, "compress")

    resp = send_file(buf, as_attachment=True, download_name="fileshare_batch.zip", mimetype="application/zip")
    resp.headers["X-Original-Size"]   = str(total_original)
    resp.headers["X-Compressed-Size"] = str(compressed_size)
    return resp


# ── Analytics ─────────────────────────────────────────────────────────────
@app.route("/api/analytics")
@jwt_required()
def analytics():
    user_id = get_jwt_identity()
    db = get_db()

    # Summary stats
    stats = row_to_dict(db.execute(
        "SELECT COUNT(*) as total_files, COALESCE(SUM(size),0) as total_size, "
        "COALESCE(SUM(download_count),0) as total_downloads "
        "FROM files WHERE owner_id=?", (user_id,)
    ).fetchone())

    # Storage breakdown by MIME category
    type_rows = db.execute(
        "SELECT mime_type, COUNT(*) as file_count, COALESCE(SUM(size),0) as total_size "
        "FROM files WHERE owner_id=? GROUP BY mime_type ORDER BY total_size DESC LIMIT 8",
        (user_id,)
    ).fetchall()

    # Top 5 files by downloads
    top_files = db.execute(
        "SELECT id, original_name, mime_type, size, download_count "
        "FROM files WHERE owner_id=? ORDER BY download_count DESC LIMIT 5",
        (user_id,)
    ).fetchall()

    # Recent 20 access log entries for this user's files
    recent = db.execute(
        "SELECT al.file_name, al.accessor, al.ip_address, al.access_type, al.accessed_at "
        "FROM access_logs al "
        "JOIN files f ON al.file_id = f.id "
        "WHERE f.owner_id=? ORDER BY al.accessed_at DESC LIMIT 20",
        (user_id,)
    ).fetchall()

    return jsonify({
        "total_files":     stats["total_files"],
        "total_size":      stats["total_size"],
        "total_downloads": stats["total_downloads"],
        "storage_by_type": [dict(r) for r in type_rows],
        "top_files":       [dict(r) for r in top_files],
        "recent_access":   [dict(r) for r in recent],
    })

# ── Error handlers ─────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large. Max size is {MAX_MB} MB"}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 3000))
    print(f"\n  FileShare running at: http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port,
            debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
