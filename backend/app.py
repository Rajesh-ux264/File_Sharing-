import os
import sqlite3
import uuid
import time
from pathlib import Path

import bcrypt
from dotenv import load_dotenv
from flask import (
    Flask, request, jsonify, send_file, send_from_directory, g
)
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
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
app.config["JWT_SECRET_KEY"]        = os.getenv("SECRET_KEY", "change_me_in_production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = False   # set to timedelta(days=7) in prod
app.config["MAX_CONTENT_LENGTH"]    = MAX_MB * 1024 * 1024

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
                created_at    INTEGER DEFAULT (strftime('%s','now')),
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

# ── Helpers ────────────────────────────────────────────────────────────────
def allowed_ext(filename):
    ext = Path(filename).suffix.lower()
    return ext not in BLOCKED_EXTENSIONS

def row_to_dict(row):
    return dict(row) if row else None

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
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    db = get_db()

    if db.execute("SELECT id FROM users WHERE email=? OR username=?", (email, username)).fetchone():
        return jsonify({"error": "Username or email already taken"}), 409

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    hashed   = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user_id  = str(uuid.uuid4())
    db.execute(
        "INSERT INTO users (id, username, email, password) VALUES (?,?,?,?)",
        (user_id, username, email, hashed)
    )
    db.commit()

    token = create_access_token(identity={"id": user_id, "username": username})
    return jsonify({"token": token, "username": username}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db   = get_db()
    user = row_to_dict(db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone())

    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid email or password"}), 401

    token = create_access_token(identity={"id": user["id"], "username": user["username"]})
    return jsonify({"token": token, "username": user["username"]})


@app.route("/api/auth/me")
@jwt_required()
def me():
    identity = get_jwt_identity()
    db   = get_db()
    user = row_to_dict(db.execute(
        "SELECT id, username, email, created_at FROM users WHERE id=?",
        (identity["id"],)
    ).fetchone())
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)

# ── Files ──────────────────────────────────────────────────────────────────
@app.route("/api/files")
@jwt_required()
def list_files():
    identity = get_jwt_identity()
    db = get_db()
    rows = db.execute(
        "SELECT id, original_name, mime_type, size, share_token, share_expires, created_at "
        "FROM files WHERE owner_id=? ORDER BY created_at DESC",
        (identity["id"],)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/upload", methods=["POST"])
@jwt_required()
def upload_files():
    identity = get_jwt_identity()
    uploaded = request.files.getlist("files")

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
        size     = 0

        dest = UPLOAD_DIR / stored
        f.save(str(dest))
        size = dest.stat().st_size

        mime   = f.content_type or "application/octet-stream"
        fid    = str(uuid.uuid4())
        db.execute(
            "INSERT INTO files (id, owner_id, original_name, stored_name, mime_type, size) "
            "VALUES (?,?,?,?,?,?)",
            (fid, identity["id"], original, stored, mime, size)
        )
        results.append({"id": fid, "original_name": original, "mime_type": mime, "size": size})

    db.commit()
    return jsonify(results), 201


@app.route("/api/files/<file_id>/download")
@jwt_required()
def download_file(file_id):
    identity = get_jwt_identity()
    db   = get_db()
    row  = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?",
        (file_id, identity["id"])
    ).fetchone())

    if not row:
        return jsonify({"error": "File not found"}), 404

    path = UPLOAD_DIR / row["stored_name"]
    if not path.exists():
        return jsonify({"error": "File data missing"}), 404

    return send_file(str(path), as_attachment=True, download_name=row["original_name"])


@app.route("/api/files/<file_id>/share", methods=["POST"])
@jwt_required()
def create_share(file_id):
    identity  = get_jwt_identity()
    db        = get_db()
    row       = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?",
        (file_id, identity["id"])
    ).fetchone())

    if not row:
        return jsonify({"error": "File not found"}), 404

    data      = request.get_json(silent=True) or {}
    expires_in = data.get("expiresIn")
    token     = uuid.uuid4().hex
    expires   = int(time.time()) + int(expires_in) * 3600 if expires_in else None

    db.execute(
        "UPDATE files SET share_token=?, share_expires=? WHERE id=?",
        (token, expires, file_id)
    )
    db.commit()
    return jsonify({"share_token": token, "share_expires": expires})


@app.route("/api/files/<file_id>/share", methods=["DELETE"])
@jwt_required()
def revoke_share(file_id):
    identity = get_jwt_identity()
    db = get_db()
    row = row_to_dict(db.execute(
        "SELECT id FROM files WHERE id=? AND owner_id=?",
        (file_id, identity["id"])
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
    identity = get_jwt_identity()
    db  = get_db()
    row = row_to_dict(db.execute(
        "SELECT * FROM files WHERE id=? AND owner_id=?",
        (file_id, identity["id"])
    ).fetchone())

    if not row:
        return jsonify({"error": "File not found"}), 404

    path = UPLOAD_DIR / row["stored_name"]
    if path.exists():
        path.unlink()

    db.execute("DELETE FROM files WHERE id=?", (file_id,))
    db.commit()
    return jsonify({"message": "File deleted"})


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
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
