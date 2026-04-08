import re
import sqlite3
import urllib.parse
from flask import Flask, g, jsonify, request, session


DB_SEED_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user',
    email    TEXT,
    ssn      TEXT,
    salary   INTEGER,
    department TEXT
);
CREATE TABLE IF NOT EXISTS expenses (
    id      INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title   TEXT NOT NULL,
    amount  REAL NOT NULL,
    status  TEXT NOT NULL DEFAULT 'pending',
    notes   TEXT
);
INSERT OR IGNORE INTO users VALUES
    (1,'admin','C0rp@dm1n2024','admin','admin@corp.internal','843-29-1923',185000,'Executive'),
    (2,'alice','alice123','user','alice@corp.internal','234-56-7890',75000,'Engineering'),
    (3,'bob','bob456','user','bob@corp.internal','345-67-8901',68000,'Sales'),
    (4,'carol','carol789','user','carol@corp.internal','456-78-9012',82000,'Finance');
INSERT OR IGNORE INTO expenses VALUES
    (1,1,'Q4 Executive Strategy Retreat',24500.00,'approved','Board approved'),
    (2,1,'Security Audit - External Vendor',45000.00,'approved','NDA on file'),
    (3,2,'Engineering team lunch',280.00,'pending','Monthly event'),
    (4,3,'NYC client meeting travel',1200.00,'approved','Receipts attached'),
    (5,4,'Annual software license renewal',3400.00,'pending','IT approval required');
"""

STATIC_FILES = {
    "Q4_strategy.pdf": "CONFIDENTIAL: Q4 Strategic Plan\nRevenue target: $4.2M\nKey initiative: cloud migration",
    "expense_report.xlsx": "Q4 2024 Expense Summary\nTotal submitted: $74,380.00",
    "employee_roster.csv": "id,name,email,department\n1,Admin,admin@corp.internal,Executive\n2,Alice Smith,alice@corp.internal,Engineering\n3,Bob Jones,bob@corp.internal,Sales",
}

TRAVERSAL_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsvcaccount:x:1001:1001::/home/svcaccount:/bin/bash",
    "/app/config.py": "SECRET_KEY = 'CorpNetProd2024!'\nDB_CONN = 'postgresql://admin:C0rp@dm1n2024@10.0.0.5/corpdb'\nAWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\nAWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    "/var/log/app.log": "2024-01-15 09:23 INFO  User admin logged in from 10.0.0.1\n2024-01-15 11:02 INFO  Expense #2 approved\n2024-01-15 14:55 WARN  Failed login attempt for user 'unknown'",
}


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.executescript(DB_SEED_SQL)
    conn.close()


def create_app(db_path: str) -> Flask:
    app = Flask(__name__)
    app.secret_key = "s3cr3t_k3y_2024"
    app.config["DB_PATH"] = db_path

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(e=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def index():
        return jsonify({
            "app": "CorpNet Internal Portal",
            "version": "3.2.1",
            "endpoints": [
                "GET  /api/health",
                "GET  /api/users",
                "GET  /api/users/<id>",
                "POST /api/login",
                "POST /api/logout",
                "GET  /api/profile",
                "GET  /api/expenses",
                "GET  /api/expenses/<id>",
                "GET  /api/search?q=<query>",
                "GET  /api/files",
                "GET  /api/files?name=<filename>",
                "GET  /api/announcements",
                "GET  /api/products",
            ],
        })

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok", "version": "3.2.1", "db": "connected"})

    @app.route("/api/users")
    def list_users():
        db = get_db()
        rows = db.execute("SELECT id, username, role, department FROM users").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/users/<int:user_id>")
    def get_user(user_id):
        db = get_db()
        row = db.execute(
            "SELECT id, username, role, email, ssn, salary, department FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify(dict(row))

    _LOGIN_WAF = re.compile(r"'\s*(or|and)\s+'", re.IGNORECASE)

    @app.route("/api/login", methods=["POST"])
    def login():
        attempts = session.get("login_attempts", 0)
        if attempts >= 5:
            return jsonify({"error": "Account locked. Too many failed attempts."}), 429

        body = request.get_json(silent=True) or {}
        username = str(body.get("username", ""))
        password = str(body.get("password", ""))

        if _LOGIN_WAF.search(username) or _LOGIN_WAF.search(password):
            return jsonify({"error": "Request blocked by security filter"}), 403

        if not username:
            return jsonify({"error": "username is required"}), 400

        db = get_db()
        try:
            query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
            row = db.execute(query).fetchone()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["login_attempts"] = 0
            return jsonify({
                "status": "success",
                "username": row["username"],
                "role": row["role"],
                "message": f"Welcome back, {row['username']}!",
            })

        session["login_attempts"] = attempts + 1
        remaining = max(0, 5 - session["login_attempts"])
        return jsonify({"error": f"Invalid credentials. {remaining} attempt(s) remaining."}), 401

    @app.route("/api/logout", methods=["POST"])
    def logout():
        session.clear()
        return jsonify({"status": "logged out"})

    @app.route("/api/profile")
    def profile():
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        db = get_db()
        row = db.execute(
            "SELECT id, username, role, email, department FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
        return jsonify(dict(row))

    @app.route("/api/expenses")
    def list_expenses():
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        db = get_db()
        rows = db.execute(
            "SELECT id, title, amount, status FROM expenses WHERE user_id = ?",
            (session["user_id"],),
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/expenses/<int:expense_id>")
    def get_expense(expense_id):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        db = get_db()
        row = db.execute("SELECT * FROM expenses WHERE id = ?", (expense_id,)).fetchone()
        if not row:
            return jsonify({"error": "Expense not found"}), 404
        return jsonify(dict(row))

    _SEARCH_WAF = re.compile(r"union\s+select", re.IGNORECASE)

    @app.route("/api/search")
    def search():
        q = request.args.get("q", "")
        if not q:
            return jsonify({"results": [], "message": "Use ?q= to search expenses by title"})
        if _SEARCH_WAF.search(q):
            return jsonify({"error": "Request blocked by security filter"}), 403
        db = get_db()
        try:
            query = f"SELECT id, title, amount, status FROM expenses WHERE title LIKE '%{q}%'"
            rows = db.execute(query).fetchall()
            return jsonify({"results": [dict(r) for r in rows], "count": len(rows)})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/files")
    def get_file():
        if "user_id" not in session:
            return jsonify({"error": "Authentication required. Please login first."}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required for file operations."}), 403

        name = request.args.get("name", "")
        if not name:
            return jsonify({
                "files": list(STATIC_FILES.keys()),
                "usage": "GET /api/files?name=<filename>",
            })

        if "../" in name or "..\\" in name:
            return jsonify({"error": "Invalid path: directory traversal not allowed"}), 403

        decoded = urllib.parse.unquote(name)
        if any(ind in decoded for ind in ["../", "..\\", "/etc/", "/app/", "/var/", "/root/"]):
            for target, content in TRAVERSAL_FILES.items():
                if target in decoded:
                    return content, 200, {"Content-Type": "text/plain"}
            return f"[Contents of {decoded}]", 200, {"Content-Type": "text/plain"}

        if name in STATIC_FILES:
            return STATIC_FILES[name], 200, {"Content-Type": "text/plain"}

        return jsonify({"error": f"File '{name}' not found"}), 404

    @app.route("/api/announcements")
    def announcements():
        return jsonify([
            {"id": 1, "title": "Q1 2025 All-Hands Meeting", "date": "2025-01-06"},
            {"id": 2, "title": "System Maintenance Window", "date": "2025-01-12"},
            {"id": 3, "title": "Updated PTO Policy", "date": "2025-01-08"},
        ])

    @app.route("/api/products")
    def products():
        return jsonify([
            {"id": 1, "name": "Laptop Stand", "sku": "LS-001", "price": 49.99},
            {"id": 2, "name": "USB-C Hub", "sku": "UC-002", "price": 79.99},
            {"id": 3, "name": "Wireless Mouse", "sku": "WM-003", "price": 35.00},
        ])

    @app.route("/api/admin/dashboard")
    def admin_dashboard():
        if session.get("role") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        db = get_db()
        total = db.execute("SELECT COALESCE(SUM(amount), 0) FROM expenses").fetchone()[0]
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        return jsonify({
            "total_users": count,
            "total_expenses_ytd": total,
            "server": "corpnet-prod-01",
            "uptime_days": 42,
        })

    return app
