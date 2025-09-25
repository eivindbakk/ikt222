import os
import sqlite3
from datetime import datetime, timedelta
from flask import (
    Flask, g, render_template, request, redirect, url_for,
    make_response, jsonify
)
from markupsafe import Markup
import bleach

DB_PATH = os.environ.get("DB_PATH", "xss_demo.sqlite3")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret"),
    # Demo: we will also set a non-HttpOnly cookie to show theft in /vuln
)

# --- DB helpers --------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open("schema.sql", "r", encoding="utf-8") as f:
            db.executescript(f.read())
        db.commit()

# Initialize DB on first run
if not os.path.exists(DB_PATH):
    init_db()

# --- Simple in-memory theft log for demo ------------------------------------
THEFT_LOG = []  # list of dicts: {when, ip, data}

# --- Security headers (for /safe views we enable CSP via a toggle) ----------
ENFORCE_CSP = True

@app.after_request
def set_security_headers(resp):
    # Add basic security headers (kept simple for teaching)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"

    # For safe routes, add a tight CSP
    # We detect "safe" by URL path prefix for simplicity.
    if ENFORCE_CSP and request.path.startswith("/safe"):
        # Blocks inline script by default; allows only same-origin resources.
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    return resp

# --- Routes ------------------------------------------------------------------
@app.route("/")
def index():
    # Drop a deliberately readable cookie for demo (NOT HttpOnly!)
    resp = make_response(redirect(url_for("vuln_posts")))
    resp.set_cookie(
        "promo", "WIN-12345",
        max_age=3600,
        httponly=False,  # <-- Intentionally readable by JS for the demo
        secure=False,    # In production use True with HTTPS
        samesite="Lax",
    )
    return resp

@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "POST":
        author = request.form.get("author", "").strip()
        content = request.form.get("content", "").strip()
        db = get_db()
        db.execute(
            "INSERT INTO posts(author, content, created_at) VALUES (?, ?, ?)",
            (author or "Anonymous", content, datetime.utcnow().isoformat())
        )
        db.commit()
        # Send back to vulnerable view to demonstrate XSS first
        return redirect(url_for("vuln_posts"))
    return render_template("add.html")

@app.route("/vuln")
def vuln_posts():
    """
    Vulnerable list view:
    - Renders user content with Jinja's |safe (or Markup) — NO output encoding.
    - Allows stored XSS payloads to execute in visitors' browsers.
    """
    db = get_db()
    rows = db.execute("SELECT id, author, content, created_at FROM posts ORDER BY id DESC").fetchall()

    # Convert to dicts
    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "author": r["author"],
            # Intentionally unsafe: mark as safe HTML (dangerous!)
            "content_html": Markup(r["content"]),
            "created_at": r["created_at"],
        })
    return render_template("posts_vuln.html", posts=posts)

@app.route("/safe")
def safe_posts():
    """
    Mitigated list view:
    - Sanitizes stored HTML with bleach (allowing only minimal safe tags)
    - Relies on Jinja autoescaping (no |safe)
    - Adds CSP via @after_request
    """
    allowed_tags = ["b", "i", "em", "strong", "u", "br", "p", "ul", "ol", "li", "code", "pre"]
    allowed_attrs = {}

    db = get_db()
    rows = db.execute("SELECT id, author, content, created_at FROM posts ORDER BY id DESC").fetchall()
    posts = []
    for r in rows:
        cleaned = bleach.clean(r["content"], tags=allowed_tags, attributes=allowed_attrs, strip=True)
        posts.append({
            "id": r["id"],
            "author": r["author"],
            # Do NOT mark as safe; we rely on Jinja's default escaping + sanitized HTML
            "content": cleaned,
            "created_at": r["created_at"],
        })
    return render_template("posts_safe.html", posts=posts)

@app.route("/steal")
def steal():
    """
    Exfiltration endpoint used by the attack payload.
    Attacker-controlled script calls: /steal?c=<encoded document.cookie>
    We log what came in to THEFT_LOG to show impact.
    """
    data = request.args.get("c", "")
    THEFT_LOG.append({
        "when": datetime.utcnow().isoformat(),
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "data": data[:1000]
    })
    # Return tiny 204-like for stealth
    return ("", 204)

@app.route("/stolen")
def stolen():
    """Page for the teacher/student to see what has been exfiltrated."""
    return jsonify(THEFT_LOG)

# Utility: wipe data (for demo resets)
@app.route("/_reset", methods=["POST"])
def reset():
    db = get_db()
    db.execute("DELETE FROM posts")
    db.commit()
    THEFT_LOG.clear()
    resp = make_response("OK")
    # Expire the demo cookie
    resp.set_cookie("promo", "", expires=datetime.utcnow() - timedelta(days=1))
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
