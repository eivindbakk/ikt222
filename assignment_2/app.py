import os
import sqlite3
import re
from datetime import datetime, timedelta
from functools import wraps
from collections import Counter

from flask import (
    Flask, g, render_template, request, redirect, url_for, session,
    flash, make_response, abort, jsonify
)
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
import bleach

# Config
APP_SECRET = os.environ.get("SECRET_KEY", "dev-secret")
DB_PATH = os.environ.get("DB_PATH", "social.sqlite3")

app = Flask(__name__, static_url_path="/static", static_folder="static")
app.config.update(SECRET_KEY=APP_SECRET)

# Constants
ALLOWED_TAGS = ["b","i","em","strong","u","br","p","ul","ol","li","code","pre"]
ALLOWED_ATTRS = {}
TAG_RE = re.compile(r'(^|[\s(])#([A-Za-z0-9_]{2,30})\b')
MENTION_RE = re.compile(r'(^|[\s(])@([A-Za-z0-9_]{2,30})\b')
HASHTAG_RE = re.compile(r'#([A-Za-z0-9_]{2,30})')

# --- DB helpers --------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
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

if not os.path.exists(DB_PATH):
    init_db()

# --- Utilities ---------------------------------------------------------------
def ensure_profile(uid):
    db = get_db()
    cur = db.execute("SELECT 1 FROM profiles WHERE user_id=?", (uid,)).fetchone()
    if not cur:
        db.execute("INSERT INTO profiles(user_id, bio, avatar_seed) VALUES(?, '', '')", (uid,))
        db.commit()

def sanitize_and_link(text):
    cleaned = bleach.clean(text or "", tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    def link_tag(m):
        prefix, tag = m.group(1), m.group(2)
        return f"{prefix}<a href='{url_for('tag', tag=tag)}'>#{tag}</a>"
    def link_mention(m):
        prefix, name = m.group(1), m.group(2)
        return f"{prefix}<a href='{url_for('profile', username=name)}'>@{name}</a>"
    cleaned = TAG_RE.sub(link_tag, cleaned)
    cleaned = MENTION_RE.sub(link_mention, cleaned)
    return cleaned

def get_trending(limit=8):
    db = get_db()
    rows = db.execute("SELECT content FROM posts ORDER BY id DESC LIMIT 500").fetchall()
    tags = []
    for r in rows:
        if r["content"]:
            tags.extend(HASHTAG_RE.findall(r["content"]))
    counts = Counter(t.lower() for t in tags)
    return [{"tag": tag, "cnt": cnt} for tag, cnt in counts.most_common(limit)]

# --- Auth helpers ------------------------------------------------------------
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    row = db.execute("SELECT id, username, created_at FROM users WHERE id = ?", (uid,)).fetchone()
    return row

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Please log in to continue.", "warn")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

# inject current user into all templates
@app.context_processor
def inject_current_user():
    return {"me": current_user()}

# --- Security headers / CSP -----------------------------------------------
@app.after_request
def set_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # Demo cookie (readable) for XSS theft demonstration only
    if request.endpoint in ("feed_vuln", "index", "feed"):
        resp.set_cookie(
            "promo", "WIN-12345",
            max_age=3600, httponly=False, secure=False, samesite="Lax"
        )
    # Strict CSP for safe routes
    if request.path.startswith("/feed-safe") or request.path.startswith("/u/") or request.path.startswith("/compose") or request.path.startswith("/following") or request.path.startswith("/posts"):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    return resp

# --- Routes ------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("feed_vuln"))

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required.", "error")
            return render_template("auth_register.html")
        db = get_db()
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Username taken.", "error")
            return render_template("auth_register.html")
        pwd_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, pwd_hash, datetime.utcnow().isoformat())
        )
        db.commit()
        uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        ensure_profile(uid)
        flash("Registered. Please log in.", "ok")
        return redirect(url_for("login"))
    return render_template("auth_register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.", "error")
            return render_template("auth_login.html")
        session["uid"] = user["id"]
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=6)
        ensure_profile(user["id"])
        nxt = request.args.get("next")
        return redirect(nxt or url_for("feed_vuln"))
    return render_template("auth_login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("login"))

# Compose
@app.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content:
            flash("Say something first.", "error")
            return render_template("compose.html", me=current_user())
        db = get_db()
        db.execute(
            "INSERT INTO posts(user_id, content, created_at) VALUES (?, ?, ?)",
            (session["uid"], content, datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Posted!", "ok")
        return redirect(url_for("feed_vuln"))
    return render_template("compose.html", me=current_user())

# Vulnerable feed (identical layout to safe, but unsafe rendering)
@app.route("/feed")
def feed_vuln():
    db = get_db()
    uid = session.get("uid", -1)

    rows = db.execute("""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) as i_like,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 100
    """, (uid,)).fetchall()

    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "content_html": Markup(r["content"]),  # intentionally unsafe
            "like_count": r["like_count"],
            "i_like": bool(r["i_like"]),
            "comment_count": r["comment_count"]
        })

    trending = get_trending()
    who = db.execute("""
        SELECT u.username FROM users u
        WHERE u.id != ? AND u.id NOT IN (SELECT followee_id FROM follows WHERE follower_id=?)
        ORDER BY u.id DESC LIMIT 5
    """, (uid, uid)).fetchall()

    return render_template(
        "timeline_safe.html",
        posts=posts,
        trending=[dict(t) for t in trending],
        who=[dict(w) for w in who],
        vulnerable=True
    )

# Safe feed
@app.route("/feed-safe")
def feed_safe():
    db = get_db()
    uid = session.get("uid", -1)
    rows = db.execute("""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) as i_like,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id=u.id
        ORDER BY p.id DESC LIMIT 100
    """, (uid,)).fetchall()
    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "content_html": Markup(sanitize_and_link(r["content"])),
            "like_count": r["like_count"],
            "i_like": bool(r["i_like"]),
            "comment_count": r["comment_count"]
        })

    trending = get_trending()
    who = db.execute("""
        SELECT u.username FROM users u
        WHERE u.id != ? AND u.id NOT IN (SELECT followee_id FROM follows WHERE follower_id=?)
        ORDER BY u.id DESC LIMIT 5
    """, (uid, uid)).fetchall()

    return render_template("timeline_safe.html", posts=posts, trending=[dict(t) for t in trending], who=[dict(w) for w in who])

# NEW: All posts page (full list, optional filter & pagination)
@app.route("/posts")
def posts_all():
    """
    List every post as its own card (no grouping).
    Optional: ?user=<username> to filter.
    Pagination: ?page=1 (1-based), page size 20.
    """
    db = get_db()
    uid = session.get("uid", -1)
    username = request.args.get("user", "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    page_size = 20
    offset = (page - 1) * page_size

    params = []
    where = ""
    if username:
        where = "WHERE u.username = ?"
        params.append(username)

    # Count total for pager
    total = db.execute(f"""
        SELECT COUNT(*)
        FROM posts p
        JOIN users u ON p.user_id = u.id
        {where}
    """, tuple(params)).fetchone()[0]

    # Fetch page
    rows = db.execute(f"""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) as i_like,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id=u.id
        {where}
        ORDER BY p.id DESC
        LIMIT ? OFFSET ?
    """, (uid, *params, page_size, offset)).fetchall()

    posts = [{
        "id": r["id"],
        "username": r["username"],
        "created_at": r["created_at"],
        "content_html": Markup(sanitize_and_link(r["content"])),
        "like_count": r["like_count"],
        "i_like": bool(r["i_like"]),
        "comment_count": r["comment_count"]
    } for r in rows]

    has_prev = page > 1
    has_next = offset + len(posts) < total

    return render_template(
        "posts.html",
        posts=posts,
        username=username or None,
        page=page,
        has_prev=has_prev,
        has_next=has_next,
        total=total,
        page_size=page_size,
        trending=[dict(t) for t in get_trending()]
    )

# Following feed
@app.route("/following")
@login_required
def feed_following():
    db = get_db()
    uid = session.get("uid")
    rows = db.execute("""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) as i_like,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id=u.id
        WHERE p.user_id IN (SELECT followee_id FROM follows WHERE follower_id=?)
        ORDER BY p.id DESC LIMIT 100
    """, (uid, uid)).fetchall()
    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "content_html": Markup(sanitize_and_link(r["content"])),
            "like_count": r["like_count"],
            "i_like": bool(r["i_like"]),
            "comment_count": r["comment_count"]
        })
    return render_template("timeline_safe.html", posts=posts, following=True, trending=[dict(t) for t in get_trending()])

# Tag page
@app.route("/tag/<tag>")
def tag(tag):
    db = get_db()
    rows = db.execute("""
        SELECT p.id, p.content, p.created_at, u.username,
               (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) as like_count,
               (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) as comment_count
        FROM posts p JOIN users u ON p.user_id=u.id
        WHERE lower(p.content) LIKE '%'||lower(?)||'%'
        ORDER BY p.id DESC LIMIT 100
    """, (f"#{tag}",)).fetchall()
    posts = []
    for r in rows:
        posts.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "content_html": Markup(sanitize_and_link(r["content"])),
            "like_count": r["like_count"],
            "comment_count": r["comment_count"]
        })
    return render_template("timeline_safe.html", posts=posts, tag=tag, trending=[dict(t) for t in get_trending()])

# Profile (view + edit bio)
@app.route("/u/<username>", methods=["GET", "POST"])
def profile(username):
    db = get_db()
    user = db.execute("SELECT id, username, created_at FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        abort(404)

    if request.method == "POST" and session.get("uid") == user["id"]:
        bio = request.form.get("bio", "").strip()
        safe_bio = bleach.clean(bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        db.execute("UPDATE profiles SET bio=? WHERE user_id=?", (safe_bio, user["id"]))
        db.commit()
        flash("Profile updated.", "ok")
        return redirect(url_for("profile", username=username))

    prof = db.execute("SELECT bio FROM profiles WHERE user_id=?", (user["id"],)).fetchone()
    stats = db.execute("""
        SELECT
          (SELECT COUNT(*) FROM posts WHERE user_id=?) AS posts,
          (SELECT COUNT(*) FROM follows WHERE followee_id=?) AS followers,
          (SELECT COUNT(*) FROM follows WHERE follower_id=?) AS following
    """, (user["id"], user["id"], user["id"])).fetchone()

    rows = db.execute("SELECT id, content, created_at FROM posts WHERE user_id = ? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()

    is_me = session.get("uid") == user["id"]
    i_follow = False
    if not is_me and session.get("uid"):
        i_follow = bool(db.execute("SELECT 1 FROM follows WHERE follower_id=? AND followee_id=?", (session["uid"], user["id"])).fetchone())

    return render_template("profile.html", user=user, prof=prof, stats=stats, posts=rows, is_me=is_me, i_follow=i_follow, trending=[dict(t) for t in get_trending()])

# Like / Unlike
@app.post("/like/<int:post_id>")
@login_required
def like(post_id):
    db = get_db()
    try:
        db.execute("INSERT INTO likes(user_id, post_id, created_at) VALUES(?,?,?)", (session["uid"], post_id, datetime.utcnow().isoformat()))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    return redirect(request.referrer or url_for("feed_safe"))

@app.post("/unlike/<int:post_id>")
@login_required
def unlike(post_id):
    db = get_db()
    db.execute("DELETE FROM likes WHERE user_id=? AND post_id=?", (session["uid"], post_id))
    db.commit()
    return redirect(request.referrer or url_for("feed_safe"))

# Comment
@app.post("/comment/<int:post_id>")
@login_required
def comment(post_id):
    text = request.form.get("comment", "").strip()
    if text:
        safe = bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
        db = get_db()
        db.execute("INSERT INTO comments(post_id, user_id, content, created_at) VALUES(?,?,?,?)", (post_id, session["uid"], safe, datetime.utcnow().isoformat()))
        db.commit()
    return redirect(request.referrer or url_for("feed_safe"))

# Follow / Unfollow
@app.post("/follow/<username>")
@login_required
def follow(username):
    db = get_db()
    u = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if u and u["id"] != session["uid"]:
        try:
            db.execute("INSERT INTO follows(follower_id, followee_id, created_at) VALUES(?,?,?)", (session["uid"], u["id"], datetime.utcnow().isoformat()))
            db.commit()
        except sqlite3.IntegrityError:
            pass
    return redirect(request.referrer or url_for("profile", username=username))

@app.post("/unfollow/<username>")
@login_required
def unfollow(username):
    db = get_db()
    u = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if u:
        db.execute("DELETE FROM follows WHERE follower_id=? AND followee_id=?", (session["uid"], u["id"]))
        db.commit()
    return redirect(request.referrer or url_for("profile", username=username))

# Theft endpoint for demo
THEFT_LOG = []
@app.route("/steal")
def steal():
    data = request.args.get("c", "")
    THEFT_LOG.append({"when": datetime.utcnow().isoformat(), "ip": request.headers.get("X-Forwarded-For", request.remote_addr), "data": data[:1000]})
    return ("", 204)

@app.route("/stolen")
def stolen():
    return jsonify(THEFT_LOG)

# Reset (careful)
@app.post("/_reset")
def reset():
    db = get_db()
    db.execute("DELETE FROM posts")
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM profiles")
    db.execute("DELETE FROM likes")
    db.execute("DELETE FROM comments")
    db.execute("DELETE FROM follows")
    db.commit()
    THEFT_LOG.clear()
    resp = make_response("OK")
    resp.set_cookie("promo", "", expires=datetime.utcnow() - timedelta(days=1))
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
