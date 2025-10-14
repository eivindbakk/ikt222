import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, abort, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import pyotp, qrcode, io, base64

from models import db, User, OAuthAccount
from security import hash_password, verify_password, ensure_csrf_token, validate_csrf
from oauth_client import bp_oauth_client, init_oauth
from mock_oauth_provider import bp_mock_oauth

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI") or "sqlite:///auth.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Secure cookie flags
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

db.init_app(app)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200/hour"])

# OAuth client
init_oauth(app)
bp_oauth_client._app = app  # quick way to pass app to blueprint
app.register_blueprint(bp_oauth_client)

# Mock OAuth provider for the provided test script
app.register_blueprint(bp_mock_oauth)

# ------------- Helpers -------------
def current_user():
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None

def require_login():
    if not current_user():
        return redirect(url_for("login"))

# ------------- Routes -------------
@app.before_request
def set_csrf():
    ensure_csrf_token()

@app.route("/")
def index():
    return render_template("index.html", user=current_user())

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5/minute")
def register():
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        if not username or not password:
            return render_template("register.html", error="Username and password required", csrf_token=session["csrf_token"])
        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already exists", csrf_token=session["csrf_token"])
        pwd_hash = hash_password(password)
        # Generate 2FA secret at registration
        secret = pyotp.random_base32()
        user = User(username=username, password_hash=pwd_hash, totp_secret=secret)
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        session["username"] = user.username
        return redirect(url_for("setup_2fa"))
    return render_template("register.html", csrf_token=session["csrf_token"])

@app.route("/setup-2fa")
def setup_2fa():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # generate otpauth uri and QR
    totp = pyotp.TOTP(user.totp_secret)
    issuer = "FlaskSecureAuthDemo"
    uri = totp.provisioning_uri(name=user.username, issuer_name=issuer)
    # Make QR code and embed as base64
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    data_uri = f"data:image/png;base64,{b64}"
    return render_template("setup_2fa.html", data_uri=data_uri, secret=user.totp_secret)

def _login_username_limit_key():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        if username:
            return f"username:{username}"
    return get_remote_address()

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
@limiter.limit("5/minute", key_func=_login_username_limit_key, methods=["POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username","").strip().lower()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        # Basic existence check
        if not user:
            return render_template("login.html", error="Invalid credentials", csrf_token=session["csrf_token"])
        # Lockout check
        now = datetime.utcnow()
        if user.lock_until and user.lock_until > now:
            remaining = int((user.lock_until - now).total_seconds())
            return render_template("login.html", error=f"Account locked. Try again in {remaining} seconds.", csrf_token=session["csrf_token"])
        # Verify password
        if not verify_password(password, user.password_hash):
            user.failed_attempts += 1
            if user.failed_attempts >= 3:
                user.lock_until = now + timedelta(minutes=5)
                user.failed_attempts = 0  # reset counter after lock
            db.session.commit()
            return render_template("login.html", error="Invalid credentials", csrf_token=session["csrf_token"])
        # Success: reset counters
        user.failed_attempts = 0
        user.lock_until = None
        db.session.commit()
        session["pending_2fa_user_id"] = user.id
        return redirect(url_for("verify_2fa"))
    return render_template("login.html", csrf_token=session["csrf_token"])

@app.route("/verify-2fa", methods=["GET","POST"])
@limiter.limit("10/minute")
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    user = User.query.get(user_id)
    if not user or not user.totp_secret:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))
    if request.method == "POST":
        validate_csrf()
        code = request.form.get("code","").strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("dashboard"))
        else:
            return render_template("verify_2fa.html", error="Invalid code", csrf_token=session["csrf_token"])
    return render_template("verify_2fa.html", csrf_token=session["csrf_token"])

@app.route("/dashboard")
def dashboard():
    if not current_user():
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=current_user())

@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    return redirect(url_for("index"))

# API sample protected endpoint using session auth
@app.route("/api/me")
def api_me():
    user = current_user()
    if not user:
        return abort(401)
    return jsonify({"username": user.username, "created_at": user.created_at.isoformat()})

# CLI helper to init DB
@app.cli.command("init-db")
def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized.")
        
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
