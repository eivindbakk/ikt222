import os, secrets, bcrypt
from flask import session, abort, request

BCRYPT_ROUNDS = 12

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False

def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(16)
    return session["csrf_token"]

def validate_csrf():
    form_token = request.form.get("csrf_token","")
    if not form_token or "csrf_token" not in session or form_token != session["csrf_token"]:
        abort(400, description="CSRF token invalid")
