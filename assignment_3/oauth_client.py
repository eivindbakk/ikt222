# oauth_client.py
import os
import secrets
from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

from models import db, User, OAuthAccount
from security import hash_password

oauth = OAuth()

def init_oauth(app):
    """Initialize Authlib with GitHub provider."""
    oauth.init_app(app)
    client_id = (os.getenv("GITHUB_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("GITHUB_CLIENT_SECRET") or "").strip()
    oauth.register(
        name="github",
        client_id=client_id,
        client_secret=client_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )

bp_oauth_client = Blueprint("oauth", __name__)

@bp_oauth_client.route("/login/github")
def login_github():
    # Explicitly mark this as a SIGN-IN flow and ensure we don't reuse a stale local session
    session["oauth_intent"] = "signin"
    session.pop("user_id", None)     # avoid linking to a non-existent/stale user
    session.pop("username", None)

    redirect_uri = (os.getenv("GITHUB_REDIRECT_URI") or "").strip()
    if not redirect_uri:
        redirect_uri = url_for("oauth.auth_github", _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@bp_oauth_client.route("/callback/github")
def auth_github():
    intent = session.pop("oauth_intent", "signin")

    token = oauth.github.authorize_access_token()  # validates state, exchanges code
    profile = oauth.github.get("user").json()

    gh_id = str(profile.get("id"))
    gh_login = (profile.get("login") or "").lower()

    # 1) If this GitHub account was linked before, fetch its local user
    link = OAuthAccount.query.filter_by(provider="github", provider_user_id=gh_id).first()
    user = None
    if link:
        user = User.query.get(link.user_id)
        # Handle dangling link (e.g., DB was reset)
        if user is None:
            db.session.delete(link)
            db.session.commit()
            link = None

    # 2) If we still don't have a user, create a brand new local user
    if user is None:
        base = gh_login or f"github_{gh_id}"
        username = base
        i = 1
        while User.query.filter_by(username=username).first():
            i += 1
            username = f"{base}{i}"

        user = User(
            username=username,
            password_hash=hash_password(secrets.token_urlsafe(16)),  # random local password
        )
        db.session.add(user)
        db.session.flush()  # ensures user.id is available

        link = OAuthAccount(
            provider="github",
            provider_user_id=gh_id,
            user_id=user.id,
            access_token=token.get("access_token"),
        )
        db.session.add(link)
    else:
        # Update token on existing link (optional, but nice to have)
        link.access_token = token.get("access_token")
        db.session.add(link)

    db.session.commit()

    # Fresh login session for that user
    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    return redirect(url_for("dashboard"))
