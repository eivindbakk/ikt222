# oauth_client.py
import os, secrets
from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

from models import db, User, OAuthAccount
from security import hash_password

oauth = OAuth()

def init_oauth(app):
    """Kalles fra app.py for å initialisere Authlib-klienten."""
    oauth.init_app(app)
    oauth.register(
        name="github",
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )

bp_oauth_client = Blueprint("oauth", __name__)

@bp_oauth_client.route("/login/github")
def login_github():
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI") or url_for("oauth.auth_github", _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@bp_oauth_client.route("/callback/github")
def auth_github():
    token = oauth.github.authorize_access_token()  # validerer også state
    userinfo = oauth.github.get("user").json()
    # emails = oauth.github.get("user/emails").json()  # tilgjengelig ved behov

    gh_id = str(userinfo.get("id"))
    gh_login = (userinfo.get("login") or "").lower()

    # Finn evt. eksisterende link
    link = OAuthAccount.query.filter_by(provider="github", provider_user_id=gh_id).first()

    if link:
        user = User.query.get(link.user_id)
    else:
        # Link til innlogget lokal bruker, ellers opprett ny
        if "user_id" in session:
            user = User.query.get(session["user_id"])
        else:
            base = gh_login or f"github_{gh_id}"
            username = base
            i = 1
            while User.query.filter_by(username=username).first():
                i += 1
                username = f"{base}{i}"
            user = User(
                username=username,
                password_hash=hash_password(secrets.token_urlsafe(16)),  # random pass
            )
            db.session.add(user)
            db.session.flush()  # får user.id

        link = OAuthAccount(
            provider="github",
            provider_user_id=gh_id,
            user_id=user.id,
            access_token=token.get("access_token"),
        )
        db.session.add(link)

    db.session.commit()

    # Logg inn brukeren i appen
    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    return redirect(url_for("dashboard"))
