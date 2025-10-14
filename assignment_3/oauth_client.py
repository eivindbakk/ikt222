# oauth_client.py
import os
from flask import Blueprint, redirect, url_for, session, abort, current_app
from authlib.integrations.flask_client import OAuth
from models import db, OAuthAccount, User

bp_oauth_client = Blueprint("oauth_client", __name__)

def init_oauth(app):
    client_id = os.getenv("GITHUB_CLIENT_ID")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError("Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env")

    oauth = OAuth(app)
    oauth.register(
        name='github',
        client_id=client_id,
        client_secret=client_secret,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'read:user user:email'},
    )
    app.oauth = oauth

@bp_oauth_client.route("/login/github")
def login_github():
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI") or url_for("oauth_client.github_callback", _external=True)
    return current_app.oauth.github.authorize_redirect(redirect_uri)

@bp_oauth_client.route("/callback/github")
def github_callback():
    oauth = current_app.oauth
    token = oauth.github.authorize_access_token()
    if not token:
        abort(400, "No token from provider")
    profile = oauth.github.get('user').json()
    email = profile.get("email")
    if not email:
        emails = oauth.github.get('user/emails').json()
        primary = next((e for e in emails if e.get("primary")), None)
        email = primary.get("email") if primary else None

    acct = OAuthAccount.query.filter_by(provider="github", provider_user_id=str(profile["id"])).first()
    if not acct:
        acct = OAuthAccount(
            provider="github",
            provider_user_id=str(profile["id"]),
            email=email,
            name=profile.get("name") or profile.get("login"),
            access_token=token.get("access_token"),
        )
        db.session.add(acct)
        db.session.commit()

    if "user_id" not in session:
        user = User.query.filter_by(username=email).first() if email else None
        if not user:
            user = User(username=email or f'gh_{profile["id"]}', password_hash="oauth_only")
            db.session.add(user)
            db.session.commit()
        acct.user_id = user.id
        db.session.commit()
        session["user_id"] = user.id
        session["username"] = user.username

    def init_oauth(app):
        cid = os.getenv("GITHUB_CLIENT_ID", "")
        csec = os.getenv("GITHUB_CLIENT_SECRET", "")
        if not cid or cid.startswith("your_") or not csec:
            raise RuntimeError("Set real GITHUB_CLIENT_ID/SECRET in .env")
        oauth = OAuth(app)
        oauth.register(
            name='github',
            client_id=cid,
            client_secret=csec,
            access_token_url='https://github.com/login/oauth/access_token',
            authorize_url='https://github.com/login/oauth/authorize',
            api_base_url='https://api.github.com/',
            client_kwargs={'scope': 'read:user user:email'},
        )
        app.oauth = oauth

    return redirect(url_for("dashboard"))
