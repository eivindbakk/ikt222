import os
import secrets

import pyotp
from flask import Blueprint, redirect, url_for, session, request, abort
from authlib.integrations.flask_client import OAuth
from models import db, OAuthAccount, User
from security import hash_password

bp_oauth_client = Blueprint("oauth_client", __name__)

def init_oauth(app):
    oauth = OAuth(app)
    oauth.register(
        name='github',
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'read:user user:email'},
    )
    app.oauth = oauth

@bp_oauth_client.route("/login/github")
def login_github():
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI") or url_for("oauth_client.github_callback", _external=True)
    return bp_oauth_client._app.oauth.github.authorize_redirect(redirect_uri)

@bp_oauth_client.route("/callback/github")
def github_callback():
    oauth = bp_oauth_client._app.oauth
    token = oauth.github.authorize_access_token()
    if not token:
        abort(400, "No token from provider")
    resp = oauth.github.get('user')
    profile = resp.json()
    # Fetch (possibly) primary email if missing
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
        )
        db.session.add(acct)

    # Always refresh token + profile metadata we care about
    acct.access_token = token.get("access_token")
    if email:
        acct.email = email
    acct.name = profile.get("name") or profile.get("login")
    db.session.commit()

    # Auto-link or auto-provision a local user if desired
    if "user_id" not in session:
        # Attempt to reuse an already linked account first
        user = acct.user_id and User.query.get(acct.user_id)

        if not user and email:
            user = User.query.filter_by(username=email).first()

        requires_totp_setup = False
        if not user:
            # Create a shadow user with a random (hashed) password and a TOTP secret
            user = User(
                username=email or f'gh_{profile["id"]}',
                password_hash=hash_password(secrets.token_urlsafe(32)),
                oauth_provider="github",
                oauth_sub=str(profile["id"]),
                totp_secret=pyotp.random_base32(),
            )
            db.session.add(user)
            db.session.commit()
            requires_totp_setup = True
        else:
            # Ensure provider identity is recorded
            updated = False
            if not user.oauth_provider or not user.oauth_sub:
                user.oauth_provider = "github"
                user.oauth_sub = str(profile["id"])
                updated = True
            if not user.totp_secret:
                user.totp_secret = pyotp.random_base32()
                updated = True
                requires_totp_setup = True
            if updated:
                db.session.commit()

        acct.user_id = user.id
        db.session.commit()

        if requires_totp_setup:
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("setup_2fa"))

        session.pop("user_id", None)
        session.pop("username", None)
        session["pending_2fa_user_id"] = user.id
        return redirect(url_for("verify_2fa"))

    return redirect(url_for("dashboard"))
