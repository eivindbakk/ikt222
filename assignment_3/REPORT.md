# Report

## Architecture (overview)
- **Flask** app with Blueprints:
  - `auth` (in `app.py`): register/login, 2FA setup & verify, session-based auth
  - `oauth_client.py`: GitHub OAuth2 Authorization Code Flow
  - `mock_oauth_provider.py`: miniature OAuth2 server for testing
- **SQLite + SQLAlchemy** models: `User`, `OAuthAccount`
- **Security helpers**: bcrypt password hashing, home‑rolled CSRF tokens, secure cookie flags
- **Rate limiting**: Flask‑Limiter (IP‑based), login lockout after 3 failures

## Database Integration (20)
- **Schema**:
  - `User(id, username UNIQUE, password_hash, totp_secret, failed_attempts, lock_until, oauth_provider, oauth_sub, created_at)`
  - `OAuthAccount(id, user_id, provider, provider_user_id, email, name, access_token, created_at)`
- **Security challenges**: SQL injection, weak storage of secrets, token sprawl.
- **Mitigations**: ORM parameterization, bcrypt hashes (no plaintext), consider at-rest encryption for tokens, least privilege.

## Basic User Authentication (20)
- **Flow**: register → bcrypt-hash → login → set session → dashboard.
- **Challenges**: credential stuffing, password reuse, session hijacking.
- **Mitigations**: bcrypt(cost=12), 2FA, HttpOnly+Secure+SameSite cookies, CSRF tokens on state‑changing POSTs, username normalization.

## Protection Against Brute Force (20)
- **Mechanisms**:
  - **Rate limiting** `/login`: `10/min` per IP plus `5/min` per username
  - **Account lockout** for **5 minutes** after **3 consecutive failures**
- **Challenges**: IP rotation, DoS via lockouts.
- **Mitigations**: combine IP rate‑limit + per‑account counters; log alerts; optionally captcha after N attempts.

## Two‑Factor Authentication (20)
- **TOTP** via `pyotp`; provisioning URI + **QR code** shown at registration.
- **Challenges**: time skew, shared secret leakage, backup codes.
- **Mitigations**: allow a small verification window; transmit secret only over HTTPS; rotate/regenerate on suspicion; optionally add backup codes.

## OAuth2 Concepts (20)
- **Client**: GitHub OAuth using Authorization Code Flow (Authlib).
- **Data**: fetch basic profile (+ primary email) and **persist** to `OAuthAccount`, link/create local user with a hashed random password and TOTP secret.
- **Challenges**: token leakage, CSRF on redirect, account linking confusion.
- **Mitigations**: use provider `state` parameter (Authlib handles), store tokens securely, verify redirect URI, require TOTP after OAuth login, explicit linking UI in production.

## Recommendations
- Add **Flask‑WTF** for robust CSRF, **HTTPS** with HSTS, **Content Security Policy**.
- Encrypt **OAuth tokens** at rest (e.g., Fernet + KMS).
- Add **refresh token** management & rotation.
- Implement **email/password reset** with signed tokens.
- Add **audit logs** and alerting on suspicious auth activity.
