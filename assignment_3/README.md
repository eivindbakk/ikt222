# Secure Auth Demo (Flask)

Covers the assignment's 5 tasks: DB integration, basic auth, brute‑force protection, 2FA (TOTP), and OAuth2 (client). Also ships a tiny mock OAuth2 provider to run the provided test script.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install -r requirements.txt

# Optional: copy env example
cp .env.example .env  # and edit values (SECRET_KEY, GitHub OAuth vars)

# Initialize DB
flask --app app.py init-db

# Run
flask --app app.py run
```

Open http://localhost:5000/

## Features

- **SQLite + SQLAlchemy** user store.
- **Password hashing** with bcrypt.
- **Brute‑force protection**: rate limiting (Flask‑Limiter) and **lockout 5 min** after 3 failed attempts.
- **2FA** using `pyotp` with QR‑code provisioning.
- **OAuth2 client** (GitHub) via Authlib — set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`.
- **Mock OAuth2 provider** for the provided testing script: `/approve_auth`, `/token`, `/protected_resource`.

## Running the provided OAuth2 test

In another Python script (while the server is running):

```python
import requests
CLIENT_ID="demo_client"
CLIENT_SECRET="demo_secret"
REDIRECT_URI="http://localhost:5000/callback"

auth_data={'client_id':CLIENT_ID,'redirect_uri':REDIRECT_URI}
r = requests.post("http://localhost:5000/approve_auth", data=auth_data, allow_redirects=True)
auth_code = r.url.split("code=")[1].split("&")[0]

token_data={'code':auth_code,'redirect_uri':REDIRECT_URI,'client_id':CLIENT_ID,'client_secret':CLIENT_SECRET}
t = requests.post("http://localhost:5000/token", data=token_data).json()
access_token = t['access_token']

h={'Authorization': f"Bearer {access_token}"}
print(requests.get("http://localhost:5000/protected_resource", headers=h).text)
```

## Security notes (high‑level)

- Use **strong hashing** (bcrypt, cost=12) and **unique usernames**; never store plaintext passwords.
- **CSRF tokens** on forms; **HttpOnly** cookies.
- **Lockout** and **rate‑limiting** to reduce brute‑force risk.
- **2FA** significantly raises the bar against credential stuffing.
- Store OAuth tokens **securely** (consider encryption/rotation in production).
