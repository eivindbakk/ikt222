import secrets, time
from urllib.parse import urlencode
from flask import Blueprint, request, redirect, jsonify, abort

bp_mock_oauth = Blueprint("mock_oauth", __name__)

AUTH_CODES = {}   # code -> {client_id, redirect_uri, created_at}
TOKENS = {}       # token -> {client_id, created_at}

@bp_mock_oauth.route("/auth", methods=["GET"])
def auth():
    # A real server would render an approval page. We'll just instruct to POST to /approve_auth.
    return "POST client_id and redirect_uri to /approve_auth to auto-approve this demo."

@bp_mock_oauth.route("/approve_auth", methods=["POST"])
def approve_auth():
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    if not client_id or not redirect_uri:
        abort(400, "missing client_id or redirect_uri")
    code = secrets.token_urlsafe(16)
    AUTH_CODES[code] = {"client_id": client_id, "redirect_uri": redirect_uri, "created_at": time.time()}
    # Redirect back with code
    qp = urlencode({"code": code, "state": request.form.get("state","")})
    return redirect(f"{redirect_uri}?{qp}", code=302)

@bp_mock_oauth.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")
    if not all([code, client_id, client_secret, redirect_uri]):
        abort(400, "missing fields")
    # Basic validations
    data = AUTH_CODES.get(code)
    if not data or data["client_id"] != client_id or data["redirect_uri"] != redirect_uri:
        abort(400, "invalid code")
    if time.time() - data["created_at"] > 300:
        abort(400, "code expired")
    # Issue token
    access_token = secrets.token_urlsafe(24)
    TOKENS[access_token] = {"client_id": client_id, "created_at": time.time()}
    # One-time use code
    AUTH_CODES.pop(code, None)
    return jsonify({"access_token": access_token, "token_type":"Bearer", "expires_in":3600})

@bp_mock_oauth.route("/protected_resource", methods=["GET"])
def protected_resource():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "):
        abort(401)
    token = auth.split(" ", 1)[1]
    if token not in TOKENS:
        abort(401)
    return jsonify({"message":"Success! You accessed the protected resource."})
