from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    twofa_secret = db.Column(db.String(64), nullable=True)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    lock_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class OAuthAccount(db.Model):
    __tablename__ = "oauth_accounts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    provider = db.Column(db.String(30), nullable=False)
    provider_user_id = db.Column(db.String(120), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(255), nullable=True)
    access_token = db.Column(db.String(2048), nullable=True)  # store securely in real apps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
