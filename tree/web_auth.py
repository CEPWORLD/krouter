"""
web_auth.py — Flask login helpers for the admin UI.

Author : Kage
Project: krouter
Thought: even a home lab UI needs a password — kids and guests should not
         casually flip study mode from a phone on the LAN.
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import secrets

from flask import redirect, request, session, url_for

import settings_store


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 120000)
    return f'{salt}${digest.hex()}'


def verify_password(password: str, stored: str) -> bool:
    if not stored or '$' not in stored:
        return False
    salt, hx = stored.split('$', 1)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 120000)
    return hmac.compare_digest(digest.hex(), hx)


def ensure_admin_password(default_user: str, default_password: str):
    settings_store.ensure_tables()
    if not settings_store.get('admin_password_hash'):
        settings_store.set_value('admin_user', default_user)
        settings_store.set_value('admin_password_hash', hash_password(default_password))


def check_login(username: str, password: str) -> bool:
    user = settings_store.get('admin_user') or 'admin'
    pw_hash = settings_store.get('admin_password_hash') or ''
    if username != user:
        return False
    return verify_password(password, pw_hash)


def login_user(username: str):
    session['logged_in'] = True
    session['user'] = username


def logout_user():
    session.clear()


def is_logged_in() -> bool:
    return bool(session.get('logged_in'))


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped
