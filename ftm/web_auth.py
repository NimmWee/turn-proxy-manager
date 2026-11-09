"""Bounded admin sessions; root-owned credential config, no metadata DB access."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

from .installer import _unique_object
from .store import ValidationError

SESSION_TTL = 4 * 60 * 60


class InvalidCredentials(ValueError):
    pass


class RateLimited(ValueError):
    def __init__(self, retry_after):
        self.retry_after = retry_after


def _password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**15, r=8, p=3,
                          maxmem=64 * 1024**2, dklen=32).hex()


def make_config(username, password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValidationError("Admin password must contain 12 to 1024 characters")
    salt = secrets.token_hex(16)
    return validate_config({"version": 1, "panel_slug": secrets.token_hex(16), "username": username,
                            "password_salt": salt, "password_hash": _password_hash(password, salt), "secure_cookie": False})


def validate_config(value):
    fields = {"version", "panel_slug", "username", "password_salt", "password_hash", "secure_cookie"}
    if not isinstance(value, dict) or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValidationError("Unsupported web credential config")
    for field, size in (("panel_slug", 32), ("password_salt", 32), ("password_hash", 64)):
        if not isinstance(value[field], str) or not re.fullmatch("[a-f0-9]{" + str(size) + "}", value[field]):
            raise ValidationError("Invalid web credential encoding")
    if (not isinstance(value["username"], str) or not 1 <= len(value["username"]) <= 128
            or any(ord(char) < 32 for char in value["username"]) or type(value["secure_cookie"]) is not bool):
        raise ValidationError("Invalid web credential fields")
    return dict(value)


def load_config(path):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValidationError("Web credential symlink rejected")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise ValidationError("Invalid web credential file")
        if os.name == "posix" and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o027):
            raise ValidationError("Web credentials must be protected and not group-writable")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValidationError("Web credential file exceeds size limit")
    return validate_config(json.loads(raw, object_pairs_hook=_unique_object))


class Auth:
    def __init__(self, config, *, clock=time.monotonic):
        self.config = validate_config(config)
        self.clock = clock
        self.lock = threading.Lock()
        self.sessions = {}
        self.failures = {}

    def _purge(self, now):
        self.sessions = {key: value for key, value in self.sessions.items() if value["expires"] > now}
        self.failures = {key: [stamp for stamp in stamps if now - stamp < 600]
                         for key, stamps in self.failures.items() if stamps and now - stamps[-1] < 600}

    def login(self, username, password, peer):
        if not isinstance(username, str) or not isinstance(password, str) or not 1 <= len(password) <= 1024 or len(username) > 128:
            raise InvalidCredentials()
        with self.lock:
            now = self.clock()
            self._purge(now)
            failures = self.failures.get(peer, [])
            if len(failures) >= 5:
                raise RateLimited(max(1, int(600 - now + failures[0])))
            candidate = _password_hash(password, self.config["password_salt"])
            correct = secrets.compare_digest(candidate, self.config["password_hash"])
            correct &= secrets.compare_digest(username.encode(), self.config["username"].encode())
            if not correct:
                if len(self.failures) >= 1024 and peer not in self.failures:
                    raise RateLimited(600)
                self.failures.setdefault(peer, []).append(now)
                raise InvalidCredentials()
            self.failures.pop(peer, None)
            if len(self.sessions) >= 256:
                oldest = min(self.sessions, key=lambda key: self.sessions[key]["expires"])
                self.sessions.pop(oldest)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {
                "username": username, "csrf": csrf, "expires": now + SESSION_TTL}
            return token, csrf

    def session(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with self.lock:
            self._purge(self.clock())
            value = self.sessions.get(hashlib.sha256(token.encode()).hexdigest())
            return dict(value) if value else None

    def authorize_mutation(self, token, csrf):
        session = self.session(token)
        return bool(session and isinstance(csrf, str) and secrets.compare_digest(session["csrf"], csrf))

    def logout(self, token):
        if isinstance(token, str):
            with self.lock:
                self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
