"""Flask application factory: wires Layer 1 (guard) and Layer 2 (secure data layer) together."""
import logging
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from cryptography.exceptions import InvalidTag
from flask import Flask, g, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import guard
from .capabilities import CapabilityAuthority, TokenError
from .config import Config
from .crypto import Crypto
from .db import BadParameters, CapabilityDenied, SecureDB, UnknownQuery

PUBLIC_CAPS = frozenset({"auth:register", "auth:login", "audit:write"})
MAX_LOGIN_FAILURES = 5


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_app(config: Config | None = None) -> Flask:
    config = config or Config.from_env()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # small bodies only
    if os.environ.get("TRUST_PROXY") == "1":       # running behind a TLS proxy / load balancer
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    crypto = Crypto(config.enc_key, config.mac_key)
    authority = CapabilityAuthority(config.mac_key, config.token_ttl)
    db = SecureDB(config.db_path)
    ip_limiter = guard.SlidingWindow(limit=120, window=60)
    login_failures = guard.SlidingWindow(limit=MAX_LOGIN_FAILURES, window=900)
    app.extensions.update({"secure_db": db, "crypto": crypto, "authority": authority})
    log = logging.getLogger("secure_app")

    # ------------------------------------------------------------ helpers
    def client_ip() -> str:
        return request.remote_addr or "unknown"

    def log_event(kind: str, detail: str) -> None:
        db.run("audit.write", (_now(), client_ip(), kind, detail[:300]), {"audit:write"})
        log.warning("security event %s: %s", kind, detail[:120])

    def checked(body, spec):
        """Layer 1 entry point."""
        try:
            return guard.screen_and_validate(body, spec)
        except guard.SQLiSuspected as hit:
            log_event("sqli_suspected", f"field={hit.field} rule={hit.pattern} sample={hit.sample!r}")
            raise ApiError(400, "request rejected")
        except guard.ValidationError as exc:
            raise ApiError(400, str(exc))

    def requires(capability: str):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                header = request.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    raise ApiError(401, "missing bearer token")
                try:
                    claims = authority.verify(header[7:])
                except TokenError as exc:
                    log_event("bad_token", str(exc))
                    raise ApiError(401, "invalid or expired token")
                if capability not in claims["caps"]:
                    log_event("capability_denied", f"user={claims['sub']} needs {capability}")
                    raise ApiError(403, "capability not granted")
                g.claims = claims
                g.caps = frozenset(claims["caps"]) | {"audit:write"}
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # ------------------------------------------------------------ hooks
    @app.before_request
    def rate_limit():
        if not ip_limiter.allow(client_ip()):
            raise ApiError(429, "too many requests")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    @app.errorhandler(ApiError)
    def handle_api_error(err):
        return jsonify(error=err.message), err.status

    @app.errorhandler(CapabilityDenied)
    def handle_denied(err):
        log_event("capability_denied", f"db layer: {err}")
        return jsonify(error="capability not granted"), 403

    @app.errorhandler(UnknownQuery)
    @app.errorhandler(BadParameters)
    def handle_bad_query(err):
        log.error("data-layer misuse: %r", err)
        return jsonify(error="internal error"), 500

    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def handle_http(err):
        return jsonify(error=err.name.lower()), err.code

    @app.errorhandler(Exception)
    def handle_unexpected(err):
        log.exception("unhandled error")
        return jsonify(error="internal error"), 500  # never leak details

    # ------------------------------------------------------------ routes
    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/register")
    def register():
        f = checked(request.get_json(silent=True), guard.REGISTER)
        email = f["email"].lower()
        bidx = crypto.blind_index(email)
        try:
            if db.run("user.email_exists", (bidx,), PUBLIC_CAPS):
                raise ApiError(409, "account could not be created")
            db.run("user.create", (
                f["username"], crypto.encrypt(email, "email"), bidx,
                crypto.encrypt(f.get("phone", ""), "phone"),
                crypto.protect_password(f["password"]), "user", _now()), PUBLIC_CAPS)
        except sqlite3.IntegrityError:
            raise ApiError(409, "account could not be created")  # generic: no user enumeration
        return jsonify(status="created"), 201

    @app.post("/login")
    def login():
        f = checked(request.get_json(silent=True), guard.LOGIN)
        key = f"{client_ip()}:{f['username'].lower()}"
        if login_failures.count(key) >= MAX_LOGIN_FAILURES:
            log_event("login_lockout", f"user={f['username']}")
            raise ApiError(429, "too many failed attempts, try again later")
        row = db.run("user.by_username", (f["username"],), PUBLIC_CAPS)
        try:
            if row is None:
                crypto.dummy_check(f["password"])
                ok = False
            else:
                ok = crypto.check_password(f["password"], row["password_enc"])
        except InvalidTag:
            log_event("integrity_failure", f"stored credential for user id={row['id']} failed GCM check")
            raise ApiError(500, "internal error")
        if not ok:
            login_failures.add(key)
            log_event("login_failed", f"user={f['username']}")
            raise ApiError(401, "invalid credentials")
        login_failures.clear(key)
        token, caps = authority.issue(row["id"], row["role"])
        return jsonify(token=token, token_type="Bearer", expires_in=config.token_ttl, capabilities=caps)

    @app.get("/profile")
    @requires("profile:read")
    def get_profile():
        row = db.run("profile.get", (g.claims["sub"],), g.caps)
        if row is None:
            raise ApiError(404, "not found")
        return jsonify(id=row["id"], username=row["username"], created_at=row["created_at"],
                       email=crypto.decrypt(row["email_enc"], "email"),
                       phone=crypto.decrypt(row["phone_enc"], "phone"))

    @app.put("/profile")
    @requires("profile:write")
    def update_profile():
        f = checked(request.get_json(silent=True), guard.PROFILE_UPDATE)
        if not f:
            raise ApiError(400, "nothing to update")
        uid = g.claims["sub"]  # always the token's subject: no way to edit someone else's row
        row = db.run("profile.get", (uid,), g.caps)
        if row is None:
            raise ApiError(404, "not found")
        email = f.get("email", crypto.decrypt(row["email_enc"], "email")).lower()
        phone = f.get("phone", crypto.decrypt(row["phone_enc"], "phone"))
        bidx = crypto.blind_index(email)
        try:
            if db.run("profile.email_taken", (bidx, uid), g.caps):
                raise ApiError(409, "email unavailable")
            db.run("profile.update", (crypto.encrypt(email, "email"), bidx,
                                      crypto.encrypt(phone, "phone"), uid), g.caps)
        except sqlite3.IntegrityError:
            raise ApiError(409, "email unavailable")
        return jsonify(status="updated")

    @app.get("/admin/users")
    @requires("users:search")
    def search_users():
        f = checked({"prefix": request.args.get("prefix", "")}, guard.SEARCH)
        rows = db.run("users.search", (guard.escape_like(f.get("prefix", "")) + "%",), g.caps)
        return jsonify(users=rows)

    @app.get("/admin/security-events")
    @requires("audit:read")
    def security_events():
        return jsonify(events=db.run("audit.recent", (), g.caps))

    return app
