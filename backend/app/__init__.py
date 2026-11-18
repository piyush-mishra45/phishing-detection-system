import logging
import os
import time

from flask import Flask, g, jsonify, request

from config import Config


def create_app(config_overrides: dict | None = None):
    from app.database import db as dbm
    from app.ml import predictor
    from app.security.validators import ValidationError

    Config.validate()
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config.update(SECRET_KEY=Config.SECRET_KEY)
    if config_overrides:
        app.config.update(config_overrides)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("phishguard")

    dbm.init_engine(app.config["DATABASE_URL"])
    dbm.init_db()
    predictor.configure(app.config["MODEL_DIR"])

    from app.services.metrics_sync import sync_metrics
    try:
        sync_metrics(app.config["MODEL_DIR"])
    except Exception:
        log.exception("metrics sync failed (non-fatal)")
    finally:
        dbm.Session.remove()

    if os.getenv("TRUST_PROXY") == "1":  # behind Render/nginx: use the proxy's X-Forwarded-For for client IPs
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from app.routes import admin, auth, dashboard, history, misc, scan
    for bp in (misc.bp, auth.bp, scan.bp, history.bp, dashboard.bp, admin.bp):
        app.register_blueprint(bp)

    @app.before_request
    def _start():
        g.t0 = time.monotonic()

    @app.after_request
    def _after(resp):
        origin = request.headers.get("Origin")
        if origin and origin in app.config["CORS_ORIGINS"]:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        # Secure logging: method, path, status, user id, duration. Never bodies, tokens, passwords or e-mail content.
        log.info("%s %s -> %s uid=%s %.0fms", request.method, request.path, resp.status_code, getattr(g, "user_id", "-"), (time.monotonic() - g.get("t0", time.monotonic())) * 1000)
        return resp

    @app.teardown_appcontext
    def _cleanup(exc):
        if dbm.Session is not None:
            dbm.Session.remove()

    @app.errorhandler(ValidationError)
    def _val(e):
        return jsonify({"error": e.message, "field": e.field}), 400

    for code, msg in ((400, "Bad request"), (404, "Not found"), (405, "Method not allowed"), (413, "Upload too large (max 2 MB)")):
        app.register_error_handler(code, lambda e, m=msg, c=code: (jsonify({"error": m}), c))

    @app.errorhandler(Exception)
    def _unhandled(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return jsonify({"error": e.description}), e.code
        log.exception("Unhandled error on %s %s", request.method, request.path)  # stack trace to server log only
        return jsonify({"error": "Internal server error"}), 500

    return app
