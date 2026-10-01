import functools
import os
from pathlib import Path
import re
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    secret_path = Path(app.instance_path) / "secret.key"
    secret_key = (test_config or {}).get("SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not secret_key:
        try:
            with open(secret_path, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as file:
                file.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        secret_key = secret_path.read_text().strip()
    app.config.update(
        SECRET_KEY=secret_key,
        DATABASE=str(Path(app.instance_path) / "accounts.sqlite"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    def database():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_database(error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        database().execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
            "name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL)"
        )
        database().commit()

    @app.before_request
    def load_user_and_check_csrf():
        g.user = None
        if session.get("user_id"):
            g.user = database().execute(
                "SELECT id, name, email FROM users WHERE id = ?", (session["user_id"],)
            ).fetchone()
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        if request.method == "POST":
            if not secrets.compare_digest(session["csrf_token"], request.form.get("csrf_token", "")):
                abort(400, "This form expired. Please refresh the page and try again.")

    @app.after_request
    def response_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline' https://easyeasy-be-staging.up.railway.app; "
            "connect-src 'self' https://easyeasy-be-staging.up.railway.app; "
            "img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

    def login_required(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def sign_in(user_id, registered=False):
        session.clear()
        session["user_id"] = user_id
        session["registered"] = registered
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True
        return redirect(url_for("success"))

    @app.route("/")
    def index():
        return redirect(url_for("success" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("success"))
        error = None
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirmation = request.form.get("confirm_password", "")
            if not 2 <= len(name) <= 80:
                error = "Please enter a name between 2 and 80 characters."
            elif len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                error = "Please enter a valid email address."
            elif not 8 <= len(password) <= 128:
                error = "Choose a password between 8 and 128 characters."
            elif password != confirmation:
                error = "Your passwords don’t match. Please try again."
            else:
                try:
                    cursor = database().execute(
                        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                        (name, email, generate_password_hash(password)),
                    )
                    database().commit()
                    return sign_in(cursor.lastrowid, registered=True)
                except sqlite3.IntegrityError:
                    database().rollback()
                    error = "An account with this email already exists. Please log in."
        return render_template("auth.html", mode="register", error=error), 400 if error else 200

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("success"))
        error = None
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = database().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and len(password) <= 128 and check_password_hash(user["password_hash"], password):
                return sign_in(user["id"])
            error = "The email or password is incorrect. Please try again."
        return render_template("auth.html", mode="login", error=error), 400 if error else 200

    @app.route("/success")
    @login_required
    def success():
        return render_template("result.html", logged_out=False)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("logged_out"))

    @app.route("/logged-out")
    def logged_out():
        if g.user:
            return redirect(url_for("success"))
        return render_template("result.html", logged_out=True)

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", message=error.description), 400

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))
