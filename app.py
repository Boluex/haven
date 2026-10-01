import functools
import os
from pathlib import Path
import re
import secrets
import sqlite3
from datetime import timedelta

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


PAYMENT_SCENARIOS = {
    "success": ("Successful payment", "Your demo payment was successful."),
    "declined": ("Card declined", "The simulated bank declined this payment."),
    "insufficient_funds": ("Insufficient funds", "The simulated account has insufficient funds."),
    "timeout": ("Gateway timeout", "The simulated gateway timed out before completing payment."),
    "cancelled": ("Payment cancelled", "You cancelled this demo payment."),
}
DEMO_AMOUNT = "5,000.00"


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
        database().execute(
            "CREATE TABLE IF NOT EXISTS payments (reference TEXT PRIMARY KEY, "
            "user_id INTEGER NOT NULL REFERENCES users(id), outcome TEXT NOT NULL, "
            "amount TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
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

    def payment_result_url(payment):
        return url_for(
            "payment_success" if payment["outcome"] == "success" else "payment_unsuccessful",
            reference=payment["reference"],
        )

    @app.route("/checkout", methods=["GET", "POST"])
    @login_required
    def checkout():
        if request.method == "POST":
            reference = request.form.get("reference", "")
            # Repeated submissions return the original result, even if the outcome changes.
            payment = database().execute(
                "SELECT * FROM payments WHERE reference = ? AND user_id = ?",
                (reference, g.user["id"]),
            ).fetchone()
            if payment:
                return redirect(payment_result_url(payment), code=303)
            if not reference or not secrets.compare_digest(
                reference, session.get("checkout_reference", "")
            ):
                abort(400, "This checkout expired. Open checkout again to start a new payment.")
            action = request.form.get("action", "pay")
            if action not in ("pay", "cancel"):
                abort(400, "Choose a valid payment action.")
            outcome = "cancelled" if action == "cancel" else request.form.get("scenario", "")
            if outcome not in PAYMENT_SCENARIOS:
                abort(400, "Choose a valid simulation outcome.")
            database().execute(
                "INSERT OR IGNORE INTO payments (reference, user_id, outcome, amount) VALUES (?, ?, ?, ?)",
                (reference, g.user["id"], outcome, DEMO_AMOUNT),
            )
            database().commit()
            session.pop("checkout_reference", None)
            payment = database().execute(
                "SELECT * FROM payments WHERE reference = ? AND user_id = ?",
                (reference, g.user["id"]),
            ).fetchone()
            return redirect(payment_result_url(payment), code=303)
        reference = session.setdefault("checkout_reference", "demo_" + secrets.token_hex(16))
        return render_template(
            "checkout.html", reference=reference, amount=DEMO_AMOUNT, scenarios=PAYMENT_SCENARIOS
        )

    def show_payment(reference, successful):
        payment = database().execute(
            "SELECT * FROM payments WHERE reference = ? AND user_id = ?",
            (reference, g.user["id"]),
        ).fetchone()
        if payment is None:
            abort(404)
        if (payment["outcome"] == "success") != successful:
            return redirect(payment_result_url(payment))
        label, message = PAYMENT_SCENARIOS[payment["outcome"]]
        return render_template(
            "payment_result.html", payment=payment, successful=successful, label=label, message=message
        )

    @app.route("/payment/success/<reference>")
    @login_required
    def payment_success(reference):
        return show_payment(reference, successful=True)

    @app.route("/payment/unsuccessful/<reference>")
    @login_required
    def payment_unsuccessful(reference):
        return show_payment(reference, successful=False)

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
