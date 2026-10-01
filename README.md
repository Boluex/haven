# Haven

A small, responsive website with working registration, login, and logout.

## Run locally

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `PORT` to use another port.

## Pages

- `/register`: create an account; automatically signs in and redirects to `/success`.
- `/login`: log in with an existing account and redirect to `/success`.
- `/success`: protected “It worked!” page with account details and a logout button.
- `/logged-out`: logout confirmation with a link back to login.
- `/checkout`: signed-in demo checkout for a fixed NGN 5,000.00 purchase. Choose success, card declined, insufficient funds, or gateway timeout, or cancel the payment.
- `/payment/success/<reference>`: successful demo payment receipt.
- `/payment/unsuccessful/<reference>`: failed or cancelled demo payment details with a retry link.

Select **Try a demo payment** after signing in. This gateway is entirely simulated: it collects no card details, calls no payment provider, and moves no money. Each submitted attempt is saved in SQLite and its receipt is only available to the account that created it. Repeated submissions of the same checkout return its original result; returning to checkout after a completed attempt creates a new reference. Payment records have the same local-storage persistence limitations as accounts.

Accounts persist in `instance/accounts.sqlite`. Passwords are hashed with Werkzeug’s scrypt password hashing. Authentication uses signed, HttpOnly, SameSite cookies with a 12-hour expiry. All forms include CSRF protection. Logout clears the session. A signing key is generated locally in `instance/secret.key`; keep the `instance` directory private.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

This is a local starter app. For public hosting, use a production WSGI server and HTTPS, set a strong `SECRET_KEY` and `COOKIE_SECURE=1`, and add login rate limiting. Password reset and email verification are not included.
