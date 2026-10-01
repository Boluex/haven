import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = str(Path(self.temp.name) / "test.sqlite")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-only", "DATABASE": self.db_path})
        self.client = self.app.test_client()

    def post_form(self, page, data, client=None):
        client = client or self.client
        html = client.get(page).get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        return client.post(page, data={"csrf_token": token, **data})

    def register(self, **overrides):
        return self.post_form("/register", {
            "name": "Alex Morgan", "email": "Alex@example.com", "password": "a-good-password",
            "confirm_password": "a-good-password", **overrides,
        })

    def logout(self):
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        return self.client.post("/logout", data={"csrf_token": token})

    def test_full_flow_and_persistence(self):
        response = self.register()
        self.assertEqual(response.location, "/success")
        page = self.client.get("/success").get_data(as_text=True)
        self.assertIn("It worked!", page)
        self.assertIn("Your account is ready", page)
        self.assertIn("Alex Morgan", page)
        with sqlite3.connect(self.db_path) as db:
            password_hash = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotEqual(password_hash, "a-good-password")
        response = self.logout()
        self.assertEqual(response.location, "/logged-out")
        self.assertIn("You’re logged out.", self.client.get(response.location).get_data(as_text=True))
        self.assertEqual(self.client.get("/success").location, "/login")
        # A fresh application and browser still find the saved account.
        fresh = create_app({"TESTING": True, "SECRET_KEY": "test-only", "DATABASE": self.db_path}).test_client()
        response = self.post_form("/login", {"email": "ALEX@example.com", "password": "a-good-password"}, fresh)
        self.assertEqual(response.location, "/success")
        self.assertIn("successfully logged in", fresh.get("/success").get_data(as_text=True))

    def test_invalid_password_and_duplicate_account(self):
        self.register()
        self.logout()
        response = self.register(email="alex@example.com")
        self.assertEqual(response.status_code, 400)
        self.assertIn("already exists", response.get_data(as_text=True))
        response = self.post_form("/login", {"email": "alex@example.com", "password": "wrong-password"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/success").location, "/login")

    def test_registration_validation(self):
        for data in ({"name": ""}, {"email": "invalid"}, {"password": "short"}, {"confirm_password": "different"}):
            with self.subTest(data=data):
                self.assertEqual(self.register(**data).status_code, 400)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_csrf_and_logout_method(self):
        self.assertEqual(self.client.post("/register", data={}).status_code, 400)
        self.register()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout", data={"csrf_token": "wrong"}).status_code, 400)
        self.assertEqual(self.client.get("/success").status_code, 200)

    def test_account_name_is_escaped(self):
        self.register(name="<script>alert(1)</script>")
        page = self.client.get("/success").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
