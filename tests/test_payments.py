from contextlib import closing
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from app import create_app


class PaymentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db_path = str(Path(temp.name) / "payments.sqlite")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-only", "DATABASE": self.db_path})
        self.client = self.app.test_client()
        self.register(self.client, "alex@example.com")

    def form_fields(self, client, path):
        html = client.get(path).get_data(as_text=True)
        return dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', html))

    def register(self, client, email):
        fields = self.form_fields(client, "/register")
        client.post("/register", data={**fields, "name": "Alex Morgan", "email": email,
                    "password": "a-good-password", "confirm_password": "a-good-password"})

    def pay(self, scenario="success", **overrides):
        fields = self.form_fields(self.client, "/checkout")
        return self.client.post("/checkout", data={**fields, "scenario": scenario, **overrides})

    def test_success_redirect_and_receipt_survive_refresh(self):
        self.assertIn("Try a demo payment", self.client.get("/success").get_data(as_text=True))
        response = self.pay(amount="0.01", user_id="999")
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.startswith("/payment/success/demo_"))
        for _ in range(2):
            receipt = self.client.get(response.location)
            self.assertEqual(receipt.status_code, 200)
            self.assertIn("Payment successful.", receipt.get_data(as_text=True))
            self.assertIn("NGN 5,000.00", receipt.get_data(as_text=True))
            self.assertIn("No real money was charged", receipt.get_data(as_text=True))
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT outcome, amount, user_id FROM payments").fetchall(),
                             [("success", "5,000.00", 1)])

    def test_failure_outcomes_and_retry(self):
        references = set()
        for outcome, message in (("declined", "bank declined"),
                                 ("insufficient_funds", "insufficient funds"),
                                 ("timeout", "timed out"), ("cancelled", "cancelled")):
            with self.subTest(outcome=outcome):
                response = self.pay(outcome)
                self.assertEqual(response.status_code, 303)
                self.assertTrue(response.location.startswith("/payment/unsuccessful/"))
                references.add(response.location)
                html = self.client.get(response.location).get_data(as_text=True)
                self.assertIn("Payment unsuccessful.", html)
                self.assertIn(message, html)
                self.assertIn("Try again", html)
        self.assertEqual(len(references), 4)
        self.assertTrue(self.pay().location.startswith("/payment/success/"))

    def test_cancel_button_overrides_selected_success(self):
        response = self.pay(action="cancel")
        self.assertIn("Payment cancelled", self.client.get(response.location).get_data(as_text=True))

    def test_duplicate_submission_keeps_original_outcome(self):
        fields = self.form_fields(self.client, "/checkout")
        first = self.client.post("/checkout", data={**fields, "scenario": "success"})
        second = self.client.post("/checkout", data={**fields, "scenario": "declined"})
        self.assertEqual(first.location, second.location)
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 1)
        next_fields = self.form_fields(self.client, "/checkout")
        self.assertNotEqual(fields["reference"], next_fields["reference"])

    def test_invalid_requests_do_not_create_payments(self):
        fields = self.form_fields(self.client, "/checkout")
        for overrides in ({"csrf_token": "wrong"}, {"reference": "invented"},
                          {"reference": ""}, {"scenario": "invalid"}, {"action": "invalid"}):
            with self.subTest(overrides=overrides):
                response = self.client.post("/checkout", data={**fields, "scenario": "success", **overrides})
                self.assertEqual(response.status_code, 400)
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM payments").fetchone()[0], 0)

    def test_receipts_are_private_and_require_login(self):
        receipt = self.pay().location
        anonymous = self.app.test_client()
        for path in ("/checkout", receipt, "/payment/unsuccessful/unknown"):
            self.assertEqual(anonymous.get(path).location, "/login")
        fields = self.form_fields(anonymous, "/login")
        self.assertEqual(anonymous.post("/checkout", data=fields).location, "/login")
        other = self.app.test_client()
        self.register(other, "other@example.com")
        self.assertEqual(other.get(receipt).status_code, 404)
        self.assertEqual(self.client.get("/payment/success/unknown").status_code, 404)
        fields = self.form_fields(other, "/checkout")
        response = other.post("/checkout", data={**fields, "scenario": "success",
                              "reference": receipt.rsplit("/", 1)[1]})
        self.assertEqual(response.status_code, 400)

    def test_url_cannot_change_result(self):
        failed = self.pay("declined").location
        response = self.client.get(failed.replace("/unsuccessful/", "/success/"))
        self.assertEqual(response.location, failed)
        successful = self.pay().location
        response = self.client.get(successful.replace("/success/", "/unsuccessful/"))
        self.assertEqual(response.location, successful)


if __name__ == "__main__":
    unittest.main()
