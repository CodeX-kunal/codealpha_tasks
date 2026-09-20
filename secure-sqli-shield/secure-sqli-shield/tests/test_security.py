import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.exceptions import InvalidTag

from app import create_app
from app.capabilities import CapabilityAuthority, TokenError
from app.config import Config
from app.crypto import Crypto
from app.db import BadParameters, CapabilityDenied, UnknownQuery
from app.main import PUBLIC_CAPS

PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM users--",
    "'; DROP TABLE users;--",
    "1' AND SLEEP(5)--",
    "x' OR 1=1 /*",
    "' UNION ALL SELECT username, password_enc FROM users",
]
USER = {"username": "alice", "email": "Alice@Example.com", "phone": "+91 98765 43210",
        "password": "Str0ng-Pa55word!"}


def make_app():
    cfg = Config(enc_key=os.urandom(32), mac_key=os.urandom(32), db_path=":memory:", token_ttl=900)
    return create_app(cfg)


class Base(unittest.TestCase):
    def setUp(self):
        self.app = make_app()
        self.c = self.app.test_client()
        self.db = self.app.extensions["secure_db"]
        self.crypto = self.app.extensions["crypto"]

    def register(self, **over):
        return self.c.post("/register", json={**USER, **over})

    def token(self, username="alice", password=USER["password"]):
        r = self.c.post("/login", json={"username": username, "password": password})
        return r.get_json()["token"]

    def auth(self, tok):
        return {"Authorization": f"Bearer {tok}"}

    def make_admin(self):
        self.db.run("user.create", ("root", self.crypto.encrypt("root@example.com", "email"),
                                    self.crypto.blind_index("root@example.com"),
                                    self.crypto.encrypt("", "phone"),
                                    self.crypto.protect_password("Admin-Pa55word!"), "admin", "now"),
                    {"auth:register"})
        return self.token("root", "Admin-Pa55word!")

    def user_count(self):
        return self.db._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


class EncryptionTests(Base):
    def test_sensitive_fields_are_encrypted_at_rest(self):
        self.assertEqual(self.register().status_code, 201)
        row = self.db._conn.execute("SELECT * FROM users").fetchone()
        for col in ("email_enc", "phone_enc", "password_enc"):
            self.assertTrue(row[col].startswith("v1:"))
        self.assertNotIn("alice@example.com", row["email_enc"].lower())
        self.assertNotIn("98765", row["phone_enc"])
        self.assertNotIn(USER["password"], row["password_enc"])

    def test_roundtrip_through_api(self):
        self.register()
        r = self.c.get("/profile", headers=self.auth(self.token()))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["email"], "alice@example.com")
        self.assertEqual(r.get_json()["phone"], USER["phone"])

    def test_gcm_detects_tampering_and_column_swapping(self):
        ct = self.crypto.encrypt("secret", "email")
        with self.assertRaises(InvalidTag):
            self.crypto.decrypt(ct[:-3] + ("AAA" if not ct.endswith("AAA") else "BBB"), "email")
        with self.assertRaises(InvalidTag):
            self.crypto.decrypt(ct, "phone")  # ciphertext bound to its column

    def test_same_plaintext_gives_different_ciphertext(self):
        self.assertNotEqual(self.crypto.encrypt("x", "email"), self.crypto.encrypt("x", "email"))

    def test_key_must_be_256_bits(self):
        with self.assertRaises(ValueError):
            Crypto(os.urandom(16), os.urandom(32))


class Layer1Tests(Base):
    def test_payloads_rejected_and_logged_on_every_endpoint(self):
        self.register()
        admin = self.make_admin()
        for p in PAYLOADS:
            self.assertEqual(self.c.post("/login", json={"username": p, "password": "x"}).status_code, 400, p)
            self.assertEqual(self.register(username=p, email="z@example.com").status_code, 400, p)
            r = self.c.get("/admin/users", query_string={"prefix": p}, headers=self.auth(admin))
            self.assertEqual(r.status_code, 400, p)
        events = self.c.get("/admin/security-events", headers=self.auth(admin)).get_json()["events"]
        self.assertGreaterEqual(sum(e["kind"] == "sqli_suspected" for e in events), len(PAYLOADS))
        self.assertEqual(self.user_count(), 2)  # table intact, nothing extra created

    def test_injection_in_password_is_just_a_wrong_password(self):
        self.register()
        r = self.c.post("/login", json={"username": "alice", "password": "' OR '1'='1"})
        self.assertEqual(r.status_code, 401)

    def test_passwords_with_sql_characters_are_allowed(self):
        self.assertEqual(self.register(password="Pa'ss--word;DROP1").status_code, 201)
        self.assertIn("token", self.c.post("/login", json={"username": "alice",
                                                          "password": "Pa'ss--word;DROP1"}).get_json())

    def test_unexpected_fields_and_bad_types_rejected(self):
        self.assertEqual(self.register(role="admin").status_code, 400)  # mass-assignment attempt
        self.assertEqual(self.c.post("/login", json={"username": ["a"], "password": "x"}).status_code, 400)
        self.assertEqual(self.c.post("/login", data="not json").status_code, 400)

    def test_lockout_after_repeated_failures(self):
        self.register()
        for _ in range(5):
            self.assertEqual(self.c.post("/login", json={"username": "alice", "password": "wrong-pass"}).status_code, 401)
        r = self.c.post("/login", json={"username": "alice", "password": USER["password"]})
        self.assertEqual(r.status_code, 429)

    def test_oversized_body_rejected(self):
        r = self.c.post("/login", data="x" * 20000, content_type="application/json")
        self.assertEqual(r.status_code, 413)


class Layer2Tests(Base):
    """These bypass Layer 1 entirely and hit the data layer directly."""

    def test_payload_is_treated_as_a_literal_value(self):
        self.register()
        for p in PAYLOADS:
            self.assertIsNone(self.db.run("user.by_username", (p,), PUBLIC_CAPS), p)
        self.assertEqual(self.user_count(), 1)

    def test_no_raw_sql_only_catalogued_queries(self):
        with self.assertRaises(UnknownQuery):
            self.db.run("SELECT * FROM users", (), PUBLIC_CAPS)

    def test_capability_required_for_each_query(self):
        with self.assertRaises(CapabilityDenied):
            self.db.run("audit.recent", (), PUBLIC_CAPS)
        with self.assertRaises(CapabilityDenied):
            self.db.run("users.search", ("a%",), {"profile:read"})

    def test_parameter_types_enforced(self):
        with self.assertRaises(BadParameters):
            self.db.run("profile.get", ("1 OR 1=1",), {"profile:read"})
        with self.assertRaises(BadParameters):
            self.db.run("user.by_username", ("a", "b"), PUBLIC_CAPS)

    def test_connection_is_least_privilege(self):
        for stmt in ("DROP TABLE users", "DELETE FROM users", "ALTER TABLE users ADD COLUMN x TEXT",
                     "SELECT * FROM sqlite_master", "ATTACH DATABASE 'x.db' AS x",
                     "CREATE TABLE evil(a)", "PRAGMA table_info(users)"):
            with self.assertRaises(sqlite3.DatabaseError, msg=stmt):
                self.db._conn.execute(stmt)

    def test_stacked_statements_refused(self):
        with self.assertRaises(sqlite3.Error):
            self.db._conn.execute("SELECT 1; DROP TABLE users")
        self.assertEqual(self.user_count(), 0)


class CapabilityTests(Base):
    def test_authentication_and_authorisation(self):
        self.register()
        tok = self.token()
        self.assertEqual(self.c.get("/profile").status_code, 401)
        self.assertEqual(self.c.get("/admin/users", headers=self.auth(tok)).status_code, 403)
        self.assertEqual(self.c.get("/admin/security-events", headers=self.auth(tok)).status_code, 403)
        admin = self.make_admin()
        r = self.c.get("/admin/users", query_string={"prefix": "ali"}, headers=self.auth(admin))
        self.assertEqual([u["username"] for u in r.get_json()["users"]], ["alice"])

    def test_like_wildcards_are_escaped(self):
        self.register()
        admin = self.make_admin()
        r = self.c.get("/admin/users", query_string={"prefix": "%"}, headers=self.auth(admin))
        self.assertEqual(r.status_code, 400)  # '%' fails the allow-list
        from app.guard import escape_like
        # a literal '%' prefix must match only usernames that really start with '%', not everything
        self.assertEqual(self.db.run("users.search", (escape_like("%") + "%",), {"users:search"}), [])
        self.assertEqual(len(self.db.run("users.search", ("%",), {"users:search"})), 2)  # unescaped = wildcard

    def test_tampered_or_forged_tokens_rejected(self):
        self.register()
        tok = self.token()
        payload, sig = tok.split(".")
        self.assertEqual(self.c.get("/profile", headers=self.auth(payload + "." + sig[:-2] + "AA")).status_code, 401)
        import base64, json
        body = json.loads(base64.urlsafe_b64decode(payload + "=="))
        body["caps"].append("audit:read")
        forged = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
        self.assertEqual(self.c.get("/admin/security-events", headers=self.auth(forged + "." + sig)).status_code, 401)

    def test_expired_token_rejected(self):
        auth = CapabilityAuthority(os.urandom(32), ttl=-1)
        with self.assertRaises(TokenError):
            auth.verify(auth.issue(1, "user")[0])

    def test_users_only_touch_their_own_profile(self):
        self.register()
        self.register(username="bob", email="bob@example.com")
        r = self.c.put("/profile", json={"phone": "+1 555 123 4567"}, headers=self.auth(self.token("bob")))
        self.assertEqual(r.status_code, 200)
        mine = self.c.get("/profile", headers=self.auth(self.token())).get_json()
        self.assertEqual(mine["phone"], USER["phone"])  # alice unchanged

    def test_duplicate_email_rejected_without_leaking_which(self):
        self.assertEqual(self.register().status_code, 201)
        r = self.register(username="mallory")
        self.assertEqual((r.status_code, r.get_json()["error"]), (409, "account could not be created"))


class ResponseHardeningTests(Base):
    def test_headers_and_no_error_leakage(self):
        r = self.c.get("/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        r = self.c.get("/nope")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
