from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

import app as app_module


class SubscriptionTokenManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._old_config_env = os.environ.get("TROJAN_PANEL_CONFIG")
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.config_path = Path(cls._tmpdir.name) / "servers.json"
        os.environ["TROJAN_PANEL_CONFIG"] = str(cls.config_path)
        app_module.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._old_config_env is None:
            os.environ.pop("TROJAN_PANEL_CONFIG", None)
        else:
            os.environ["TROJAN_PANEL_CONFIG"] = cls._old_config_env
        cls._tmpdir.cleanup()

    def setUp(self) -> None:
        self.client = app_module.app.test_client()
        self.write_config(subscriptions={})

    def write_config(self, subscriptions: dict[str, list[str]], auth: dict[str, str] | None = None) -> None:
        payload = {
            "servers": [
                {
                    "id": "hk-main",
                    "name": "Hong Kong Main",
                    "command_template": "ssh hk trojan port $1",
                    "status_command_template": "ssh hk trojan status",
                    "addr": "hk.example.com",
                    "trojan_password": "pwd-hk",
                    "current_port": 443,
                },
                {
                    "id": "sg-main",
                    "name": "Singapore Main",
                    "command_template": "ssh sg trojan port $1",
                    "status_command_template": "ssh sg trojan status",
                    "addr": "sg.example.com",
                    "trojan_password": "pwd-sg",
                    "current_port": 8443,
                },
            ],
            "subscriptions": subscriptions,
        }
        if auth is not None:
            payload["auth"] = auth
        with self.config_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")

    def read_config(self) -> dict:
        with self.config_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def test_generate_custom_token_and_list(self) -> None:
        resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["hk-main", "sg-main"], "token": "teamA"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["token"], "teamA")
        self.assertFalse(body["overwritten"])
        self.assertEqual(body["server_count"], 2)
        self.assertEqual(body["server_ids"], ["hk-main", "sg-main"])
        self.assertEqual(len(body["links"]), 2)

        list_resp = self.client.get("/api/subscriptions")
        self.assertEqual(list_resp.status_code, 200)
        list_body = list_resp.get_json()
        self.assertTrue(list_body["ok"])
        self.assertEqual(list_body["count"], 1)
        item = list_body["subscriptions"][0]
        self.assertEqual(item["token"], "teamA")
        self.assertEqual(item["server_ids"], ["hk-main", "sg-main"])
        self.assertEqual(item["server_names"], ["Hong Kong Main", "Singapore Main"])
        self.assertEqual(item["missing_server_ids"], [])
        self.assertTrue(item["url"].endswith("/sub/teamA"))

    def test_generate_with_existing_token_sets_overwritten(self) -> None:
        self.write_config(subscriptions={"teamA": ["hk-main"]})
        resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["sg-main"], "token": "teamA"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["overwritten"])
        self.assertEqual(body["token"], "teamA")
        self.assertEqual(body["server_ids"], ["sg-main"])

        cfg = self.read_config()
        self.assertEqual(cfg["subscriptions"]["teamA"], ["sg-main"])

    def test_delete_subscription_success(self) -> None:
        self.write_config(subscriptions={"to-delete": ["hk-main", "sg-main"]})
        resp = self.client.delete("/api/subscriptions/to-delete")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["token"], "to-delete")
        self.assertEqual(body["server_count"], 2)

        cfg = self.read_config()
        self.assertEqual(cfg["subscriptions"], {})

        list_resp = self.client.get("/api/subscriptions")
        self.assertEqual(list_resp.status_code, 200)
        self.assertEqual(list_resp.get_json()["count"], 0)

    def test_delete_subscription_not_found(self) -> None:
        resp = self.client.delete("/api/subscriptions/not-exists")
        self.assertEqual(resp.status_code, 404)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("not found", body["message"].lower())

    def test_list_subscriptions_reports_missing_servers(self) -> None:
        self.write_config(subscriptions={"mixed": ["hk-main", "gone-server"]})
        resp = self.client.get("/api/subscriptions")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["count"], 1)
        item = body["subscriptions"][0]
        self.assertEqual(item["token"], "mixed")
        self.assertEqual(item["server_count"], 2)
        self.assertEqual(item["server_names"], ["Hong Kong Main"])
        self.assertEqual(item["missing_server_ids"], ["gone-server"])

    def test_generate_rejects_invalid_token(self) -> None:
        resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["hk-main"], "token": "bad token"},
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("token", body["message"].lower())

    def test_delete_rejects_invalid_token(self) -> None:
        resp = self.client.delete("/api/subscriptions/bad%20token")
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("token", body["message"].lower())

    def test_subscription_content_matches_selected_servers(self) -> None:
        create_resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["hk-main", "sg-main"], "token": "bundle"},
        )
        self.assertEqual(create_resp.status_code, 200)
        self.assertTrue(create_resp.get_json()["ok"])

        sub_resp = self.client.get("/sub/bundle")
        self.assertEqual(sub_resp.status_code, 200)
        encoded = sub_resp.get_data(as_text=True).strip()
        decoded = base64.b64decode(encoded).decode("utf-8")
        lines = [line for line in decoded.splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith("trojan://") for line in lines))

    def test_api_requires_login_when_auth_enabled(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
        )
        resp = self.client.get("/api/subscriptions")
        self.assertEqual(resp.status_code, 401)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("unauthorized", body["message"].lower())

    def test_api_accessible_after_login_when_auth_enabled(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
        )
        login_resp = self.client.post(
            "/login",
            data={"username": "admin", "password": "pass123", "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(login_resp.status_code, 302)

        list_resp = self.client.get("/api/subscriptions")
        self.assertEqual(list_resp.status_code, 200)
        body = list_resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["count"], 1)

    def test_subscriptions_page_renders(self) -> None:
        resp = self.client.get("/subscriptions")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("sub-manager-token-list", html)
        self.assertIn("sub-manager-refresh-btn", html)

    def test_subscriptions_page_redirects_to_login_when_auth_enabled(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
        )
        resp = self.client.get("/subscriptions", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        location = resp.headers.get("Location", "")
        self.assertTrue(location.startswith("/login?next="))
        self.assertIn("/subscriptions", location)


if __name__ == "__main__":
    unittest.main(verbosity=2)
