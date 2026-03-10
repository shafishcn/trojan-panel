from __future__ import annotations

import base64
import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
        with app_module.SMS_LOGIN_RUNTIME_LOCK:
            app_module.SMS_LOGIN_RUNTIME.clear()
        self.write_config(subscriptions={})

    def write_config(
        self,
        subscriptions: dict[str, object],
        auth: dict[str, str] | None = None,
        sms_login: dict | None = None,
        servers: list[dict] | None = None,
    ) -> None:
        server_list = servers if servers is not None else [
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
        ]
        payload = {
            "servers": server_list,
            "subscriptions": subscriptions,
        }
        if auth is not None:
            payload["auth"] = auth
        if sms_login is not None:
            payload["sms_login"] = sms_login
        with self.config_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")

    def read_config(self) -> dict:
        with self.config_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def build_sms_login(self, phones: list[str] | None = None) -> dict:
        selected_phones = phones or ["13800138000"]
        return {
            "enabled": True,
            "allowed_phones": selected_phones,
            "sign_name": "速通互联验证码",
            "template_code": "100001",
            "template_param": "{\"code\":\"##code##\",\"min\":\"##min##\"}",
        }

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
        self.assertIsNone(item["expires_at"])
        self.assertFalse(item["expired"])
        self.assertEqual(item["expiry_state"], "permanent")
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
        self.assertEqual(
            cfg["subscriptions"]["teamA"],
            {"server_ids": ["sg-main"], "expires_at": None},
        )

    def test_generate_subscription_with_expiry(self) -> None:
        expires_at = "2030-03-10T04:00:00Z"
        resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["hk-main"], "token": "expiring", "expires_at": expires_at},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["expires_at"], expires_at)
        self.assertFalse(body["expired"])
        self.assertEqual(body["expiry_state"], "active")

        cfg = self.read_config()
        self.assertEqual(
            cfg["subscriptions"]["expiring"],
            {"server_ids": ["hk-main"], "expires_at": expires_at},
        )

    def test_generate_rejects_past_expiry(self) -> None:
        resp = self.client.post(
            "/api/subscription-link",
            json={"server_ids": ["hk-main"], "token": "expired", "expires_at": "2020-01-01T00:00:00Z"},
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("有效期", body["message"])

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

    def test_list_subscriptions_reports_expiry_state(self) -> None:
        self.write_config(
            subscriptions={
                "permanent": ["hk-main"],
                "active": {"server_ids": ["sg-main"], "expires_at": "2026-03-10T12:00:00Z"},
                "expired": {"server_ids": ["hk-main"], "expires_at": "2026-03-08T12:00:00Z"},
            }
        )
        now = datetime.datetime(2026, 3, 9, 12, 0, tzinfo=datetime.timezone.utc)
        with patch.object(app_module, "utc_now", return_value=now):
            resp = self.client.get("/api/subscriptions")

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        items = {item["token"]: item for item in body["subscriptions"]}
        self.assertEqual(items["permanent"]["expiry_state"], "permanent")
        self.assertFalse(items["permanent"]["expired"])
        self.assertEqual(items["active"]["expiry_state"], "active")
        self.assertFalse(items["active"]["expired"])
        self.assertEqual(items["expired"]["expiry_state"], "expired")
        self.assertTrue(items["expired"]["expired"])

    def test_subscriptions_page_lists_expired_items_last(self) -> None:
        self.write_config(
            subscriptions={
                "alpha": {"server_ids": ["hk-main"], "expires_at": "2026-03-10T12:00:00Z"},
                "expired": {"server_ids": ["sg-main"], "expires_at": "2026-03-08T12:00:00Z"},
                "permanent": ["hk-main"],
            }
        )
        now = datetime.datetime(2026, 3, 9, 12, 0, tzinfo=datetime.timezone.utc)
        with patch.object(app_module, "utc_now", return_value=now):
            resp = self.client.get("/api/subscriptions")

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        ordered = [item["token"] for item in body["subscriptions"]]
        self.assertEqual(ordered, ["alpha", "permanent", "expired"])

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

    def test_subscription_content_returns_gone_when_expired(self) -> None:
        self.write_config(
            subscriptions={
                "bundle": {"server_ids": ["hk-main"], "expires_at": "2026-03-08T12:00:00Z"}
            }
        )
        now = datetime.datetime(2026, 3, 9, 12, 0, tzinfo=datetime.timezone.utc)
        with patch.object(app_module, "utc_now", return_value=now):
            sub_resp = self.client.get("/sub/bundle")
        self.assertEqual(sub_resp.status_code, 410)
        self.assertIn("expired", sub_resp.get_data(as_text=True))

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

    def test_api_requires_relogin_after_session_expires(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
        )
        login_ts = app_module.time.time()
        with patch.object(app_module.time, "time", return_value=login_ts):
            login_resp = self.client.post(
                "/login",
                data={"username": "admin", "password": "pass123", "next": "/"},
                follow_redirects=False,
            )
        self.assertEqual(login_resp.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(
                session.get("login_expires_at"),
                login_ts + app_module.LOGIN_SESSION_TTL_SECONDS,
            )

        expired_ts = login_ts + app_module.LOGIN_SESSION_TTL_SECONDS + 1
        with patch.object(app_module.time, "time", return_value=expired_ts):
            list_resp = self.client.get("/api/subscriptions")

        self.assertEqual(list_resp.status_code, 401)
        body = list_resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("unauthorized", body["message"].lower())
        with self.client.session_transaction() as session:
            self.assertFalse(session.get("logged_in"))

    def test_page_redirects_to_login_after_session_expires(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
        )
        login_ts = app_module.time.time()
        with patch.object(app_module.time, "time", return_value=login_ts):
            login_resp = self.client.post(
                "/login",
                data={"username": "admin", "password": "pass123", "next": "/"},
                follow_redirects=False,
            )
        self.assertEqual(login_resp.status_code, 302)

        expired_ts = login_ts + app_module.LOGIN_SESSION_TTL_SECONDS + 1
        with patch.object(app_module.time, "time", return_value=expired_ts):
            page_resp = self.client.get("/", follow_redirects=False)

        self.assertEqual(page_resp.status_code, 302)
        location = page_resp.headers.get("Location", "")
        self.assertTrue(location.startswith("/login?next="))

    def test_send_sms_code_requires_whitelisted_phone(self) -> None:
        self.write_config(
            subscriptions={},
            auth={"username": "admin", "password": "pass123"},
            sms_login=self.build_sms_login(["13800138000"]),
        )
        resp = self.client.post("/api/auth/send-sms-code", json={"phone": "13900000000"})
        self.assertEqual(resp.status_code, 403)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("未被授权", body["message"])

    def test_send_sms_code_limited_to_two_times_per_day(self) -> None:
        self.write_config(
            subscriptions={},
            auth={"username": "admin", "password": "pass123"},
            sms_login=self.build_sms_login(["13800138000"]),
        )
        with patch.object(app_module, "send_aliyun_sms_code", return_value={"ok": True, "message": "SMS sent."}):
            first = self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"})
            second = self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"})
            third = self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(third.status_code, 429)
        self.assertTrue(first.get_json()["ok"])
        self.assertTrue(second.get_json()["ok"])
        self.assertFalse(third.get_json()["ok"])
        self.assertEqual(first.get_json()["ttl_seconds"], 900)
        self.assertIn("15分钟内有效", first.get_json()["message"])

    def test_render_sms_template_param_replaces_min_placeholder(self) -> None:
        rendered = app_module.render_sms_template_param(
            "{\"code\":\"##code##\",\"min\":\"##min##\"}",
            "123456",
            900,
        )
        self.assertEqual(rendered, "{\"code\":\"123456\",\"min\":\"15\"}")

    def test_normalize_traffic_quota_supports_tb_and_gb(self) -> None:
        display_tb, bytes_tb = app_module.normalize_traffic_quota("2.9 TB")
        display_gb, bytes_gb = app_module.normalize_traffic_quota("6144 GB")

        self.assertEqual(display_tb, "2.9 TB")
        self.assertEqual(display_gb, "6144 GB")
        self.assertEqual(bytes_tb, int(app_module.Decimal("2.9") * (1024**4)))
        self.assertEqual(bytes_gb, 6144 * (1024**3))
        self.assertEqual(app_module.format_traffic_gb(bytes_tb), "2969.6 GB")
        self.assertEqual(app_module.format_traffic_gb(bytes_gb), "6144 GB")

    def test_run_server_traffic_check_sums_current_custom_cycle(self) -> None:
        server = {
            "id": "hk-main",
            "name": "Hong Kong Main",
            "command_template": "ssh hk trojan port $1",
            "status_command_template": "ssh hk trojan status",
            "vnstat_interface": "eth0",
            "traffic_cycle_day": 15,
            "traffic_quota": "2048 GB",
        }
        vnstat_payload = {
            "jsonversion": "2",
            "interfaces": [
                {
                    "name": "eth0",
                    "traffic": {
                        "total": {"rx": 999, "tx": 999},
                        "day": [
                            {"date": {"year": 2026, "month": 2, "day": 10}, "rx": 90, "tx": 10},
                            {"date": {"year": 2026, "month": 2, "day": 15}, "rx": 120, "tx": 30},
                            {"date": {"year": 2026, "month": 2, "day": 20}, "rx": 200, "tx": 50},
                            {"date": {"year": 2026, "month": 3, "day": 9}, "rx": 400, "tx": 80},
                        ],
                    },
                }
            ],
        }
        with patch.object(
            app_module,
            "run_shell_command",
            return_value={
                "ok": True,
                "message": "Traffic usage fetched.",
                "command": "ssh hk vnstat -i eth0 --json d 0",
                "returncode": 0,
                "stdout": json.dumps(vnstat_payload),
                "stderr": "",
            },
        ) as mock_run:
            result = app_module.run_server_traffic_check(server, today=datetime.date(2026, 3, 9))

        self.assertTrue(result["ok"])
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(result["traffic_cycle_day"], 15)
        self.assertEqual(result["traffic_cycle_label"], "每月 15 日重置")
        self.assertEqual(result["traffic_period_start"], "2026-02-15")
        self.assertEqual(result["traffic_period_end"], "2026-03-14")
        self.assertEqual(result["traffic_rx_bytes"], 720)
        self.assertEqual(result["traffic_tx_bytes"], 160)
        self.assertEqual(result["traffic_total_bytes"], 880)
        self.assertEqual(result["traffic_total_display"], "880 B")
        self.assertEqual(result["traffic_quota_display"], "2048 GB")
        self.assertEqual(result["traffic_remaining_display"], "2048 GB")
        self.assertEqual(result["traffic_quota_percent"], 0.0)
        self.assertIn("vnstat -i eth0 --json d 0", result["command"])
        mock_run.assert_called_once()

    def test_run_server_traffic_check_auto_selects_primary_interface(self) -> None:
        server = {
            "id": "hk-main",
            "name": "Hong Kong Main",
            "command_template": "ssh hk trojan port $1",
        }
        vnstat_payload = {
            "jsonversion": "2",
            "interfaces": [
                {
                    "name": "docker0",
                    "traffic": {
                        "total": {"rx": 10, "tx": 10},
                        "day": [{"date": {"year": 2026, "month": 3, "day": 9}, "rx": 10, "tx": 10}],
                    },
                },
                {
                    "name": "eth0",
                    "traffic": {
                        "total": {"rx": 1000, "tx": 500},
                        "day": [{"date": {"year": 2026, "month": 3, "day": 9}, "rx": 80, "tx": 20}],
                    },
                },
            ],
        }
        with patch.object(
            app_module,
            "run_shell_command",
            return_value={
                "ok": True,
                "message": "Traffic usage fetched.",
                "command": "ssh hk vnstat --json d 0",
                "returncode": 0,
                "stdout": json.dumps(vnstat_payload),
                "stderr": "",
            },
        ):
            result = app_module.run_server_traffic_check(server, today=datetime.date(2026, 3, 9))

        self.assertTrue(result["ok"])
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(result["traffic_total_bytes"], 100)

    def test_run_server_traffic_check_retries_legacy_vnstat_without_limit(self) -> None:
        server = {
            "id": "hk-main",
            "name": "Hong Kong Main",
            "command_template": "ssh hk trojan port $1",
            "status_command_template": "ssh hk trojan status",
            "vnstat_interface": "eth0",
        }
        legacy_payload = {
            "jsonversion": "1",
            "vnstatversion": "1.18",
            "interfaces": [
                {
                    "id": "eth0",
                    "traffic": {
                        "day": [
                            {"date": {"year": 2026, "month": 3, "day": 8}, "rx": 128, "tx": 64},
                            {"date": {"year": 2026, "month": 3, "day": 9}, "rx": 256, "tx": 128},
                        ]
                    },
                }
            ],
        }
        with patch.object(
            app_module,
            "run_shell_command",
            side_effect=[
                {
                    "ok": False,
                    "message": "Failed to fetch traffic usage.",
                    "command": "ssh hk vnstat -i eth0 --json d 0",
                    "returncode": 1,
                    "stdout": 'Unknown parameter "0". Use --help for help.',
                    "stderr": "",
                },
                {
                    "ok": True,
                    "message": "Traffic usage fetched.",
                    "command": "ssh hk vnstat -i eth0 --json d",
                    "returncode": 0,
                    "stdout": json.dumps(legacy_payload),
                    "stderr": "",
                },
            ],
        ) as mock_run:
            result = app_module.run_server_traffic_check(server, today=datetime.date(2026, 3, 9))

        self.assertTrue(result["ok"])
        self.assertEqual(result["interface"], "eth0")
        self.assertEqual(result["traffic_rx_bytes"], (128 + 256) * 1024)
        self.assertEqual(result["traffic_tx_bytes"], (64 + 128) * 1024)
        self.assertEqual(result["traffic_total_bytes"], (128 + 64 + 256 + 128) * 1024)
        self.assertIn("vnstat -i eth0 --json d", result["command"])
        self.assertNotIn("vnstat -i eth0 --json d 0", result["command"])
        self.assertEqual(mock_run.call_count, 2)
        first_call = mock_run.call_args_list[0].args[0]
        second_call = mock_run.call_args_list[1].args[0]
        self.assertEqual(first_call[-1], "vnstat -i eth0 --json d 0")
        self.assertEqual(second_call[-1], "vnstat -i eth0 --json d")

    def test_save_servers_preserves_vnstat_fields(self) -> None:
        self.write_config(
            subscriptions={},
            servers=[
                {
                    "id": "hk-main",
                    "name": "Hong Kong Main",
                    "command_template": "ssh hk trojan port $1",
                    "status_command_template": "ssh hk trojan status",
                    "addr": "hk.example.com",
                    "trojan_password": "pwd-hk",
                    "current_port": 443,
                    "vnstat_interface": "eth0",
                    "traffic_cycle_day": 15,
                    "traffic_quota": "2048 GB",
                }
            ],
        )
        get_resp = self.client.get("/api/servers")
        self.assertEqual(get_resp.status_code, 200)
        body = get_resp.get_json()
        self.assertTrue(body["ok"])

        put_resp = self.client.put(
            "/api/servers",
            json={
                "servers": body["servers"],
                "auth": {"username": "", "password": ""},
            },
        )
        self.assertEqual(put_resp.status_code, 200)
        cfg = self.read_config()
        self.assertEqual(cfg["servers"][0]["vnstat_interface"], "eth0")
        self.assertEqual(cfg["servers"][0]["traffic_cycle_day"], 15)
        self.assertEqual(cfg["servers"][0]["traffic_quota"], "2048 GB")

    def test_server_traffic_api_returns_usage_payload(self) -> None:
        with patch.object(
            app_module,
            "run_server_traffic_check",
            return_value={
                "ok": True,
                "message": "Traffic usage fetched.",
                "command": "ssh hk vnstat --json d 0",
                "returncode": 0,
                "stdout": "{}",
                "stderr": "",
                "traffic_cycle_day": 1,
                "traffic_cycle_label": "自然月（每月 1 日）",
                "traffic_period_start": "2026-03-01",
                "traffic_period_end": "2026-03-31",
                "traffic_period_label": "2026-03-01 至 2026-03-31",
                "interface": "eth0",
                "traffic_rx_bytes": 100,
                "traffic_tx_bytes": 80,
                "traffic_total_bytes": 180,
                "traffic_rx_display": "100 B",
                "traffic_tx_display": "80 B",
                "traffic_total_display": "180 B",
                "traffic_quota_display": "2048 GB",
                "traffic_remaining_display": "2048 GB",
                "traffic_quota_percent": 0.0,
            },
        ) as mock_check:
            resp = self.client.post("/api/server-traffic", json={"server_id": "hk-main"})

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["server_id"], "hk-main")
        self.assertEqual(body["traffic_total_display"], "180 B")
        self.assertEqual(body["traffic_quota_display"], "2048 GB")
        mock_check.assert_called_once()

    def test_sms_login_success(self) -> None:
        self.write_config(
            subscriptions={"teamA": ["hk-main"]},
            auth={"username": "admin", "password": "pass123"},
            sms_login=self.build_sms_login(["13800138000"]),
        )
        with (
            patch.object(app_module, "send_aliyun_sms_code", return_value={"ok": True, "message": "SMS sent."}),
            patch.object(app_module, "generate_sms_code", return_value="123456"),
        ):
            send_resp = self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"})
            self.assertEqual(send_resp.status_code, 200)

            login_resp = self.client.post(
                "/login",
                data={"login_type": "sms", "phone": "13800138000", "sms_code": "123456", "next": "/"},
                follow_redirects=False,
            )
        self.assertEqual(login_resp.status_code, 302)

        with self.client.session_transaction() as session:
            self.assertEqual(session.get("username"), "admin")
            self.assertEqual(session.get("display_user"), "13800138000")

        home_resp = self.client.get("/")
        self.assertEqual(home_resp.status_code, 200)
        home_html = home_resp.get_data(as_text=True)
        self.assertIn("13800138000", home_html)
        self.assertNotIn("（admin）", home_html)

        list_resp = self.client.get("/api/subscriptions")
        self.assertEqual(list_resp.status_code, 200)
        body = list_resp.get_json()
        self.assertTrue(body["ok"])

    def test_sms_login_fails_twice_then_password_only(self) -> None:
        self.write_config(
            subscriptions={},
            auth={"username": "admin", "password": "pass123"},
            sms_login=self.build_sms_login(["13800138000"]),
        )
        with (
            patch.object(app_module, "send_aliyun_sms_code", return_value={"ok": True, "message": "SMS sent."}),
            patch.object(app_module, "generate_sms_code", side_effect=["111111", "222222"]),
        ):
            self.assertEqual(self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"}).status_code, 200)
            first_login = self.client.post(
                "/login",
                data={"login_type": "sms", "phone": "13800138000", "sms_code": "000000", "next": "/"},
                follow_redirects=False,
            )
            self.assertEqual(first_login.status_code, 200)

            self.assertEqual(self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"}).status_code, 200)
            second_login = self.client.post(
                "/login",
                data={"login_type": "sms", "phone": "13800138000", "sms_code": "000000", "next": "/"},
                follow_redirects=False,
            )
            self.assertEqual(second_login.status_code, 200)
            second_html = second_login.get_data(as_text=True)
            self.assertIn("仅可使用账号密码登录", second_html)

        blocked_send = self.client.post("/api/auth/send-sms-code", json={"phone": "13800138000"})
        self.assertEqual(blocked_send.status_code, 429)
        blocked_body = blocked_send.get_json()
        self.assertFalse(blocked_body["ok"])

        password_login = self.client.post(
            "/login",
            data={"login_type": "password", "username": "admin", "password": "pass123", "next": "/"},
            follow_redirects=False,
        )
        self.assertEqual(password_login.status_code, 302)

    def test_subscriptions_page_renders(self) -> None:
        resp = self.client.get("/subscriptions")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("sub-manager-token-list", html)
        self.assertIn("sub-manager-refresh-btn", html)

    def test_index_page_renders_subscription_expiry_controls(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("sub-expiry-input", html)
        self.assertIn("订阅有效期", html)
        self.assertIn('id="sub-expiry-custom"', html)
        self.assertIn('id="sub-expiry-minute"', html)
        self.assertIn("流量监控", html)
        self.assertIn("刷新流量", html)
        self.assertIn("server-result-summary", html)
        self.assertIn("server-result-detail", html)
        self.assertNotIn("当前周期:", html)
        self.assertIn("app-icon.svg", html)

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

    def test_switch_port_auto_runs_network_check_on_success(self) -> None:
        switch_result = {
            "ok": True,
            "message": "Port switched successfully.",
            "command": "ssh hk trojan port 9527",
            "returncode": 0,
            "stdout": "",
            "stderr": "",
        }
        network_result = {
            "network_checked": True,
            "network_ok": True,
            "network_status": "reachable",
            "network_target": "hk.example.com:9527",
            "network_message": "Network is reachable.",
        }
        with (
            patch.object(app_module, "run_switch_command", return_value=switch_result) as mock_switch,
            patch.object(app_module, "run_network_check", return_value=network_result) as mock_network,
        ):
            resp = self.client.post("/api/switch-port", json={"server_id": "hk-main", "port": 9527})

        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["current_port"], 9527)
        self.assertEqual(body["quick_ports"], [9528])
        self.assertTrue(body["network_checked"])
        self.assertTrue(body["network_ok"])
        mock_switch.assert_called_once()
        mock_network.assert_called_once()

    def test_switch_port_auto_runs_network_check_on_failure(self) -> None:
        switch_result = {
            "ok": False,
            "message": "Failed to switch port.",
            "command": "ssh hk trojan port 9527",
            "returncode": 1,
            "stdout": "",
            "stderr": "boom",
        }
        network_result = {
            "network_checked": True,
            "network_ok": False,
            "network_status": "unreachable",
            "network_target": "hk.example.com:443",
            "network_message": "Connection timed out.",
        }
        with (
            patch.object(app_module, "run_switch_command", return_value=switch_result) as mock_switch,
            patch.object(app_module, "run_network_check", return_value=network_result) as mock_network,
        ):
            resp = self.client.post("/api/switch-port", json={"server_id": "hk-main", "port": 9527})

        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["current_port"], 443)
        self.assertEqual(body["quick_ports"], [444])
        self.assertTrue(body["network_checked"])
        self.assertFalse(body["network_ok"])
        mock_switch.assert_called_once()
        mock_network.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
