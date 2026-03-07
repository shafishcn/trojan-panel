from __future__ import annotations

import base64
import datetime
import hmac
import json
import os
import secrets
import shlex
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import quote

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "servers.json"

app = Flask(__name__)
app.secret_key = os.getenv("TROJAN_PANEL_SECRET_KEY", "trojan-panel-change-me")
SSH_OPTIONS_WITH_ARG = {
    "-b",
    "-c",
    "-D",
    "-E",
    "-e",
    "-F",
    "-I",
    "-i",
    "-J",
    "-L",
    "-l",
    "-m",
    "-O",
    "-o",
    "-p",
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}
SMS_CODE_TTL_SECONDS = 300
SMS_DAILY_SEND_LIMIT = 2
SMS_CODE_LENGTH = 6
SMS_LOGIN_RUNTIME: dict[str, dict[str, Any]] = {}
SMS_LOGIN_RUNTIME_LOCK = threading.Lock()


def load_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        return {"servers": [], "subscriptions": {}}
    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Invalid config: root must be an object.")
    servers = data.get("servers", [])
    if servers is None:
        servers = []
    if not isinstance(servers, list):
        raise ValueError("Invalid config: `servers` must be a list.")
    data["servers"] = servers
    data["subscriptions"] = normalize_subscriptions(data.get("subscriptions"))
    data["sms_login"] = normalize_sms_login(data.get("sms_login"))
    return data


def load_servers(config_path: Path) -> list[dict[str, Any]]:
    data = load_config(config_path)
    servers = data.get("servers", [])
    return servers


def save_config(config_path: Path, payload: dict[str, Any]) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def save_servers(config_path: Path, servers: list[dict[str, Any]]) -> None:
    try:
        payload = load_config(config_path)
    except Exception:  # noqa: BLE001
        payload = {}
    payload["servers"] = servers
    save_config(config_path, payload)


def get_config_path() -> Path:
    custom = os.getenv("TROJAN_PANEL_CONFIG")
    if custom:
        return Path(custom).expanduser().resolve()
    return DEFAULT_CONFIG_PATH


def safe_port(raw_port: Any) -> int:
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number.")
    if port < 1 or port > 65535:
        raise ValueError("Port out of range (1-65535).")
    return port


def parse_current_port(raw_port: Any) -> int | None:
    if raw_port is None:
        return None
    if isinstance(raw_port, str) and not raw_port.strip():
        return None
    return safe_port(raw_port)


def build_quick_ports(current_port: int | None) -> list[int]:
    if isinstance(current_port, int) and current_port < 65535:
        return [current_port + 1]
    return []


def normalize_token(raw_token: Any) -> str:
    if raw_token is None:
        return ""
    token = str(raw_token).strip()
    if not token:
        return ""
    if len(token) > 64:
        raise ValueError("`token` length must be <= 64.")
    for ch in token:
        if ch.isalnum() or ch in {"-", "_"}:
            continue
        raise ValueError("`token` only supports letters, numbers, '-' and '_'.")
    return token


def normalize_server_id_list(raw_ids: Any) -> list[str]:
    if not isinstance(raw_ids, list):
        raise ValueError("`server_ids` must be a non-empty array.")

    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_ids:
        server_id = str(raw).strip()
        if not server_id or server_id in seen:
            continue
        out.append(server_id)
        seen.add(server_id)
    if not out:
        raise ValueError("No valid server ids.")
    return out


def normalize_subscriptions(raw_subscriptions: Any) -> dict[str, list[str]]:
    if raw_subscriptions is None:
        return {}
    if not isinstance(raw_subscriptions, dict):
        raise ValueError("Invalid config: `subscriptions` must be an object.")

    out: dict[str, list[str]] = {}
    for raw_token, raw_value in raw_subscriptions.items():
        token = normalize_token(raw_token)
        if not token:
            continue

        value = raw_value
        if isinstance(raw_value, dict):
            value = raw_value.get("server_ids")
        if not isinstance(value, list):
            continue
        try:
            server_ids = normalize_server_id_list(value)
        except ValueError:
            continue
        out[token] = server_ids
    return out


def build_new_token(existing_tokens: set[str]) -> str:
    for _ in range(20):
        token = secrets.token_urlsafe(9).replace("=", "")
        if token and token not in existing_tokens:
            return token
    while True:
        token = f"sub-{secrets.token_hex(6)}"
        if token not in existing_tokens:
            return token


def clean_subscription_view(
    token: str, server_ids: list[str], server_name_by_id: dict[str, str], sub_url: str
) -> dict[str, Any]:
    missing_server_ids = [x for x in server_ids if x not in server_name_by_id]
    return {
        "token": token,
        "url": sub_url,
        "server_ids": server_ids,
        "server_count": len(server_ids),
        "server_names": [server_name_by_id[x] for x in server_ids if x in server_name_by_id],
        "missing_server_ids": missing_server_ids,
    }


def find_server(servers: list[dict[str, Any]], server_id: str) -> dict[str, Any]:
    for server in servers:
        if server.get("id") == server_id:
            return server
    raise ValueError("Server not found.")


def get_auth_credentials(config_path: Path) -> tuple[str, str] | None:
    try:
        config = load_config(config_path)
    except Exception:  # noqa: BLE001
        return None

    auth = config.get("auth")
    if not isinstance(auth, dict):
        return None

    raw_user = auth.get("username")
    raw_pass = auth.get("password")
    username = str(raw_user).strip() if raw_user is not None else ""
    password = str(raw_pass) if raw_pass is not None else ""
    if not username or not password:
        return None
    return username, password


def normalize_auth(raw_auth: Any) -> dict[str, str] | None:
    if raw_auth is None:
        return None
    if not isinstance(raw_auth, dict):
        raise ValueError("`auth` must be an object.")

    raw_user = raw_auth.get("username")
    raw_pass = raw_auth.get("password")
    username = str(raw_user).strip() if raw_user is not None else ""
    password = str(raw_pass) if raw_pass is not None else ""

    if not username and not password:
        return None
    if not username or not password:
        raise ValueError("`auth.username` and `auth.password` must both be set.")
    return {"username": username, "password": password}


def clean_auth_view(config: dict[str, Any]) -> dict[str, str]:
    raw_auth = config.get("auth")
    if not isinstance(raw_auth, dict):
        return {"username": "", "password": ""}
    username = str(raw_auth.get("username")).strip() if raw_auth.get("username") is not None else ""
    password = str(raw_auth.get("password")) if raw_auth.get("password") is not None else ""
    return {"username": username, "password": password}


def normalize_phone_number(raw_phone: Any) -> str:
    if raw_phone is None:
        return ""
    digits = "".join(ch for ch in str(raw_phone) if ch.isdigit())
    if digits.startswith("86") and len(digits) == 13:
        digits = digits[2:]
    return digits


def normalize_sms_login(raw_sms_login: Any) -> dict[str, Any] | None:
    if raw_sms_login is None:
        return None
    if not isinstance(raw_sms_login, dict):
        raise ValueError("`sms_login` must be an object.")

    enabled = bool(raw_sms_login.get("enabled", True))
    raw_allowed = raw_sms_login.get("allowed_phones", [])
    if raw_allowed is None:
        raw_allowed = []
    if not isinstance(raw_allowed, list):
        raise ValueError("`sms_login.allowed_phones` must be an array.")

    raw_aliyun = raw_sms_login.get("aliyun")
    if raw_aliyun is not None and not isinstance(raw_aliyun, dict):
        raise ValueError("`sms_login.aliyun` must be an object.")
    if raw_aliyun is None:
        raw_aliyun = {}

    allowed_phones: list[str] = []
    seen_phones: set[str] = set()
    for raw_phone in raw_allowed:
        phone = normalize_phone_number(raw_phone)
        if not phone:
            continue
        if phone in seen_phones:
            continue
        if len(phone) < 6 or len(phone) > 15:
            raise ValueError(f"`sms_login.allowed_phones` contains invalid phone: {raw_phone}")
        allowed_phones.append(phone)
        seen_phones.add(phone)

    aliyun: dict[str, str] = {
        "access_key_id": "",
        "access_key_secret": "",
        "sign_name": "",
        "template_code": "",
        "template_param": "{\"code\":\"##code##\",\"min\":\"5\"}",
        "endpoint": "dypnsapi.aliyuncs.com",
    }
    for key in ("access_key_id", "access_key_secret", "sign_name", "template_code", "template_param", "endpoint"):
        raw_value = raw_sms_login.get(key)
        if raw_value is None:
            raw_value = raw_aliyun.get(key)
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if value:
            aliyun[key] = value

    if enabled:
        if not allowed_phones:
            raise ValueError("`sms_login.allowed_phones` must contain at least one phone.")
        missing_fields = [key for key in ("sign_name", "template_code", "template_param") if not aliyun[key]]
        if missing_fields:
            raise ValueError(f"`sms_login.aliyun` missing fields: {', '.join(missing_fields)}")

    return {
        "enabled": enabled,
        "allowed_phones": allowed_phones,
        "daily_send_limit": SMS_DAILY_SEND_LIMIT,
        "code_ttl_seconds": SMS_CODE_TTL_SECONDS,
        "aliyun": aliyun,
    }


def get_sms_login_config(config_path: Path) -> dict[str, Any] | None:
    try:
        config = load_config(config_path)
    except Exception:  # noqa: BLE001
        return None
    sms_login = config.get("sms_login")
    if not isinstance(sms_login, dict):
        return None
    if not sms_login.get("enabled"):
        return None
    return sms_login


def mask_phone(phone: str) -> str:
    if len(phone) <= 7:
        return phone
    return f"{phone[:3]}****{phone[-4:]}"


def _get_sms_runtime_state(phone: str) -> dict[str, Any]:
    today = datetime.date.today().isoformat()
    state = SMS_LOGIN_RUNTIME.get(phone)
    if not isinstance(state, dict) or state.get("date") != today:
        state = {
            "date": today,
            "send_count": 0,
            "failed_count": 0,
            "code": "",
            "expires_at": 0.0,
        }
        SMS_LOGIN_RUNTIME[phone] = state
    return state


def generate_sms_code() -> str:
    return f"{secrets.randbelow(10 ** SMS_CODE_LENGTH):0{SMS_CODE_LENGTH}d}"


def render_sms_template_param(raw_template_param: str, code: str) -> str:
    if "##code##" in raw_template_param:
        return raw_template_param.replace("##code##", code)
    try:
        data = json.loads(raw_template_param)
    except json.JSONDecodeError:
        return raw_template_param
    if not isinstance(data, dict):
        return raw_template_param
    if "code" not in data:
        data["code"] = code
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False)


def map_aliyun_sms_error(message: str, recommend: str = "") -> str:
    lower_message = message.lower()
    if "timed out" in lower_message or "timeout" in lower_message:
        return "阿里云短信服务请求超时，请稍后重试。"
    if "connection refused" in lower_message or "name or service not known" in lower_message:
        return "阿里云短信服务连接失败，请检查网络或 endpoint 配置。"
    if (
        "forbidden.nopermission" in lower_message
        or "you are not authorized to perform this action" in lower_message
        or "code: 403" in lower_message
        or "not authorized" in lower_message
    ):
        return "阿里云账号无短信发送权限（Dypnsapi）。请为该 AK 开通并授权短信相关权限。"
    if recommend:
        return f"阿里云短信请求失败：{message}（{recommend}）"
    return f"Aliyun SMS request failed: {message}"


def send_aliyun_sms_code(phone: str, code: str, sms_login: dict[str, Any]) -> dict[str, Any]:
    try:
        from alibabacloud_dypnsapi20170525 import models as dypnsapi_20170525_models
        from alibabacloud_dypnsapi20170525.client import Client as Dypnsapi20170525Client
        from alibabacloud_tea_openapi import models as open_api_models
        from alibabacloud_tea_util import models as util_models
    except ModuleNotFoundError:
        return {"ok": False, "message": "缺少阿里云短信依赖，请先安装 requirements.txt。"}

    aliyun = sms_login.get("aliyun", {})
    sign_name = str(aliyun.get("sign_name", "")).strip()
    template_code = str(aliyun.get("template_code", "")).strip()
    raw_template_param = str(aliyun.get("template_param", "{\"code\":\"##code##\",\"min\":\"5\"}")).strip()
    endpoint = str(aliyun.get("endpoint", "dypnsapi.aliyuncs.com")).strip() or "dypnsapi.aliyuncs.com"
    endpoint = endpoint.removeprefix("https://").removeprefix("http://").strip("/")
    template_param = render_sms_template_param(raw_template_param, code)
    access_key_id = str(aliyun.get("access_key_id", "")).strip() or str(os.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID", "")).strip()
    access_key_secret = str(aliyun.get("access_key_secret", "")).strip() or str(
        os.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
    ).strip()
    if not access_key_id or not access_key_secret:
        return {
            "ok": False,
            "message": "未配置阿里云 AK/SK，请在 servers.json 的 sms_login 中设置 access_key_id/access_key_secret，或配置环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID/ALIBABA_CLOUD_ACCESS_KEY_SECRET。",
        }

    config = open_api_models.Config(
        access_key_id=access_key_id,
        access_key_secret=access_key_secret,
    )
    config.endpoint = endpoint
    client = Dypnsapi20170525Client(config)
    send_sms_verify_code_request = dypnsapi_20170525_models.SendSmsVerifyCodeRequest(
        sign_name=sign_name,
        template_code=template_code,
        phone_number=phone,
        template_param=template_param,
    )
    runtime = util_models.RuntimeOptions(
        autoretry=True,
        max_attempts=2,
        backoff_policy="no",
        connect_timeout=7000,
        read_timeout=15000,
    )
    try:
        resp = client.send_sms_verify_code_with_options(send_sms_verify_code_request, runtime)
    except Exception as exc:  # noqa: BLE001
        message = str(getattr(exc, "message", str(exc)))
        recommend = ""
        data = getattr(exc, "data", None)
        if isinstance(data, dict):
            recommend = str(data.get("Recommend", "")).strip()
        return {"ok": False, "message": map_aliyun_sms_error(message, recommend)}

    body = getattr(resp, "body", None)
    provider_code = str(getattr(body, "code", "") or getattr(body, "Code", "")).strip()
    provider_message = str(getattr(body, "message", "") or getattr(body, "Message", "")).strip()
    request_id = str(getattr(body, "request_id", "") or getattr(body, "RequestId", "")).strip()
    success_value = getattr(body, "success", None)
    provider_success = bool(success_value) if isinstance(success_value, bool) else False
    if provider_code.upper() == "OK" or provider_success:
        return {"ok": True, "message": "SMS sent.", "request_id": request_id}

    message = provider_message or provider_code or "Unknown provider error."
    return {"ok": False, "message": map_aliyun_sms_error(message), "request_id": request_id}


def login_with_password(username: str, password: str, creds: tuple[str, str]) -> bool:
    user_ok = hmac.compare_digest(username, creds[0])
    pass_ok = hmac.compare_digest(password, creds[1])
    return bool(user_ok and pass_ok)


def login_with_sms(phone: str, code: str, sms_login: dict[str, Any]) -> tuple[bool, str]:
    allowed_phones = {str(x) for x in sms_login.get("allowed_phones", []) if str(x)}
    if phone not in allowed_phones:
        return False, "该手机号未被授权登录。"

    if len(code) != SMS_CODE_LENGTH or not code.isdigit():
        return False, "验证码格式错误。"

    limit = int(sms_login.get("daily_send_limit", SMS_DAILY_SEND_LIMIT))
    now_ts = time.time()
    with SMS_LOGIN_RUNTIME_LOCK:
        state = _get_sms_runtime_state(phone)
        if int(state.get("failed_count", 0)) >= limit:
            return False, "今日验证码已全部验证失败，仅可使用账号密码登录。"
        current_code = str(state.get("code", ""))
        if not current_code:
            return False, "请先发送验证码。"
        expires_at = float(state.get("expires_at", 0))
        if now_ts > expires_at:
            state["code"] = ""
            state["expires_at"] = 0.0
            return False, "验证码已过期，请重新发送。"
        if hmac.compare_digest(code, current_code):
            state["code"] = ""
            state["expires_at"] = 0.0
            state["failed_count"] = 0
            return True, ""

        state["code"] = ""
        state["expires_at"] = 0.0
        state["failed_count"] = int(state.get("failed_count", 0)) + 1
        if int(state.get("failed_count", 0)) >= limit:
            return False, "今日验证码已全部验证失败，仅可使用账号密码登录。"
        return False, "验证码错误。"


def select_servers_by_ids(servers: list[dict[str, Any]], server_ids: list[str]) -> list[dict[str, Any]]:
    wanted = {x for x in server_ids if x}
    selected = [s for s in servers if s.get("id") in wanted]
    return selected


def build_trojan_link(server: dict[str, Any]) -> str:
    server_id = str(server.get("id", "")).strip() or "unknown"
    server_name = str(server.get("name", "")).strip() or server_id
    raw_addr = server.get("addr")
    addr = str(raw_addr).strip() if raw_addr is not None else ""
    if not addr:
        raise ValueError(f"Server `{server_id}` missing `addr`.")

    try:
        port = parse_current_port(server.get("current_port"))
    except ValueError:
        port = None
    if port is None:
        raise ValueError(f"Server `{server_id}` missing valid `current_port`.")

    raw_password = server.get("trojan_password")
    password = str(raw_password) if raw_password is not None else ""
    if not password:
        raise ValueError(f"Server `{server_id}` missing `trojan_password`.")

    userinfo = quote(password, safe="")
    fragment = quote(server_name, safe="")
    return f"trojan://{userinfo}@{addr}:{port}?security=tls&headerType=none&type=tcp#{fragment}"


def build_subscription_links(selected: list[dict[str, Any]]) -> list[str]:
    links: list[str] = []
    for server in selected:
        links.append(build_trojan_link(server))
    return links


def is_safe_next(next_url: str) -> bool:
    if not next_url:
        return False
    if not next_url.startswith("/"):
        return False
    if next_url.startswith("//"):
        return False
    return True


def get_session_display_user() -> str:
    display_user = str(session.get("display_user", "")).strip()
    if display_user:
        return display_user
    return str(session.get("username", "")).strip()


@app.before_request
def require_login():
    endpoint = request.endpoint or ""
    if endpoint in {"login", "logout", "send_sms_code", "static", "subscription_content"}:
        return None

    creds = get_auth_credentials(get_config_path())
    if creds is None:
        return None

    expected_username = creds[0]
    if session.get("logged_in") and session.get("username") == expected_username:
        return None

    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "message": "Unauthorized."}), 401

    next_url = request.path
    if request.query_string:
        next_url += f"?{request.query_string.decode()}"
    return redirect(url_for("login", next=next_url))


def normalize_servers(raw_servers: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_servers, list):
        raise ValueError("`servers` must be a list.")

    seen_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for idx, raw in enumerate(raw_servers, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Server #{idx} must be an object.")

        raw_server_id = raw.get("id")
        server_id = str(raw_server_id).strip() if raw_server_id is not None else ""
        if not server_id:
            raise ValueError(f"Server #{idx}: `id` is required.")
        if server_id in seen_ids:
            raise ValueError(f"Duplicate server id: `{server_id}`.")
        seen_ids.add(server_id)

        raw_name = raw.get("name")
        raw_description = raw.get("description")
        raw_command_template = raw.get("command_template")
        raw_status_template = raw.get("status_command_template")
        raw_ssh_target = raw.get("ssh_target")
        raw_current_port = raw.get("current_port")
        raw_addr = raw.get("addr")
        raw_trojan_password = raw.get("trojan_password")

        name = str(raw_name).strip() if raw_name is not None else server_id
        if not name:
            name = server_id
        description = str(raw_description).strip() if raw_description is not None else ""
        command_template = str(raw_command_template).strip() if raw_command_template is not None else ""
        status_template = str(raw_status_template).strip() if raw_status_template is not None else ""
        ssh_target = str(raw_ssh_target).strip() if raw_ssh_target is not None else ""
        addr = str(raw_addr).strip() if raw_addr is not None else ""
        trojan_password = str(raw_trojan_password) if raw_trojan_password is not None else ""
        if any(ch.isspace() for ch in trojan_password):
            raise ValueError(f"Server `{server_id}`: `trojan_password` must not contain whitespace.")
        try:
            current_port = parse_current_port(raw_current_port)
        except ValueError:
            raise ValueError(f"Server `{server_id}`: `current_port` out of range (1-65535).")
        if command_template:
            if "$1" not in command_template:
                raise ValueError(f"Server `{server_id}`: `command_template` must contain `$1`.")
        elif not ssh_target:
            raise ValueError(f"Server `{server_id}` must provide `command_template` or `ssh_target`.")

        item: dict[str, Any] = {
            "id": server_id,
            "name": name,
            "description": description,
        }
        if command_template:
            item["command_template"] = command_template
        else:
            item["ssh_target"] = ssh_target
            ssh_options = raw.get("ssh_options", [])
            if ssh_options is None:
                ssh_options = []
            if not isinstance(ssh_options, list):
                raise ValueError(f"Server `{server_id}`: `ssh_options` must be an array.")
            item["ssh_options"] = [str(x) for x in ssh_options if str(x).strip()]
        if status_template:
            item["status_command_template"] = status_template
        if current_port is not None:
            item["current_port"] = current_port
        if addr:
            item["addr"] = addr
        if trojan_password:
            item["trojan_password"] = trojan_password

        normalized.append(item)
    return normalized


def clean_server_view(item: dict[str, Any]) -> dict[str, Any]:
    raw_id = item.get("id")
    raw_name = item.get("name")
    raw_target = item.get("ssh_target")
    raw_template = item.get("command_template")
    raw_status_template = item.get("status_command_template")
    raw_desc = item.get("description")
    raw_current_port = item.get("current_port")
    raw_addr = item.get("addr")
    raw_trojan_password = item.get("trojan_password")

    server_id = str(raw_id).strip() if raw_id is not None else ""
    name = str(raw_name).strip() if raw_name is not None else ""
    ssh_target = str(raw_target).strip() if raw_target is not None else ""
    command_template = str(raw_template).strip() if raw_template is not None else ""
    status_template = str(raw_status_template).strip() if raw_status_template is not None else ""
    description = str(raw_desc).strip() if raw_desc is not None else ""
    addr = str(raw_addr).strip() if raw_addr is not None else ""
    trojan_password = str(raw_trojan_password) if raw_trojan_password is not None else ""
    try:
        current_port = parse_current_port(raw_current_port) if raw_current_port is not None else None
    except ValueError:
        current_port = None
    return {
        "id": server_id,
        "name": name or server_id or "Unnamed",
        "ssh_target": ssh_target,
        "command_template": command_template,
        "status_command_template": status_template,
        "description": description,
        "current_port": current_port,
        "quick_ports": build_quick_ports(current_port),
        "addr": addr,
        "trojan_password": trojan_password,
    }


def build_ssh_command(server: dict[str, Any], port: int) -> list[str]:
    template = server.get("command_template")
    if template is not None:
        if not isinstance(template, str) or not template.strip():
            raise ValueError("`command_template` must be a non-empty string.")
        if "$1" not in template:
            raise ValueError("`command_template` must contain `$1` placeholder.")
        return shlex.split(template.replace("$1", str(port)))

    target = server.get("ssh_target")
    if not target:
        raise ValueError("`ssh_target` is required when `command_template` is absent.")

    ssh_options = server.get("ssh_options", [])
    if ssh_options is None:
        ssh_options = []
    if not isinstance(ssh_options, list):
        raise ValueError("`ssh_options` must be an array.")

    remote_cmd = f"trojan port {port}"
    return ["ssh", *ssh_options, target, remote_cmd]


def find_ssh_target_index(parts: list[str]) -> int:
    idx = 1
    while idx < len(parts):
        token = parts[idx]
        if token == "--":
            idx += 1
            break
        if token.startswith("-") and token != "-":
            if token in SSH_OPTIONS_WITH_ARG:
                idx += 2
            elif len(token) > 2 and token[:2] in SSH_OPTIONS_WITH_ARG:
                idx += 1
            else:
                idx += 1
            continue
        return idx

    if idx < len(parts):
        return idx
    raise ValueError("Cannot parse ssh target from command.")


def run_shell_command(cmd: list[str], success_message: str, failed_message: str) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "message": "SSH command timed out.",
            "command": shlex.join(cmd),
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "message": f"Run failed: {exc}",
            "command": shlex.join(cmd),
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }

    output = (proc.stdout or "").strip()
    errors = (proc.stderr or "").strip()
    ok = proc.returncode == 0
    return {
        "ok": ok,
        "message": success_message if ok else failed_message,
        "command": shlex.join(cmd),
        "returncode": proc.returncode,
        "stdout": output,
        "stderr": errors,
    }


def run_switch_command(server: dict[str, Any], port: int) -> dict[str, Any]:
    try:
        cmd = build_ssh_command(server, port)
    except ValueError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "command": "",
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }

    return run_shell_command(cmd, "Port switched successfully.", "Failed to switch port.")


def derive_status_command_from_port_template(command_template: str) -> list[str]:
    parts = shlex.split(command_template)
    if not parts or parts[0] != "ssh":
        raise ValueError("Cannot infer status command from `command_template`; please set `status_command_template`.")
    target_idx = find_ssh_target_index(parts)
    return [*parts[: target_idx + 1], "trojan", "status"]


def build_status_command(server: dict[str, Any]) -> list[str]:
    custom_template = server.get("status_command_template")
    if custom_template is not None:
        if not isinstance(custom_template, str) or not custom_template.strip():
            raise ValueError("`status_command_template` must be a non-empty string.")
        return shlex.split(custom_template)

    command_template = server.get("command_template")
    if isinstance(command_template, str) and command_template.strip():
        return derive_status_command_from_port_template(command_template)

    target = server.get("ssh_target")
    if not target:
        raise ValueError("`ssh_target` is required when command templates are absent.")

    ssh_options = server.get("ssh_options", [])
    if ssh_options is None:
        ssh_options = []
    if not isinstance(ssh_options, list):
        raise ValueError("`ssh_options` must be an array.")

    return ["ssh", *ssh_options, target, "trojan status"]


def parse_service_status(stdout: str, stderr: str) -> dict[str, Any]:
    text = "\n".join([stdout, stderr]).strip()
    active_line = ""
    for line in text.splitlines():
        if line.strip().startswith("Active:"):
            active_line = line.strip()
            break

    probe = active_line.lower() if active_line else text.lower()
    if "active (running)" in probe:
        return {"service_ok": True, "service_status": "running", "service_active_line": active_line}
    if "inactive" in probe or "failed" in probe or "dead" in probe:
        return {"service_ok": False, "service_status": "not-running", "service_active_line": active_line}
    if "running" in probe and "not running" not in probe:
        return {"service_ok": True, "service_status": "running", "service_active_line": active_line}
    return {"service_ok": False, "service_status": "unknown", "service_active_line": active_line}


def run_network_check(server: dict[str, Any]) -> dict[str, Any]:
    raw_addr = server.get("addr")
    addr = str(raw_addr).strip() if raw_addr is not None else ""
    try:
        current_port = parse_current_port(server.get("current_port"))
    except ValueError:
        current_port = None

    if not addr:
        return {
            "network_checked": False,
            "network_ok": False,
            "network_status": "unknown",
            "network_target": "",
            "network_message": "`addr` is not configured.",
        }
    if current_port is None:
        return {
            "network_checked": False,
            "network_ok": False,
            "network_status": "unknown",
            "network_target": "",
            "network_message": "`current_port` is not configured.",
        }

    target = f"{addr}:{current_port}"
    try:
        with socket.create_connection((addr, current_port), timeout=4):
            pass
        return {
            "network_checked": True,
            "network_ok": True,
            "network_status": "reachable",
            "network_target": target,
            "network_message": "Network is reachable.",
        }
    except socket.timeout:
        return {
            "network_checked": True,
            "network_ok": False,
            "network_status": "unreachable",
            "network_target": target,
            "network_message": "Connection timed out.",
        }
    except OSError as exc:
        return {
            "network_checked": True,
            "network_ok": False,
            "network_status": "unreachable",
            "network_target": target,
            "network_message": str(exc),
        }


def run_status_command(server: dict[str, Any]) -> dict[str, Any]:
    try:
        cmd = build_status_command(server)
    except ValueError as exc:
        try:
            current_port = parse_current_port(server.get("current_port"))
        except ValueError:
            current_port = None
        return {
            "ok": False,
            "exec_ok": False,
            "service_ok": False,
            "service_status": "unknown",
            "service_active_line": "",
            "current_port": current_port,
            "quick_ports": build_quick_ports(current_port),
            "port_message": "",
            **run_network_check(server),
            "message": str(exc),
            "command": "",
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }

    result = run_shell_command(cmd, "Status fetched.", "Failed to fetch status.")
    result["exec_ok"] = result["ok"]
    if not result["exec_ok"]:
        result["service_ok"] = False
        result["service_status"] = "unknown"
        result["service_active_line"] = ""
        try:
            current_port = parse_current_port(server.get("current_port"))
        except ValueError:
            current_port = None
        result["current_port"] = current_port
        result["quick_ports"] = build_quick_ports(current_port)
        result["port_message"] = ""
        result.update(run_network_check(server))
        return result

    parsed = parse_service_status(result.get("stdout", ""), result.get("stderr", ""))
    result["service_ok"] = parsed["service_ok"]
    result["service_status"] = parsed["service_status"]
    result["service_active_line"] = parsed["service_active_line"]
    try:
        current_port = parse_current_port(server.get("current_port"))
    except ValueError:
        current_port = None
    result["current_port"] = current_port
    result["quick_ports"] = build_quick_ports(current_port)
    result["port_message"] = ""
    result.update(run_network_check(server))
    result["ok"] = bool(parsed["service_ok"])
    result["message"] = "Trojan service is running normally." if result["ok"] else "Trojan service is NOT running normally."
    return result


@app.get("/")
def index():
    config_path = get_config_path()
    error = None
    servers: list[dict[str, Any]] = []
    auth_enabled = False
    current_user = ""
    try:
        config = load_config(config_path)
        servers = config.get("servers", [])
        auth_enabled = get_auth_credentials(config_path) is not None
        current_user = get_session_display_user()
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    clean_servers = [clean_server_view(item) for item in servers if item.get("id")]
    return render_template(
        "index.html",
        servers=clean_servers,
        config_path=str(config_path),
        error=error,
        auth_enabled=auth_enabled,
        current_user=current_user,
    )


@app.get("/servers")
def servers_page():
    config_path = get_config_path()
    error = None
    servers: list[dict[str, Any]] = []
    auth = {"username": "", "password": ""}
    auth_enabled = False
    current_user = ""
    try:
        config = load_config(config_path)
        servers = config.get("servers", [])
        auth = clean_auth_view(config)
        auth_enabled = get_auth_credentials(config_path) is not None
        current_user = get_session_display_user()
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    clean_servers = [clean_server_view(item) for item in servers if item.get("id")]
    return render_template(
        "servers.html",
        servers=clean_servers,
        auth=auth,
        config_path=str(config_path),
        error=error,
        auth_enabled=auth_enabled,
        current_user=current_user,
    )


@app.get("/subscriptions")
def subscriptions_page():
    config_path = get_config_path()
    error = None
    auth_enabled = False
    current_user = ""
    try:
        _ = load_config(config_path)
        auth_enabled = get_auth_credentials(config_path) is not None
        current_user = get_session_display_user()
    except Exception as exc:  # noqa: BLE001
        error = str(exc)

    return render_template(
        "subscriptions.html",
        config_path=str(config_path),
        error=error,
        auth_enabled=auth_enabled,
        current_user=current_user,
    )


@app.post("/api/auth/send-sms-code")
def send_sms_code():
    config_path = get_config_path()
    creds = get_auth_credentials(config_path)
    if creds is None:
        return jsonify({"ok": False, "message": "未启用登录认证。"}), 400

    sms_login = get_sms_login_config(config_path)
    if sms_login is None:
        return jsonify({"ok": False, "message": "未启用手机号登录。"}), 400

    payload = request.get_json(silent=True) or {}
    phone = normalize_phone_number(payload.get("phone"))
    if not phone:
        return jsonify({"ok": False, "message": "手机号不能为空。"}), 400

    allowed_phones = {str(x) for x in sms_login.get("allowed_phones", []) if str(x)}
    if phone not in allowed_phones:
        return jsonify({"ok": False, "message": "该手机号未被授权登录。"}), 403

    limit = int(sms_login.get("daily_send_limit", SMS_DAILY_SEND_LIMIT))
    ttl_seconds = int(sms_login.get("code_ttl_seconds", SMS_CODE_TTL_SECONDS))
    with SMS_LOGIN_RUNTIME_LOCK:
        state = _get_sms_runtime_state(phone)
        send_count = int(state.get("send_count", 0))
        failed_count = int(state.get("failed_count", 0))
        if send_count >= limit or failed_count >= limit:
            return jsonify({"ok": False, "message": "今日验证码发送次数已用尽，请使用账号密码登录。", "remaining": 0}), 429

    code = generate_sms_code()
    send_result = send_aliyun_sms_code(phone, code, sms_login)
    if not send_result.get("ok"):
        return jsonify({"ok": False, "message": send_result.get("message", "短信发送失败。")}), 502

    now_ts = time.time()
    with SMS_LOGIN_RUNTIME_LOCK:
        state = _get_sms_runtime_state(phone)
        send_count = int(state.get("send_count", 0))
        failed_count = int(state.get("failed_count", 0))
        if send_count >= limit or failed_count >= limit:
            return jsonify({"ok": False, "message": "今日验证码发送次数已用尽，请使用账号密码登录。", "remaining": 0}), 429
        state["send_count"] = send_count + 1
        state["code"] = code
        state["expires_at"] = now_ts + ttl_seconds
        remaining = max(0, limit - int(state["send_count"]))

    return jsonify(
        {
            "ok": True,
            "message": f"验证码已发送到 {mask_phone(phone)}。",
            "remaining": remaining,
            "ttl_seconds": ttl_seconds,
            "daily_limit": limit,
        }
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    config_path = get_config_path()
    creds = get_auth_credentials(config_path)
    if creds is None:
        return redirect(url_for("index"))
    sms_login = get_sms_login_config(config_path)
    sms_login_enabled = sms_login is not None

    default_next = url_for("index")
    next_url = request.values.get("next", default_next)
    if not is_safe_next(next_url):
        next_url = default_next

    if session.get("logged_in") and session.get("username") == creds[0]:
        return redirect(next_url)

    error = None
    requested_mode = str(request.args.get("mode", "")).strip()
    current_login_type = "sms" if sms_login_enabled and requested_mode == "sms" else "password"
    if request.method == "POST":
        login_type = str(request.form.get("login_type", "password")).strip()
        current_login_type = "sms" if login_type == "sms" and sms_login_enabled else "password"
        if login_type == "sms":
            if not sms_login_enabled:
                error = "未启用手机号登录。"
            else:
                phone = normalize_phone_number(request.form.get("phone", ""))
                sms_code = str(request.form.get("sms_code", "")).strip()
                ok, message = login_with_sms(phone, sms_code, sms_login)
                if ok:
                    session.clear()
                    session["logged_in"] = True
                    session["username"] = creds[0]
                    session["display_user"] = phone
                    return redirect(next_url)
                error = message
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if login_with_password(username, password, creds):
                session.clear()
                session["logged_in"] = True
                session["username"] = creds[0]
                session["display_user"] = creds[0]
                return redirect(next_url)
            error = "用户名或密码错误。"

    return render_template(
        "login.html",
        error=error,
        next_url=next_url,
        sms_login_enabled=sms_login_enabled,
        login_type=current_login_type,
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/api/switch-port")
def switch_port():
    payload = request.get_json(silent=True) or {}
    server_id = payload.get("server_id")
    raw_port = payload.get("port")

    if not server_id:
        return jsonify({"ok": False, "message": "Missing `server_id`."}), 400

    config_path = get_config_path()
    try:
        port = safe_port(raw_port)
        servers = load_servers(config_path)
        server = find_server(servers, server_id)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    result = run_switch_command(server, port)
    if result.get("ok"):
        server["current_port"] = port
        try:
            save_servers(config_path, servers)
        except Exception as exc:  # noqa: BLE001
            result["ok"] = False
            result["message"] = f"Port switched, but failed to save current_port: {exc}"
            result["current_port"] = port
            result["quick_ports"] = build_quick_ports(port)
            result.update(run_network_check(server))
            return jsonify(result), 500
        result["current_port"] = port
        result["quick_ports"] = build_quick_ports(port)
    else:
        try:
            current_port = parse_current_port(server.get("current_port"))
        except ValueError:
            current_port = None
        result["current_port"] = current_port
        result["quick_ports"] = build_quick_ports(current_port)

    # Auto-run network check after switching port (or attempted switch).
    result.update(run_network_check(server))

    if result["ok"]:
        code = 200
    elif result.get("command") == "":
        code = 400
    elif result.get("message") == "SSH command timed out.":
        code = 504
    else:
        code = 500
    return jsonify(result), code


@app.post("/api/trojan-status")
def trojan_status():
    payload = request.get_json(silent=True) or {}
    server_id = payload.get("server_id")
    if not server_id:
        return jsonify({"ok": False, "message": "Missing `server_id`."}), 400

    try:
        servers = load_servers(get_config_path())
        server = find_server(servers, server_id)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    result = run_status_command(server)
    if result.get("exec_ok") is False:
        if result.get("command") == "":
            code = 400
        elif result.get("message") == "SSH command timed out.":
            code = 504
        else:
            code = 500
    else:
        code = 200
    return jsonify(result), code


@app.post("/api/network-check")
def network_check():
    payload = request.get_json(silent=True) or {}
    server_id = payload.get("server_id")
    if not server_id:
        return jsonify({"ok": False, "message": "Missing `server_id`."}), 400

    try:
        servers = load_servers(get_config_path())
        server = find_server(servers, server_id)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    data = run_network_check(server)
    try:
        current_port = parse_current_port(server.get("current_port"))
    except ValueError:
        current_port = None
    data["current_port"] = current_port
    data["quick_ports"] = build_quick_ports(current_port)
    data["server_id"] = server.get("id", "")
    data["message"] = "Network is reachable." if data.get("network_ok") else data.get("network_message", "Network check failed.")
    data["ok"] = bool(data.get("network_ok"))
    return jsonify(data), 200


@app.post("/api/subscription-link")
def subscription_link():
    payload = request.get_json(silent=True) or {}
    raw_ids = payload.get("server_ids")
    raw_token = payload.get("token")
    try:
        server_ids = normalize_server_id_list(raw_ids)
        custom_token = normalize_token(raw_token)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400

    config_path = get_config_path()
    try:
        config = load_config(config_path)
        servers = config.get("servers", [])
        subscriptions = normalize_subscriptions(config.get("subscriptions"))
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    selected = select_servers_by_ids(servers, server_ids)
    if len(selected) != len(server_ids):
        missing = [x for x in server_ids if x not in {str(s.get("id", "")) for s in selected}]
        return jsonify({"ok": False, "message": f"Server not found: {', '.join(missing)}"}), 400

    try:
        links = build_subscription_links(selected)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400

    existing_tokens = set(subscriptions.keys())
    token = custom_token or build_new_token(existing_tokens)
    overwritten = token in subscriptions
    subscriptions[token] = server_ids
    config["subscriptions"] = subscriptions
    try:
        save_config(config_path, config)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Save failed: {exc}"}), 500

    sub_url = request.host_url.rstrip("/") + url_for("subscription_content", token=token)
    message = "Subscription URL generated."
    if overwritten:
        message = "Token existed. Replaced with latest server selection."
    return jsonify(
        {
            "ok": True,
            "token": token,
            "overwritten": overwritten,
            "url": sub_url,
            "server_count": len(selected),
            "server_ids": server_ids,
            "links": links,
            "message": message,
        }
    )


@app.get("/api/subscriptions")
def list_subscriptions():
    try:
        config = load_config(get_config_path())
        servers = config.get("servers", [])
        subscriptions = normalize_subscriptions(config.get("subscriptions"))
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    server_name_by_id: dict[str, str] = {}
    for item in servers:
        server_id = str(item.get("id", "")).strip()
        if not server_id:
            continue
        name = str(item.get("name", "")).strip() or server_id
        server_name_by_id[server_id] = name

    out: list[dict[str, Any]] = []
    for token in sorted(subscriptions.keys()):
        server_ids = subscriptions[token]
        sub_url = request.host_url.rstrip("/") + url_for("subscription_content", token=token)
        out.append(clean_subscription_view(token, server_ids, server_name_by_id, sub_url))

    return jsonify({"ok": True, "subscriptions": out, "count": len(out)})


@app.delete("/api/subscriptions/<token>")
def delete_subscription(token: str):
    try:
        clean_token = normalize_token(token)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    if not clean_token:
        return jsonify({"ok": False, "message": "Token must not be empty."}), 400

    config_path = get_config_path()
    try:
        config = load_config(config_path)
        subscriptions = normalize_subscriptions(config.get("subscriptions"))
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    server_ids = subscriptions.get(clean_token)
    if server_ids is None:
        return jsonify({"ok": False, "message": "Subscription token not found."}), 404

    subscriptions.pop(clean_token, None)
    config["subscriptions"] = subscriptions
    try:
        save_config(config_path, config)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Save failed: {exc}"}), 500

    return jsonify(
        {
            "ok": True,
            "message": "Subscription token deleted.",
            "token": clean_token,
            "server_ids": server_ids,
            "server_count": len(server_ids),
        }
    )


@app.get("/sub/<token>")
def subscription_content(token: str):
    try:
        clean_token = normalize_token(token)
    except ValueError as exc:
        return Response(f"invalid subscription token: {exc}\n", mimetype="text/plain"), 400
    if not clean_token:
        return Response("invalid subscription token: empty token\n", mimetype="text/plain"), 400

    try:
        config = load_config(get_config_path())
        servers = config.get("servers", [])
        subscriptions = normalize_subscriptions(config.get("subscriptions"))
    except Exception as exc:  # noqa: BLE001
        return Response(f"config error: {exc}\n", mimetype="text/plain"), 500

    server_ids = subscriptions.get(clean_token)
    if not server_ids:
        return Response("subscription token not found\n", mimetype="text/plain"), 404

    selected = select_servers_by_ids(servers, server_ids)
    if len(selected) != len(server_ids):
        existing = {str(s.get("id", "")) for s in selected}
        missing = [x for x in server_ids if x not in existing]
        return Response(f"server not found: {', '.join(missing)}\n", mimetype="text/plain"), 400

    try:
        links = build_subscription_links(selected)
    except ValueError as exc:
        return Response(f"build link failed: {exc}\n", mimetype="text/plain"), 400

    plain = "\n".join(links)
    encoded = base64.b64encode(plain.encode("utf-8")).decode("utf-8")
    return Response(encoded + "\n", mimetype="text/plain")


@app.get("/api/servers")
def get_servers():
    try:
        config = load_config(get_config_path())
        servers = config.get("servers", [])
        auth = clean_auth_view(config)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    clean_servers = [clean_server_view(item) for item in servers if item.get("id")]
    return jsonify({"ok": True, "servers": clean_servers, "auth": auth})


@app.put("/api/servers")
def put_servers():
    payload = request.get_json(silent=True) or {}
    raw_servers = payload.get("servers")
    raw_auth = payload.get("auth")
    config_path = get_config_path()
    try:
        config = load_config(config_path)
        normalized = normalize_servers(raw_servers)
        config["servers"] = normalized
        if "auth" in payload:
            auth = normalize_auth(raw_auth)
            if auth is None:
                config.pop("auth", None)
            else:
                config["auth"] = auth
        save_config(config_path, config)
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Save failed: {exc}"}), 500

    clean_servers = [clean_server_view(item) for item in normalized]
    return jsonify({"ok": True, "message": "Servers saved.", "servers": clean_servers, "auth": clean_auth_view(config)})


@app.post("/api/trojan-status-all")
def trojan_status_all():
    payload = request.get_json(silent=True) or {}
    selected_ids = payload.get("server_ids")

    try:
        servers = load_servers(get_config_path())
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "message": f"Config error: {exc}"}), 500

    if isinstance(selected_ids, list) and selected_ids:
        selected = []
        wanted_ids = {str(x) for x in selected_ids}
        for s in servers:
            server_id = s.get("id")
            if server_id in wanted_ids:
                selected.append(s)
    else:
        selected = [s for s in servers if s.get("id")]

    if not selected:
        return jsonify({"ok": False, "message": "No servers selected."}), 400

    results: list[dict[str, Any]] = []
    worker_count = min(8, len(selected))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(run_status_command, server): server for server in selected}
        for future in as_completed(futures):
            server = futures[future]
            server_id = server.get("id", "")
            server_name = server.get("name", server_id)
            try:
                item = future.result()
            except Exception as exc:  # noqa: BLE001
                item = {
                    "ok": False,
                    "exec_ok": False,
                    "service_ok": False,
                    "service_status": "unknown",
                    "service_active_line": "",
                    "message": f"Unexpected error: {exc}",
                    "command": "",
                    "returncode": None,
                    "stdout": "",
                    "stderr": "",
                }

            item["server_id"] = server_id
            item["server_name"] = server_name
            results.append(item)

    ok_count = sum(1 for x in results if x.get("ok"))
    summary = f"{ok_count}/{len(results)} servers are running normally."
    http_code = 200 if ok_count == len(results) else 207
    return jsonify({"ok": ok_count == len(results), "summary": summary, "results": results}), http_code


if __name__ == "__main__":
    host = os.getenv("TROJAN_PANEL_HOST", "127.0.0.1")
    port = int(os.getenv("TROJAN_PANEL_PORT", "8000"))
    debug = os.getenv("TROJAN_PANEL_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
