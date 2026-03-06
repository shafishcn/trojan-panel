from __future__ import annotations

import hmac
import json
import os
import shlex
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, session, url_for


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


def load_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        return {"servers": []}
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


def is_safe_next(next_url: str) -> bool:
    if not next_url:
        return False
    if not next_url.startswith("/"):
        return False
    if next_url.startswith("//"):
        return False
    return True


@app.before_request
def require_login():
    endpoint = request.endpoint or ""
    if endpoint in {"login", "logout", "static"}:
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

        name = str(raw_name).strip() if raw_name is not None else server_id
        if not name:
            name = server_id
        description = str(raw_description).strip() if raw_description is not None else ""
        command_template = str(raw_command_template).strip() if raw_command_template is not None else ""
        status_template = str(raw_status_template).strip() if raw_status_template is not None else ""
        ssh_target = str(raw_ssh_target).strip() if raw_ssh_target is not None else ""
        addr = str(raw_addr).strip() if raw_addr is not None else ""
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

    server_id = str(raw_id).strip() if raw_id is not None else ""
    name = str(raw_name).strip() if raw_name is not None else ""
    ssh_target = str(raw_target).strip() if raw_target is not None else ""
    command_template = str(raw_template).strip() if raw_template is not None else ""
    status_template = str(raw_status_template).strip() if raw_status_template is not None else ""
    description = str(raw_desc).strip() if raw_desc is not None else ""
    addr = str(raw_addr).strip() if raw_addr is not None else ""
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
        current_user = str(session.get("username", "")).strip()
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
        current_user = str(session.get("username", "")).strip()
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


@app.route("/login", methods=["GET", "POST"])
def login():
    creds = get_auth_credentials(get_config_path())
    if creds is None:
        return redirect(url_for("index"))

    default_next = url_for("index")
    next_url = request.values.get("next", default_next)
    if not is_safe_next(next_url):
        next_url = default_next

    if session.get("logged_in") and session.get("username") == creds[0]:
        return redirect(next_url)

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user_ok = hmac.compare_digest(username, creds[0])
        pass_ok = hmac.compare_digest(password, creds[1])
        if user_ok and pass_ok:
            session.clear()
            session["logged_in"] = True
            session["username"] = creds[0]
            return redirect(next_url)
        error = "用户名或密码错误。"

    return render_template("login.html", error=error, next_url=next_url)


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
            return jsonify(result), 500
        result["current_port"] = port
        result["quick_ports"] = build_quick_ports(port)

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
