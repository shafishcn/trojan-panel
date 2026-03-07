function formatOutput(res) {
  const lines = [];
  lines.push(`status: ${res.ok ? "success" : "failed"}`);
  if (res.exec_ok !== undefined) lines.push(`command ok: ${res.exec_ok ? "yes" : "no"}`);
  if (res.service_status) lines.push(`service: ${res.service_status}`);
  if (res.service_active_line) lines.push(`active: ${res.service_active_line}`);
  if (res.current_port !== undefined && res.current_port !== null) lines.push(`current port: ${res.current_port}`);
  if (Array.isArray(res.quick_ports) && res.quick_ports.length) lines.push(`quick next: ${res.quick_ports.join(", ")}`);
  if (res.network_status) lines.push(`network: ${res.network_status}`);
  if (res.network_target) lines.push(`network target: ${res.network_target}`);
  if (res.network_message) lines.push(`network message: ${res.network_message}`);
  if (res.command) lines.push(`command: ${res.command}`);
  if (res.returncode !== undefined) lines.push(`return code: ${res.returncode}`);
  if (res.message) lines.push(`message: ${res.message}`);
  if (res.stdout) lines.push(`stdout:\n${res.stdout}`);
  if (res.stderr) lines.push(`stderr:\n${res.stderr}`);
  return lines.join("\n");
}

class UnauthorizedError extends Error {}

function redirectToLogin() {
  const next = `${window.location.pathname}${window.location.search}`;
  window.location.href = `/login?next=${encodeURIComponent(next)}`;
}

async function parseApiResponse(resp) {
  if (resp.status === 401) {
    redirectToLogin();
    throw new UnauthorizedError("Unauthorized");
  }
  let data = {};
  try {
    data = await resp.json();
  } catch (_err) {
    data = {};
  }
  if (!data || typeof data !== "object") data = {};
  if (data.ok === undefined) data.ok = resp.ok;
  if (!data.message && !resp.ok) data.message = `HTTP ${resp.status}`;
  return data;
}

function markResult(resultEl, ok, text) {
  resultEl.classList.remove("ok", "err");
  if (ok === true) resultEl.classList.add("ok");
  if (ok === false) resultEl.classList.add("err");
  resultEl.textContent = text;
}

function setButtonLoading(button, loadingText) {
  const prev = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  return () => {
    button.disabled = false;
    button.textContent = prev;
  };
}

function renderQuickButtons(card, quickPorts) {
  const listEl = card.querySelector(".quick-list");
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!Array.isArray(quickPorts) || !quickPorts.length) return;

  for (const p of quickPorts) {
    const btn = document.createElement("button");
    btn.className = "quick-btn";
    btn.type = "button";
    btn.dataset.port = String(p);
    btn.textContent = String(p);
    listEl.appendChild(btn);
  }
}

function applyRuntimeToCard(card, data) {
  if (!card || !data) return;
  const currentEl = card.querySelector(".current-port-value");
  if (currentEl && data.current_port !== undefined) {
    currentEl.textContent = data.current_port === null ? "未知" : String(data.current_port);
  }
  if (data.quick_ports !== undefined) {
    renderQuickButtons(card, data.quick_ports);
  }
}

function applyNetworkToCard(card, data) {
  if (!card || !data) return;
  const networkEl = card.querySelector(".network-value");
  if (!networkEl) return;

  networkEl.classList.remove("ok", "err", "muted");
  if (data.network_checked === true) {
    if (data.network_ok) {
      networkEl.textContent = "可访问";
      networkEl.classList.add("ok");
    } else {
      networkEl.textContent = "不可访问";
      networkEl.classList.add("err");
    }
    return;
  }

  if (data.network_checked === false && data.network_message) {
    networkEl.textContent = data.network_message;
    networkEl.classList.add("muted");
    return;
  }
}

function applyCardResult(serverId, data) {
  const card = document.querySelector(`.server-card[data-server-id="${serverId}"]`);
  if (!card) return;
  applyRuntimeToCard(card, data);
  applyNetworkToCard(card, data);
  const resultEl = card.querySelector(".result");
  if (!resultEl) return;
  markResult(resultEl, Boolean(data.ok), formatOutput(data));
}

async function switchPort(serverId, port, button, resultEl) {
  markResult(resultEl, null, "正在执行 SSH 命令...");
  const restore = setButtonLoading(button, "执行中...");
  try {
    const resp = await fetch("/api/switch-port", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId, port }),
    });
    const data = await parseApiResponse(resp);
    applyCardResult(serverId, data);
  } catch (err) {
    if (err instanceof UnauthorizedError) return;
    markResult(resultEl, false, `request error: ${err}`);
  } finally {
    restore();
  }
}

async function checkStatus(serverId, button, resultEl) {
  markResult(resultEl, null, "正在检查 trojan 服务状态...");
  const restore = setButtonLoading(button, "检查中...");
  try {
    const resp = await fetch("/api/trojan-status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId }),
    });
    const data = await parseApiResponse(resp);
    applyCardResult(serverId, data);
  } catch (err) {
    if (err instanceof UnauthorizedError) return;
    markResult(resultEl, false, `request error: ${err}`);
  } finally {
    restore();
  }
}

async function checkNetwork(serverId, button, resultEl) {
  markResult(resultEl, null, "正在检测地址端口连通性...");
  const restore = setButtonLoading(button, "检测中...");
  try {
    const resp = await fetch("/api/network-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId }),
    });
    const data = await parseApiResponse(resp);
    applyCardResult(serverId, data);
  } catch (err) {
    if (err instanceof UnauthorizedError) return;
    markResult(resultEl, false, `request error: ${err}`);
  } finally {
    restore();
  }
}

function formatSubscriptionResult(data) {
  const lines = [];
  lines.push(`status: ${data.ok ? "success" : "failed"}`);
  if (data.message) lines.push(`message: ${data.message}`);
  if (data.token) lines.push(`subscription id: ${data.token}`);
  if (data.overwritten !== undefined) lines.push(`overwritten: ${data.overwritten ? "yes" : "no"}`);
  if (data.server_count !== undefined) lines.push(`server count: ${data.server_count}`);
  if (Array.isArray(data.server_ids) && data.server_ids.length) lines.push(`server ids: ${data.server_ids.join(", ")}`);
  if (data.url) lines.push(`subscription url: ${data.url}`);
  if (Array.isArray(data.links) && data.links.length) lines.push(`links:\n${data.links.join("\n")}`);
  return lines.join("\n");
}

function parseInitialServers() {
  const el = document.querySelector("#initial-servers");
  if (!el) return [];
  try {
    const data = JSON.parse(el.textContent || "[]");
    return Array.isArray(data) ? data : [];
  } catch (_err) {
    return [];
  }
}

const initialServers = parseInitialServers();

function parseInitialAuth() {
  const el = document.querySelector("#initial-auth");
  if (!el) return { username: "", password: "" };
  try {
    const data = JSON.parse(el.textContent || "{}");
    if (!data || typeof data !== "object") return { username: "", password: "" };
    return {
      username: typeof data.username === "string" ? data.username : "",
      password: typeof data.password === "string" ? data.password : "",
    };
  } catch (_err) {
    return { username: "", password: "" };
  }
}

const initialAuth = parseInitialAuth();

function buildAutoServerId(listEl) {
  const used = new Set(
    Array.from(listEl.querySelectorAll('input[data-field="id"]'))
      .map((el) => (el instanceof HTMLInputElement ? el.value.trim() : ""))
      .filter((x) => Boolean(x)),
  );
  let idx = 1;
  while (used.has(`srv-${idx}`)) idx += 1;
  return `srv-${idx}`;
}

function createEditorItem(server, templateEl) {
  const fragment = templateEl.content.cloneNode(true);
  const item = fragment.querySelector(".editor-item");
  if (!item) return null;

  const fields = {
    id: item.querySelector('input[data-field="id"]'),
    name: item.querySelector('input[data-field="name"]'),
    commandTemplate: item.querySelector('input[data-field="command_template"]'),
    statusTemplate: item.querySelector('input[data-field="status_command_template"]'),
    currentPort: item.querySelector('input[data-field="current_port"]'),
    addr: item.querySelector('input[data-field="addr"]'),
    trojanPassword: item.querySelector('input[data-field="trojan_password"]'),
    description: item.querySelector('input[data-field="description"]'),
  };

  const initialCommandTemplate = String(server.command_template || "").trim();
  const initialStatusTemplate = String(server.status_command_template || "").trim();
  const hasSshTarget = String(server.ssh_target || "").trim() !== "";
  const shouldAutoDerive = !initialCommandTemplate && !initialStatusTemplate && !hasSshTarget;
  const syncDerivedCommands = () => {
    if (!shouldAutoDerive) return;
    const serverId = fields.id ? fields.id.value.trim() : "";
    if (fields.commandTemplate) {
      fields.commandTemplate.value = serverId ? `ssh ${serverId} trojan port $1` : "";
    }
    if (fields.statusTemplate) {
      fields.statusTemplate.value = serverId ? `ssh ${serverId} trojan status` : "";
    }
  };

  if (fields.id) {
    fields.id.value = server.id || "";
    fields.id.readOnly = true;
  }
  if (fields.name) fields.name.value = server.name || "";
  if (fields.commandTemplate) {
    const fallback = server.ssh_target ? `ssh ${server.ssh_target} trojan port $1` : "";
    fields.commandTemplate.value = server.command_template || fallback;
    fields.commandTemplate.readOnly = true;
  }
  if (fields.statusTemplate) {
    fields.statusTemplate.value = server.status_command_template || "";
    fields.statusTemplate.readOnly = true;
  }
  if (fields.currentPort) {
    fields.currentPort.value = server.current_port || "";
    fields.currentPort.readOnly = true;
  }
  if (fields.addr) {
    fields.addr.value = server.addr || "";
    fields.addr.readOnly = true;
  }
  if (fields.trojanPassword) {
    fields.trojanPassword.value = server.trojan_password || "";
    fields.trojanPassword.readOnly = true;
  }
  if (fields.description) fields.description.value = server.description || "";

  syncDerivedCommands();

  const removeBtn = item.querySelector(".remove-server-btn");
  if (removeBtn) {
    removeBtn.addEventListener("click", () => {
      item.remove();
    });
  }
  return item;
}

function collectServerEditors(listEl) {
  const items = Array.from(listEl.querySelectorAll(".editor-item"));
  return items.map((item) => {
    const getValue = (field) => {
      const el = item.querySelector(`input[data-field="${field}"]`);
      return el ? el.value.trim() : "";
    };
    return {
      id: getValue("id"),
      name: getValue("name"),
      command_template: getValue("command_template"),
      status_command_template: getValue("status_command_template"),
      current_port: getValue("current_port"),
      addr: getValue("addr"),
      trojan_password: getValue("trojan_password"),
      description: getValue("description"),
    };
  });
}

function initConfigEditor() {
  const listEl = document.querySelector("#editor-list");
  const templateEl = document.querySelector("#server-editor-template");
  const addBtn = document.querySelector("#add-server-btn");
  const saveBtn = document.querySelector("#save-servers-btn");
  const resultEl = document.querySelector("#config-result");
  const authUsernameEl = document.querySelector("#auth-username");
  const authPasswordEl = document.querySelector("#auth-password");
  if (!listEl || !templateEl || !addBtn || !saveBtn || !resultEl) return;

  const initial = initialServers.length
    ? initialServers
    : [{ id: "", name: "", command_template: "", status_command_template: "", current_port: "", addr: "", trojan_password: "", description: "" }];

  for (const server of initial) {
    const node = createEditorItem(server, templateEl);
    if (node) listEl.appendChild(node);
  }

  if (authUsernameEl) authUsernameEl.value = initialAuth.username || "";
  if (authPasswordEl) authPasswordEl.value = initialAuth.password || "";

  addBtn.addEventListener("click", () => {
    const autoId = buildAutoServerId(listEl);
    const node = createEditorItem(
      { id: autoId, name: "", command_template: "", status_command_template: "", current_port: "", addr: "", trojan_password: "", description: "" },
      templateEl,
    );
    if (node) listEl.appendChild(node);
  });

  saveBtn.addEventListener("click", async () => {
    const servers = collectServerEditors(listEl);
    const authUsername = authUsernameEl ? authUsernameEl.value.trim() : "";
    const authPassword = authPasswordEl ? authPasswordEl.value.trim() : "";
    if (!servers.length) {
      markResult(resultEl, false, "至少保留一个服务器配置。");
      return;
    }

    for (let i = 0; i < servers.length; i += 1) {
      const s = servers[i];
      if (!s.id) {
        markResult(resultEl, false, `第 ${i + 1} 行缺少服务器 ID。`);
        return;
      }
      if (!s.command_template || !s.command_template.includes("$1")) {
        markResult(resultEl, false, `第 ${i + 1} 行命令模板必须包含 $1。`);
        return;
      }
      if (s.current_port) {
        const p = Number(s.current_port);
        if (!Number.isInteger(p) || p < 1 || p > 65535) {
          markResult(resultEl, false, `第 ${i + 1} 行当前端口必须是 1-65535 的整数。`);
          return;
        }
      }
      if (s.addr && /\s/.test(s.addr)) {
        markResult(resultEl, false, `第 ${i + 1} 行检测地址不能包含空白字符。`);
        return;
      }
      if (s.trojan_password && /\s/.test(s.trojan_password)) {
        markResult(resultEl, false, `第 ${i + 1} 行 Trojan 密码不能包含空白字符。`);
        return;
      }
    }

    if ((authUsername && !authPassword) || (!authUsername && authPassword)) {
      markResult(resultEl, false, "登录配置必须同时填写账号和密码，或全部留空。");
      return;
    }

    const restore = setButtonLoading(saveBtn, "保存中...");
    markResult(resultEl, null, "正在写入配置文件...");
    try {
      const resp = await fetch("/api/servers", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          servers,
          auth: {
            username: authUsername,
            password: authPassword,
          },
        }),
      });
      const data = await parseApiResponse(resp);
      if (!data.ok) {
        markResult(resultEl, false, data.message || "保存失败。");
        return;
      }
      markResult(resultEl, true, "保存成功。");
      window.setTimeout(() => window.location.reload(), 600);
    } catch (err) {
      if (err instanceof UnauthorizedError) return;
      markResult(resultEl, false, `request error: ${err}`);
    } finally {
      restore();
    }
  });
}

function initSubscriptionPanel() {
  const genBtn = document.querySelector("#sub-generate-btn");
  const selectAllBtn = document.querySelector("#sub-select-all-btn");
  const clearBtn = document.querySelector("#sub-clear-btn");
  const tokenInput = document.querySelector("#sub-token-input");
  const resultEl = document.querySelector("#sub-result");
  if (!genBtn || !selectAllBtn || !clearBtn || !resultEl) return;

  const allChecks = () => Array.from(document.querySelectorAll(".server-card .sub-select"));
  const getServerIdByCheck = (el) => {
    const card = el.closest(".server-card");
    return card ? card.getAttribute("data-server-id") || "" : "";
  };
  const getSelectedServerIds = () => {
    return allChecks()
      .filter((el) => el.checked)
      .map((el) => getServerIdByCheck(el))
      .filter((x) => Boolean(x));
  };

  const tokenFromQuery = new URLSearchParams(window.location.search).get("token") || "";
  if (tokenInput && tokenFromQuery && /^[A-Za-z0-9_-]{1,64}$/.test(tokenFromQuery) && !tokenInput.value.trim()) {
    tokenInput.value = tokenFromQuery;
    markResult(resultEl, null, `已载入订阅标识: ${tokenFromQuery}，请勾选服务器后点击生成进行覆盖更新。`);
  }

  selectAllBtn.addEventListener("click", () => {
    for (const el of allChecks()) el.checked = true;
    markResult(resultEl, null, "已全选服务器。");
  });

  clearBtn.addEventListener("click", () => {
    for (const el of allChecks()) el.checked = false;
    markResult(resultEl, null, "已清空选择。");
  });

  genBtn.addEventListener("click", async () => {
    const selectedIds = getSelectedServerIds();

    if (!selectedIds.length) {
      markResult(resultEl, false, "请先勾选至少一个服务器。");
      return;
    }

    const token = tokenInput ? tokenInput.value.trim() : "";
    if (token && !/^[A-Za-z0-9_-]{1,64}$/.test(token)) {
      markResult(resultEl, false, "自定义订阅标识只能包含字母、数字、-、_，且长度不超过 64。");
      return;
    }

    const restore = setButtonLoading(genBtn, "生成中...");
    markResult(resultEl, null, "正在生成订阅访问地址...");
    try {
      const resp = await fetch("/api/subscription-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_ids: selectedIds, token }),
      });
      const data = await parseApiResponse(resp);
      if (tokenInput && data.token) tokenInput.value = String(data.token);
      markResult(resultEl, Boolean(data.ok), formatSubscriptionResult(data));
    } catch (err) {
      if (err instanceof UnauthorizedError) return;
      markResult(resultEl, false, `request error: ${err}`);
    } finally {
      restore();
    }
  });
}

function initSubscriptionManagerPage() {
  const refreshBtn = document.querySelector("#sub-manager-refresh-btn");
  const tokenListEl = document.querySelector("#sub-manager-token-list");
  const resultEl = document.querySelector("#sub-manager-result");
  if (!refreshBtn || !tokenListEl || !resultEl) return;

  const setListText = (text) => {
    tokenListEl.innerHTML = "";
    const el = document.createElement("p");
    el.className = "sub-token-empty";
    el.textContent = text;
    tokenListEl.appendChild(el);
  };

  const buildCopyUrl = (rawUrl) => {
    try {
      const parsed = new URL(rawUrl);
      const host = (parsed.hostname || "").trim().toLowerCase();
      const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
      const isIPv6 = host.includes(":");
      const isLocalhost = host === "localhost";
      const isDomain = !isIPv4 && !isIPv6 && !isLocalhost && /[a-z]/i.test(host);
      if (isDomain) {
        parsed.protocol = "https:";
        return { url: parsed.toString(), forcedHttps: true };
      }
    } catch (_err) {
      // Fall through and keep original URL.
    }
    return { url: rawUrl, forcedHttps: false };
  };

  const renderList = (items) => {
    tokenListEl.innerHTML = "";
    if (!Array.isArray(items) || !items.length) {
      setListText("暂无已保存订阅。");
      return;
    }

    for (const item of items) {
      const token = typeof item.token === "string" ? item.token : "";
      if (!token) continue;
      const serverIds = Array.isArray(item.server_ids) ? item.server_ids.filter((x) => typeof x === "string" && x) : [];
      const serverNames = Array.isArray(item.server_names) ? item.server_names.filter((x) => typeof x === "string" && x) : [];
      const missingIds = Array.isArray(item.missing_server_ids)
        ? item.missing_server_ids.filter((x) => typeof x === "string" && x)
        : [];

      const row = document.createElement("article");
      row.className = "sub-token-item";

      const tokenLine = document.createElement("p");
      tokenLine.className = "sub-token-token";
      tokenLine.textContent = token;
      row.appendChild(tokenLine);

      const infoLine = document.createElement("p");
      infoLine.className = "sub-token-meta";
      infoLine.textContent = `服务器(${serverIds.length}): ${serverIds.join(", ") || "无"}`;
      row.appendChild(infoLine);

      if (serverNames.length) {
        const nameLine = document.createElement("p");
        nameLine.className = "sub-token-meta";
        nameLine.textContent = `节点名: ${serverNames.join(", ")}`;
        row.appendChild(nameLine);
      }

      if (missingIds.length) {
        const missingLine = document.createElement("p");
        missingLine.className = "sub-token-meta sub-token-missing";
        missingLine.textContent = `缺失节点: ${missingIds.join(", ")}`;
        row.appendChild(missingLine);
      }

      const url = typeof item.url === "string" ? item.url : "";
      if (url) {
        const urlLine = document.createElement("a");
        urlLine.className = "sub-token-url";
        urlLine.href = url;
        urlLine.target = "_blank";
        urlLine.rel = "noopener noreferrer";
        urlLine.textContent = url;
        row.appendChild(urlLine);
      }

      const actions = document.createElement("div");
      actions.className = "sub-token-actions";

      const useBtn = document.createElement("button");
      useBtn.type = "button";
      useBtn.className = "ghost-btn";
      useBtn.textContent = "去生成页";
      useBtn.addEventListener("click", () => {
        window.location.href = `/?token=${encodeURIComponent(token)}`;
      });
      actions.appendChild(useBtn);

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "ghost-btn";
      copyBtn.textContent = "复制链接";
      copyBtn.addEventListener("click", async () => {
        if (!url) {
          markResult(resultEl, false, "当前订阅没有可复制的链接。");
          return;
        }
        try {
          const copied = buildCopyUrl(url);
          await navigator.clipboard.writeText(copied.url);
          if (copied.forcedHttps) {
            markResult(resultEl, true, `已复制订阅地址: ${token}（域名链接已强制 HTTPS）`);
          } else {
            markResult(resultEl, true, `已复制订阅地址: ${token}`);
          }
        } catch (err) {
          markResult(resultEl, false, `复制失败: ${err}`);
        }
      });
      actions.appendChild(copyBtn);

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "danger-btn";
      deleteBtn.textContent = "删除";
      deleteBtn.addEventListener("click", async () => {
        if (!window.confirm(`确认删除订阅 "${token}" 吗？`)) return;
        const restore = setButtonLoading(deleteBtn, "删除中...");
        try {
          const resp = await fetch(`/api/subscriptions/${encodeURIComponent(token)}`, { method: "DELETE" });
          const data = await parseApiResponse(resp);
          if (!data.ok) {
            markResult(resultEl, false, data.message || "删除失败。");
            return;
          }
          markResult(resultEl, true, `订阅已删除: ${token}`);
          await loadSubscriptionList();
        } catch (err) {
          if (err instanceof UnauthorizedError) return;
          markResult(resultEl, false, `request error: ${err}`);
        } finally {
          restore();
        }
      });
      actions.appendChild(deleteBtn);

      row.appendChild(actions);
      tokenListEl.appendChild(row);
    }
  };

  const loadSubscriptionList = async (button = null) => {
    let restore = null;
    if (button) restore = setButtonLoading(button, "刷新中...");
    setListText("正在加载订阅列表...");
    try {
      const resp = await fetch("/api/subscriptions");
      const data = await parseApiResponse(resp);
      if (!data.ok) {
        setListText(`加载失败: ${data.message || "未知错误"}`);
        return;
      }
      renderList(data.subscriptions);
    } catch (err) {
      if (err instanceof UnauthorizedError) return;
      setListText(`request error: ${err}`);
    } finally {
      if (restore) restore();
    }
  };

  refreshBtn.addEventListener("click", async () => {
    await loadSubscriptionList(refreshBtn);
  });
  loadSubscriptionList();
}

function initServerCards() {
  document.querySelectorAll(".server-card").forEach((card) => {
    const serverId = card.dataset.serverId;
    const input = card.querySelector("input[type='number']");
    const submitBtn = card.querySelector(".submit-btn");
    const statusBtn = card.querySelector(".status-btn");
    const networkBtn = card.querySelector(".network-btn");
    const resultEl = card.querySelector(".result");
    if (!serverId || !input || !submitBtn || !statusBtn || !networkBtn || !resultEl) return;

    const initial = initialServers.find((item) => item.id === serverId);
    if (initial) applyRuntimeToCard(card, initial);

    card.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const btn = target.closest(".quick-btn");
      if (!btn) return;
      const p = btn.dataset.port;
      if (!p) return;
      input.value = p;
      input.focus();
    });

    submitBtn.addEventListener("click", async () => {
      const port = Number(input.value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        markResult(resultEl, false, "端口必须是 1-65535 的整数");
        return;
      }
      await switchPort(serverId, port, submitBtn, resultEl);
    });

    statusBtn.addEventListener("click", async () => {
      await checkStatus(serverId, statusBtn, resultEl);
    });

    networkBtn.addEventListener("click", async () => {
      await checkNetwork(serverId, networkBtn, resultEl);
    });

    input.addEventListener("keydown", async (event) => {
      if (event.key === "Enter") {
        submitBtn.click();
      }
    });
  });
}

initConfigEditor();
initServerCards();
initSubscriptionPanel();
initSubscriptionManagerPage();
