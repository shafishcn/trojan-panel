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
  if (res.traffic_cycle_label) lines.push(`traffic cycle: ${res.traffic_cycle_label}`);
  if (res.traffic_period_label) lines.push(`traffic period: ${res.traffic_period_label}`);
  if (res.interface) lines.push(`traffic interface: ${res.interface}`);
  if (res.traffic_rx_display) lines.push(`traffic download: ${res.traffic_rx_display}`);
  if (res.traffic_tx_display) lines.push(`traffic upload: ${res.traffic_tx_display}`);
  if (res.traffic_total_display) lines.push(`traffic total: ${res.traffic_total_display}`);
  if (res.traffic_quota_display) lines.push(`traffic quota: ${res.traffic_quota_display}`);
  if (res.traffic_remaining_display) lines.push(`traffic remaining: ${res.traffic_remaining_display}`);
  if (res.traffic_quota_percent !== undefined && res.traffic_quota_percent !== null) lines.push(`traffic used: ${res.traffic_quota_percent}%`);
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

let closeActiveDialog = null;

function ensureThemeDialog() {
  let root = document.querySelector("#theme-dialog");
  if (root) {
    return {
      root,
      backdrop: root.querySelector(".theme-dialog-backdrop"),
      title: root.querySelector(".theme-dialog-title"),
      message: root.querySelector(".theme-dialog-message"),
      cancelBtn: root.querySelector(".theme-dialog-cancel"),
      confirmBtn: root.querySelector(".theme-dialog-confirm"),
    };
  }

  root = document.createElement("div");
  root.id = "theme-dialog";
  root.className = "theme-dialog";
  root.setAttribute("aria-hidden", "true");
  root.innerHTML = `
    <div class="theme-dialog-backdrop"></div>
    <section class="theme-dialog-card" role="dialog" aria-modal="true" aria-labelledby="theme-dialog-title" aria-describedby="theme-dialog-message">
      <h3 id="theme-dialog-title" class="theme-dialog-title"></h3>
      <p id="theme-dialog-message" class="theme-dialog-message"></p>
      <div class="theme-dialog-actions">
        <button type="button" class="theme-dialog-btn theme-dialog-cancel">取消</button>
        <button type="button" class="theme-dialog-btn theme-dialog-confirm">确认</button>
      </div>
    </section>
  `;
  document.body.appendChild(root);

  return {
    root,
    backdrop: root.querySelector(".theme-dialog-backdrop"),
    title: root.querySelector(".theme-dialog-title"),
    message: root.querySelector(".theme-dialog-message"),
    cancelBtn: root.querySelector(".theme-dialog-cancel"),
    confirmBtn: root.querySelector(".theme-dialog-confirm"),
  };
}

function showThemeDialog({
  title = "提示",
  message = "",
  confirmText = "确认",
  cancelText = "取消",
  danger = false,
  hideCancel = false,
} = {}) {
  const modal = ensureThemeDialog();
  if (!modal.root || !modal.backdrop || !modal.title || !modal.message || !modal.cancelBtn || !modal.confirmBtn) {
    return Promise.resolve(false);
  }

  if (typeof closeActiveDialog === "function") closeActiveDialog(false);

  modal.title.textContent = String(title || "提示");
  modal.message.textContent = String(message || "");
  modal.confirmBtn.textContent = String(confirmText || "确认");
  modal.cancelBtn.textContent = String(cancelText || "取消");
  modal.cancelBtn.hidden = Boolean(hideCancel);
  modal.cancelBtn.disabled = false;
  modal.confirmBtn.disabled = false;
  modal.confirmBtn.classList.toggle("is-danger", Boolean(danger));

  modal.root.classList.add("is-open");
  modal.root.setAttribute("aria-hidden", "false");
  document.body.classList.add("has-modal-open");

  return new Promise((resolve) => {
    let settled = false;

    const cleanup = () => {
      modal.backdrop.removeEventListener("click", onCancel);
      modal.cancelBtn.removeEventListener("click", onCancel);
      modal.confirmBtn.removeEventListener("click", onConfirm);
      document.removeEventListener("keydown", onKeydown);
      modal.root.classList.remove("is-open");
      modal.root.setAttribute("aria-hidden", "true");
      document.body.classList.remove("has-modal-open");
      closeActiveDialog = null;
    };

    const close = (ok) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Boolean(ok));
    };

    const onCancel = () => close(false);
    const onConfirm = () => close(true);
    const onKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close(false);
      }
    };

    closeActiveDialog = close;
    modal.backdrop.addEventListener("click", onCancel);
    modal.cancelBtn.addEventListener("click", onCancel);
    modal.confirmBtn.addEventListener("click", onConfirm);
    document.addEventListener("keydown", onKeydown);
    window.setTimeout(() => {
      if (hideCancel) modal.confirmBtn.focus();
      else modal.cancelBtn.focus();
    }, 0);
  });
}

function showThemeConfirm(options) {
  return showThemeDialog(options);
}

function ensureOutputDialog() {
  let root = document.querySelector("#theme-output-dialog");
  if (root) {
    return {
      root,
      backdrop: root.querySelector(".theme-dialog-backdrop"),
      title: root.querySelector(".theme-output-title"),
      summary: root.querySelector(".theme-output-summary"),
      closeBtn: root.querySelector(".theme-output-close"),
      body: root.querySelector(".theme-output-body"),
    };
  }

  root = document.createElement("div");
  root.id = "theme-output-dialog";
  root.className = "theme-dialog theme-dialog-output";
  root.setAttribute("aria-hidden", "true");
  root.innerHTML = `
    <div class="theme-dialog-backdrop"></div>
    <section class="theme-dialog-card" role="dialog" aria-modal="true" aria-labelledby="theme-output-title" aria-describedby="theme-output-body">
      <div class="theme-output-head">
        <div class="theme-output-copy">
          <h3 id="theme-output-title" class="theme-dialog-title theme-output-title"></h3>
          <p class="theme-output-summary"></p>
        </div>
        <button type="button" class="theme-dialog-btn theme-output-close">关闭</button>
      </div>
      <pre id="theme-output-body" class="theme-output-body"></pre>
    </section>
  `;
  document.body.appendChild(root);

  return {
    root,
    backdrop: root.querySelector(".theme-dialog-backdrop"),
    title: root.querySelector(".theme-output-title"),
    summary: root.querySelector(".theme-output-summary"),
    closeBtn: root.querySelector(".theme-output-close"),
    body: root.querySelector(".theme-output-body"),
  };
}

function showOutputDialog({
  title = "运行详情",
  summary = "",
  details = "",
  state = "idle",
} = {}) {
  const modal = ensureOutputDialog();
  if (!modal.root || !modal.backdrop || !modal.title || !modal.summary || !modal.closeBtn || !modal.body) {
    return Promise.resolve(false);
  }

  if (typeof closeActiveDialog === "function") closeActiveDialog(false);

  modal.title.textContent = String(title || "运行详情");
  modal.summary.textContent = String(summary || "");
  modal.summary.classList.remove("is-ok", "is-err", "is-pending");
  if (state === "ok") modal.summary.classList.add("is-ok");
  else if (state === "err") modal.summary.classList.add("is-err");
  else if (state === "pending") modal.summary.classList.add("is-pending");
  modal.body.textContent = String(details || summary || "");

  modal.root.classList.add("is-open");
  modal.root.setAttribute("aria-hidden", "false");
  document.body.classList.add("has-modal-open");

  return new Promise((resolve) => {
    let settled = false;

    const cleanup = () => {
      modal.backdrop.removeEventListener("click", onClose);
      modal.closeBtn.removeEventListener("click", onClose);
      document.removeEventListener("keydown", onKeydown);
      modal.root.classList.remove("is-open");
      modal.root.setAttribute("aria-hidden", "true");
      document.body.classList.remove("has-modal-open");
      closeActiveDialog = null;
    };

    const close = (ok) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Boolean(ok));
    };

    const onClose = () => close(true);
    const onKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close(true);
      }
    };

    closeActiveDialog = close;
    modal.backdrop.addEventListener("click", onClose);
    modal.closeBtn.addEventListener("click", onClose);
    document.addEventListener("keydown", onKeydown);
    window.setTimeout(() => modal.closeBtn.focus(), 0);
  });
}

function parseDateValue(rawValue) {
  if (!rawValue) return null;
  const date = rawValue instanceof Date ? rawValue : new Date(rawValue);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function formatDateTimeDisplay(rawValue) {
  const date = parseDateValue(rawValue);
  if (!date) return rawValue ? String(rawValue) : "";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function toDateTimeLocalValue(rawValue) {
  const date = parseDateValue(rawValue);
  if (!date) return "";
  const pad = (value) => String(value).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function cloneDate(rawValue) {
  const date = parseDateValue(rawValue);
  return date ? new Date(date.getTime()) : null;
}

function roundUpToNextMinute(rawValue = new Date()) {
  const date = cloneDate(rawValue) || new Date();
  date.setSeconds(0, 0);
  date.setMinutes(date.getMinutes() + 1);
  return date;
}

function addDays(rawValue, days) {
  const date = cloneDate(rawValue) || new Date();
  date.setDate(date.getDate() + days);
  return date;
}

function buildLocalDate(year, monthIndex, day, hour, minute) {
  return new Date(year, monthIndex, day, hour, minute, 0, 0);
}

function parseManualDateTimeInput(rawValue) {
  const text = String(rawValue || "").trim();
  if (!text) return null;
  const matched = text.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:\s+|T)(\d{1,2}):(\d{2})$/);
  if (!matched) return null;
  const year = Number(matched[1]);
  const month = Number(matched[2]);
  const day = Number(matched[3]);
  const hour = Number(matched[4]);
  const minute = Number(matched[5]);
  if (
    !Number.isInteger(year)
    || !Number.isInteger(month)
    || !Number.isInteger(day)
    || !Number.isInteger(hour)
    || !Number.isInteger(minute)
  ) {
    return null;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    return null;
  }
  const date = buildLocalDate(year, month - 1, day, hour, minute);
  if (
    date.getFullYear() !== year
    || date.getMonth() !== month - 1
    || date.getDate() !== day
    || date.getHours() !== hour
    || date.getMinutes() !== minute
  ) {
    return null;
  }
  return date;
}

function isSameCalendarDay(a, b) {
  const left = parseDateValue(a);
  const right = parseDateValue(b);
  if (!left || !right) return false;
  return left.getFullYear() === right.getFullYear()
    && left.getMonth() === right.getMonth()
    && left.getDate() === right.getDate();
}

function isSameCalendarMonth(a, b) {
  const left = parseDateValue(a);
  const right = parseDateValue(b);
  if (!left || !right) return false;
  return left.getFullYear() === right.getFullYear() && left.getMonth() === right.getMonth();
}

function monthLabel(rawValue) {
  const date = parseDateValue(rawValue);
  if (!date) return "";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "long",
  }).format(date);
}

function formatSubscriptionExpiry(expiresAt, expired) {
  if (!expiresAt) return "永久有效";
  const display = formatDateTimeDisplay(expiresAt);
  return expired ? `已过期：${display}` : `截止时间：${display}`;
}

function sortSubscriptionsForDisplay(items) {
  if (!Array.isArray(items)) return [];
  return items
    .map((item, index) => ({ item, index }))
    .sort((left, right) => {
      const leftExpired = Boolean(left.item && left.item.expired);
      const rightExpired = Boolean(right.item && right.item.expired);
      if (leftExpired !== rightExpired) {
        return leftExpired ? 1 : -1;
      }
      return left.index - right.index;
    })
    .map((entry) => entry.item);
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

function formatTrafficSource(data) {
  if (!data || typeof data !== "object") {
    return "数据源：vnstat / 自动选择网卡";
  }
  if (data.interface) {
    return `数据源：vnstat / ${data.interface}`;
  }
  if (data.vnstat_interface) {
    return `数据源：vnstat / ${data.vnstat_interface}`;
  }
  return "数据源：vnstat / 自动选择网卡";
}

function translateServerMessage(rawText, fallback = "操作失败。") {
  const text = String(rawText || "").trim();
  if (!text) return fallback;
  const lower = text.toLowerCase();

  const exactMap = new Map([
    ["ssh command timed out.", "SSH 命令执行超时。"],
    ["port switched successfully.", "端口切换成功。"],
    ["failed to switch port.", "切换端口失败。"],
    ["status fetched.", "状态获取成功。"],
    ["failed to fetch status.", "状态获取失败。"],
    ["traffic usage fetched.", "流量已更新。"],
    ["failed to fetch traffic usage.", "获取流量失败。"],
    ["traffic usage fetched, but vnstat daily history may be incomplete for the current cycle.", "流量已更新，但当前周期数据可能尚未完整。"],
    ["trojan service is running normally.", "Trojan 服务运行正常。"],
    ["trojan service is not running normally.", "Trojan 服务未正常运行。"],
    ["network is reachable.", "网络可访问。"],
    ["network check failed.", "网络检测失败。"],
    ["connection timed out.", "连接超时。"],
    ["`addr` is not configured.", "未配置检测地址。"],
    ["`current_port` is not configured.", "未配置当前端口。"],
    ["`vnstat` has no daily traffic data yet.", "流量数据尚未生成。"],
  ]);
  if (exactMap.has(lower)) return exactMap.get(lower) || fallback;

  if (text.startsWith("Port switched, but failed to save current_port:")) {
    return "端口已切换，但保存当前端口失败。";
  }
  if (text.startsWith("Config error:")) {
    return `配置错误：${text.slice("Config error:".length).trim() || "请检查配置。"}`
  }
  if (text.startsWith("request error:")) {
    return `请求失败：${text.slice("request error:".length).trim() || "请稍后重试。"}`
  }
  if (text.startsWith("`vnstat` returned invalid JSON:")) {
    return "流量数据格式异常。";
  }
  if (lower.includes("connection refused")) {
    return "连接被拒绝。";
  }
  if (lower.includes("name or service not known") || lower.includes("nodename nor servname provided")) {
    return "域名解析失败。";
  }
  if (lower.includes("no route to host")) {
    return "无法路由到目标主机。";
  }
  if (lower.includes("network is unreachable")) {
    return "网络不可达。";
  }
  if (lower.includes("timed out") || lower.includes("timeout")) {
    return "连接超时。";
  }

  return fallback;
}

function summarizeNetworkStatus(data) {
  if (!data || typeof data !== "object" || data.network_checked === undefined) return "";
  if (data.network_checked === true) {
    if (data.network_ok) return "网络可访问。";
    return `网络不可访问：${translateServerMessage(data.network_message, "请检查目标地址或端口。")}`;
  }
  if (data.network_checked === false) {
    return translateServerMessage(data.network_message, "网络检测条件不足。");
  }
  return "";
}

function summarizeTrafficStatus(data) {
  if (!data || typeof data !== "object") return "";
  const hasTrafficContext = Boolean(
    data.traffic_cycle_label
    || data.traffic_total_display
    || data.traffic_rx_display
    || data.traffic_tx_display
    || (typeof data.command === "string" && data.command.includes("vnstat")),
  );
  if (!hasTrafficContext) return "";
  if (data.ok) {
    if (data.traffic_total_display) {
      if (data.traffic_data_coverage_ok === false) {
        return `流量已更新，当前已用 ${data.traffic_total_display}，但当前周期数据可能尚未完整。`;
      }
      return `流量已更新，当前已用 ${data.traffic_total_display}。`;
    }
    return "流量已更新。";
  }
  return translateServerMessage(data.message, "获取流量失败。");
}

function summarizeServiceStatus(data) {
  if (!data || typeof data !== "object") return "";
  const hasServiceContext = Boolean(
    data.service_status !== undefined
    || data.service_ok !== undefined
    || (typeof data.command === "string" && data.command.includes("trojan status")),
  );
  if (!hasServiceContext) return "";
  if (data.service_status === "running") {
    return data.network_checked === true
      ? `Trojan 服务运行正常，${data.network_ok ? "网络可访问" : "网络不可访问"}。`
      : "Trojan 服务运行正常。";
  }
  if (data.service_status === "not-running") {
    return "Trojan 服务未正常运行。";
  }
  if (data.service_status === "unknown" && data.ok === false) {
    return translateServerMessage(data.message, "状态检查失败。");
  }
  return "";
}

function summarizePortSwitchStatus(data) {
  if (!data || typeof data !== "object") return "";
  const command = typeof data.command === "string" ? data.command : "";
  const hasSwitchContext = command.includes("trojan port");
  if (!hasSwitchContext) return "";
  if (data.ok) {
    const portPart = data.current_port !== undefined && data.current_port !== null
      ? `端口已切换为 ${data.current_port}`
      : "端口已切换";
    if (data.network_checked === true) {
      return `${portPart}，${data.network_ok ? "网络可访问" : "网络不可访问"}。`;
    }
    return `${portPart}。`;
  }
  if (typeof data.message === "string" && data.message.startsWith("Port switched, but failed to save current_port:")) {
    return "端口已切换，但保存当前端口失败。";
  }
  return translateServerMessage(data.message, "切换端口失败。");
}

function buildCardOutputSummary(data) {
  if (!data || typeof data !== "object") return "等待操作...";
  const switchSummary = summarizePortSwitchStatus(data);
  if (switchSummary) return switchSummary;
  const serviceSummary = summarizeServiceStatus(data);
  if (serviceSummary) return serviceSummary;
  const trafficSummary = summarizeTrafficStatus(data);
  if (trafficSummary) return trafficSummary;
  const networkSummary = summarizeNetworkStatus(data);
  if (networkSummary) return networkSummary;
  if (data.message) return translateServerMessage(data.message, "操作失败。");
  if (data.network_message) return translateServerMessage(data.network_message, "网络检测失败。");
  if (data.ok === true) return "操作已完成。";
  if (data.ok === false) return "操作失败。";
  return "等待操作...";
}

function getServerResultState(ok) {
  if (ok === true) return "ok";
  if (ok === false) return "err";
  return "pending";
}

function setServerResult(card, {
  ok = null,
  summary = "等待操作...",
  details = "",
  title = "运行详情",
} = {}) {
  if (!card) return;
  const panel = card.querySelector(".server-result");
  const summaryEl = card.querySelector(".server-result-summary");
  const detailBtn = card.querySelector(".server-result-detail");
  const resultEl = card.querySelector(".result");
  if (!resultEl) return;

  if (!panel || !summaryEl || !detailBtn) {
    markResult(resultEl, ok, String(details || summary || ""));
    return;
  }

  const state = getServerResultState(ok);
  panel.classList.remove("is-ok", "is-err", "is-pending", "is-idle");
  panel.classList.add(state === "ok" ? "is-ok" : state === "err" ? "is-err" : summary === "等待操作..." ? "is-idle" : "is-pending");
  summaryEl.textContent = String(summary || "等待操作...");
  resultEl.textContent = String(details || "");

  const hasDetails = Boolean(String(details || "").trim());
  detailBtn.hidden = !hasDetails;
  detailBtn.disabled = !hasDetails;
  detailBtn.dataset.detailTitle = String(title || "运行详情");
  detailBtn.dataset.detailSummary = String(summary || "");
  detailBtn.dataset.detailState = state;
}

function openServerResultDialog(card) {
  if (!card) return;
  const detailBtn = card.querySelector(".server-result-detail");
  const resultEl = card.querySelector(".result");
  if (!detailBtn || !resultEl) return;
  const details = resultEl.textContent || "";
  if (!details.trim()) return;
  showOutputDialog({
    title: detailBtn.dataset.detailTitle || "运行详情",
    summary: detailBtn.dataset.detailSummary || "",
    details,
    state: detailBtn.dataset.detailState || "idle",
  });
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

function applyTrafficToCard(card, data) {
  if (!card || !data) return;
  const cycleBadgeEl = card.querySelector(".traffic-cycle-badge");
  const periodEl = card.querySelector(".traffic-period-value");
  const rxEl = card.querySelector(".traffic-rx-value");
  const txEl = card.querySelector(".traffic-tx-value");
  const totalEl = card.querySelector(".traffic-total-value");
  const quotaEl = card.querySelector(".traffic-quota-value");
  const remainingEl = card.querySelector(".traffic-remaining-value");
  const percentEl = card.querySelector(".traffic-percent-value");
  const progressEl = card.querySelector(".traffic-progress");
  const progressBarEl = card.querySelector(".traffic-progress-bar");
  const noteEl = card.querySelector(".traffic-note");
  const panelEl = card.querySelector(".traffic-panel");
  if (!rxEl || !txEl || !totalEl || !quotaEl || !remainingEl || !percentEl || !progressEl || !progressBarEl || !noteEl || !panelEl) return;
  const hasTrafficMeta = Boolean(
    data.traffic_cycle_label
    || data.traffic_period_label
    || data.interface
    || data.vnstat_interface,
  );
  const hasTrafficValues = Boolean(
    data.traffic_rx_display
    || data.traffic_tx_display
    || data.traffic_total_display,
  );
  const hasQuotaConfig = Boolean(data.traffic_quota_display || data.traffic_quota_bytes !== undefined);

  if (cycleBadgeEl && data.traffic_cycle_label) {
    cycleBadgeEl.textContent = data.traffic_cycle_label;
  }
  if (periodEl && data.traffic_period_label) {
    periodEl.textContent = data.traffic_period_label;
  }
  if (data.traffic_rx_display) {
    rxEl.textContent = data.traffic_rx_display;
  }
  if (data.traffic_tx_display) {
    txEl.textContent = data.traffic_tx_display;
  }
  if (data.traffic_total_display) {
    totalEl.textContent = data.traffic_total_display;
  }
  if (hasQuotaConfig) {
    quotaEl.textContent = data.traffic_quota_display || data.traffic_quota || "未设置";
    remainingEl.textContent = data.traffic_remaining_display || "--";
    percentEl.textContent = data.traffic_quota_percent !== undefined && data.traffic_quota_percent !== null
      ? `${data.traffic_quota_percent}%`
      : "--";
    const percent = Number(data.traffic_quota_percent);
    const safePercent = Number.isFinite(percent) ? Math.max(0, Math.min(percent, 100)) : 0;
    progressBarEl.style.width = `${safePercent}%`;
    progressEl.classList.toggle("is-configured", Boolean(data.traffic_quota_configured || data.traffic_quota_display));
    progressEl.classList.toggle("is-exceeded", Boolean(data.traffic_quota_exceeded));
  } else {
    progressBarEl.style.width = "0%";
    progressEl.classList.remove("is-configured", "is-exceeded");
  }
  if (hasTrafficMeta) {
    noteEl.textContent = formatTrafficSource(data);
  }

  if (!hasTrafficMeta && !hasTrafficValues) {
    return;
  }

  panelEl.classList.remove("is-error", "is-ok");
  if (hasTrafficValues) {
    panelEl.classList.add(data.ok ? "is-ok" : "is-error");
  } else if (data.ok === false) {
    panelEl.classList.add("is-error");
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
  applyTrafficToCard(card, data);
  setServerResult(card, {
    ok: data.ok,
    summary: buildCardOutputSummary(data),
    details: formatOutput(data),
    title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 运行详情`,
  });
}

async function switchPort(serverId, port, button, card) {
  setServerResult(card, {
    ok: null,
    summary: "正在执行 SSH 命令...",
    details: "",
    title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 切换端口`,
  });
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
    setServerResult(card, {
      ok: false,
      summary: `请求失败：${err}`,
      details: `request error: ${err}`,
      title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 切换端口`,
    });
  } finally {
    restore();
  }
}

async function checkStatus(serverId, button, card) {
  setServerResult(card, {
    ok: null,
    summary: "正在检查 trojan 服务状态...",
    details: "",
    title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 状态检查`,
  });
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
    setServerResult(card, {
      ok: false,
      summary: `请求失败：${err}`,
      details: `request error: ${err}`,
      title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 状态检查`,
    });
  } finally {
    restore();
  }
}

async function checkNetwork(serverId, button, card) {
  setServerResult(card, {
    ok: null,
    summary: "正在检测地址端口连通性...",
    details: "",
    title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 网络检测`,
  });
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
    setServerResult(card, {
      ok: false,
      summary: `请求失败：${err}`,
      details: `request error: ${err}`,
      title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 网络检测`,
    });
  } finally {
    restore();
  }
}

async function checkTraffic(serverId, button, card) {
  setServerResult(card, {
    ok: null,
    summary: "正在读取当前周期流量...",
    details: "",
    title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 流量监控`,
  });
  const restore = setButtonLoading(button, "读取中...");
  try {
    const resp = await fetch("/api/server-traffic", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ server_id: serverId }),
    });
    const data = await parseApiResponse(resp);
    applyCardResult(serverId, data);
  } catch (err) {
    if (err instanceof UnauthorizedError) return;
    setServerResult(card, {
      ok: false,
      summary: `请求失败：${err}`,
      details: `request error: ${err}`,
      title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 流量监控`,
    });
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
  if (data.expires_at !== undefined || data.expiry_state !== undefined) {
    lines.push(`expiry: ${formatSubscriptionExpiry(data.expires_at, Boolean(data.expired))}`);
  }
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
    trafficQuota: item.querySelector('input[data-field="traffic_quota"]'),
    vnstatInterface: item.querySelector('input[data-field="vnstat_interface"]'),
    trafficCycleDay: item.querySelector('input[data-field="traffic_cycle_day"]'),
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
  if (fields.trafficQuota) {
    fields.trafficQuota.value = server.traffic_quota || "";
    fields.trafficQuota.readOnly = true;
  }
  if (fields.vnstatInterface) {
    fields.vnstatInterface.value = server.vnstat_interface || "";
    fields.vnstatInterface.readOnly = true;
  }
  if (fields.trafficCycleDay) {
    fields.trafficCycleDay.value = server.traffic_cycle_day || "";
    fields.trafficCycleDay.readOnly = true;
  }
  if (fields.description) fields.description.value = server.description || "";

  syncDerivedCommands();
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
      traffic_quota: getValue("traffic_quota"),
      vnstat_interface: getValue("vnstat_interface"),
      traffic_cycle_day: getValue("traffic_cycle_day"),
      description: getValue("description"),
    };
  });
}

function initConfigEditor() {
  const listEl = document.querySelector("#editor-list");
  const templateEl = document.querySelector("#server-editor-template");
  const saveBtn = document.querySelector("#save-servers-btn");
  const resultEl = document.querySelector("#config-result");
  const authUsernameEl = document.querySelector("#auth-username");
  const authPasswordEl = document.querySelector("#auth-password");
  if (!listEl || !templateEl || !saveBtn || !resultEl) return;

  const initial = initialServers.length
    ? initialServers
    : [{
      id: "",
      name: "",
      command_template: "",
      status_command_template: "",
      current_port: "",
      addr: "",
      trojan_password: "",
      traffic_quota: "",
      vnstat_interface: "",
      traffic_cycle_day: "",
      description: "",
    }];

  for (const server of initial) {
    const node = createEditorItem(server, templateEl);
    if (node) listEl.appendChild(node);
  }

  if (authUsernameEl) authUsernameEl.value = initialAuth.username || "";
  if (authPasswordEl) authPasswordEl.value = initialAuth.password || "";

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
  const expiryTrigger = document.querySelector("#sub-expiry-trigger");
  const expiryInput = document.querySelector("#sub-expiry-input");
  const expiryPopover = document.querySelector("#sub-expiry-popover");
  const expiryMonthLabel = document.querySelector("#sub-expiry-month-label");
  const expiryDaysEl = document.querySelector("#sub-expiry-days");
  const expiryHourEl = document.querySelector("#sub-expiry-hour");
  const expiryMinuteTrigger = document.querySelector("#sub-expiry-minute");
  const expiryMinuteWrap = document.querySelector("#sub-expiry-minute-wrap");
  const expiryMinutePanel = document.querySelector("#sub-expiry-minute-panel");
  const expiryMinuteOptionsEl = document.querySelector("#sub-expiry-minute-options");
  const expiryManualToggle = document.querySelector("#sub-expiry-manual-toggle");
  const expiryManualEditor = document.querySelector("#sub-expiry-manual-editor");
  const expiryManualInput = document.querySelector("#sub-expiry-manual-input");
  const expiryManualFillBtn = document.querySelector("#sub-expiry-manual-fill");
  const expiryManualFeedback = document.querySelector("#sub-expiry-manual-feedback");
  const expiryAdjustButtons = Array.from(document.querySelectorAll(".sub-expiry-stepper-btn"));
  const expiryApplyBtn = document.querySelector("#sub-expiry-apply");
  const expiryCancelBtn = document.querySelector("#sub-expiry-cancel");
  const expiryNavButtons = Array.from(document.querySelectorAll(".sub-expiry-nav"));
  const expiryHintEl = document.querySelector("#sub-expiry-hint");
  const expiryPresetButtons = Array.from(document.querySelectorAll(".sub-expiry-btn"));
  const resultEl = document.querySelector("#sub-result");
  if (!genBtn || !selectAllBtn || !clearBtn || !resultEl) return;

  let expiryMode = "permanent";
  let customExpiryDate = null;
  let pickerDraftDate = null;
  let pickerViewDate = roundUpToNextMinute();
  let removePickerOutsideListener = null;

  const setManualFeedback = (message, ok = false) => {
    if (!expiryManualFeedback) return;
    expiryManualFeedback.textContent = message;
    expiryManualFeedback.classList.toggle("is-success", ok);
    expiryManualFeedback.classList.toggle("is-error", !ok && Boolean(message) && !message.startsWith("支持格式"));
  };

  const syncManualInput = () => {
    if (!expiryManualInput) return;
    const sourceDate = pickerDraftDate || getActiveExpiryDate();
    expiryManualInput.value = sourceDate ? formatDateTimeDisplay(sourceDate) : "";
  };

  const setManualEditorOpen = (open) => {
    if (!expiryManualEditor || !expiryManualToggle) return;
    expiryManualEditor.hidden = !open;
    expiryManualToggle.setAttribute("aria-expanded", open ? "true" : "false");
    expiryManualToggle.textContent = open ? "收起编辑" : "点击编辑";
    if (open) {
      syncManualInput();
      setManualFeedback("支持格式：YYYY-MM-DD HH:mm");
    }
  };

  const getPresetDays = () => {
    if (expiryMode === "1d") return 1;
    if (expiryMode === "7d") return 7;
    if (expiryMode === "30d") return 30;
    return null;
  };

  const getActiveExpiryDate = () => {
    if (expiryMode === "custom" && customExpiryDate) {
      return cloneDate(customExpiryDate);
    }
    const presetDays = getPresetDays();
    if (presetDays) {
      return addDays(roundUpToNextMinute(), presetDays);
    }
    return customExpiryDate ? cloneDate(customExpiryDate) : addDays(roundUpToNextMinute(), 1);
  };

  const updateExpiryTrigger = () => {
    if (!expiryTrigger) return;
    let label = "点击选择时间";
    if (expiryMode === "custom" && customExpiryDate) {
      label = formatDateTimeDisplay(customExpiryDate);
      expiryTrigger.classList.remove("is-placeholder");
    } else if (expiryMode !== "permanent") {
      label = formatDateTimeDisplay(getActiveExpiryDate());
      expiryTrigger.classList.remove("is-placeholder");
    } else {
      expiryTrigger.classList.add("is-placeholder");
    }
    expiryTrigger.textContent = label;
  };

  const syncExpiryButtons = () => {
    for (const button of expiryPresetButtons) {
      button.classList.toggle("is-active", button.dataset.expiryMode === expiryMode);
    }
  };

  const updateExpiryHint = () => {
    if (!expiryHintEl) return;
    if (expiryMode === "permanent") {
      expiryHintEl.textContent = "当前设置：永久有效";
      return;
    }
    if (expiryMode === "custom") {
      if (!customExpiryDate) {
        expiryHintEl.textContent = "当前设置：请选择自定义有效期";
        return;
      }
      expiryHintEl.textContent = `当前设置：${formatSubscriptionExpiry(customExpiryDate, false)}`;
      return;
    }
    const presetDays = getPresetDays();
    if (!presetDays) {
      expiryHintEl.textContent = "当前设置：永久有效";
      return;
    }
    expiryHintEl.textContent = `当前设置：${formatSubscriptionExpiry(getActiveExpiryDate(), false)}`;
  };

  const setExpiryMode = (mode) => {
    expiryMode = mode;
    syncExpiryButtons();
    updateExpiryTrigger();
    updateExpiryHint();
  };

  const syncPickerTimeInputs = () => {
    if (!pickerDraftDate || !expiryHourEl || !expiryMinuteTrigger) return;
    expiryHourEl.textContent = String(pickerDraftDate.getHours()).padStart(2, "0");
    expiryMinuteTrigger.textContent = String(pickerDraftDate.getMinutes()).padStart(2, "0");
    syncManualInput();
  };

  const renderMinuteOptions = () => {
    if (!expiryMinuteOptionsEl) return;
    expiryMinuteOptionsEl.innerHTML = "";
    const activeDate = pickerDraftDate || getActiveExpiryDate();
    const activeMinute = activeDate ? activeDate.getMinutes() : 0;
    const applyMinuteSelection = (minute) => {
      const baseDate = pickerDraftDate ? cloneDate(pickerDraftDate) : getActiveExpiryDate();
      if (!baseDate) return;
      baseDate.setMinutes(minute);
      pickerDraftDate = baseDate;
      syncPickerTimeInputs();
      renderMinuteOptions();
      renderPickerCalendar();
      closeMinutePanel();
    };
    for (let minute = 0; minute < 60; minute += 1) {
      const option = document.createElement("div");
      option.className = "sub-expiry-minute-option";
      option.textContent = String(minute).padStart(2, "0");
      option.dataset.minuteValue = String(minute);
      option.setAttribute("role", "option");
      option.tabIndex = 0;
      option.setAttribute("aria-selected", minute === activeMinute ? "true" : "false");
      if (minute === activeMinute) option.classList.add("is-selected");
      option.addEventListener("click", () => applyMinuteSelection(minute));
      option.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        applyMinuteSelection(minute);
      });
      expiryMinuteOptionsEl.appendChild(option);
    }
  };

  const closeMinutePanel = () => {
    if (!expiryMinutePanel || !expiryMinuteTrigger || !expiryMinuteWrap) return;
    expiryMinutePanel.hidden = true;
    expiryMinuteTrigger.setAttribute("aria-expanded", "false");
    expiryMinuteWrap.classList.remove("is-open");
  };

  const openMinutePanel = () => {
    if (!expiryMinutePanel || !expiryMinuteTrigger || !expiryMinuteWrap) return;
    renderMinuteOptions();
    expiryMinutePanel.hidden = false;
    expiryMinuteTrigger.setAttribute("aria-expanded", "true");
    expiryMinuteWrap.classList.add("is-open");
    const selectedOption = expiryMinuteOptionsEl
      ? expiryMinuteOptionsEl.querySelector(".sub-expiry-minute-option.is-selected")
      : null;
    if (selectedOption instanceof HTMLElement) {
      selectedOption.scrollIntoView({ block: "nearest" });
    }
  };

  const renderPickerCalendar = () => {
    if (!expiryDaysEl || !expiryMonthLabel) return;
    expiryMonthLabel.textContent = monthLabel(pickerViewDate);
    expiryDaysEl.innerHTML = "";

    const firstOfMonth = buildLocalDate(pickerViewDate.getFullYear(), pickerViewDate.getMonth(), 1, 0, 0);
    const weekdayOffset = (firstOfMonth.getDay() + 6) % 7;
    const gridStart = buildLocalDate(pickerViewDate.getFullYear(), pickerViewDate.getMonth(), 1 - weekdayOffset, 0, 0);
    const minSelectableDate = roundUpToNextMinute();
    const applyDaySelection = (dayDate) => {
      const current = pickerDraftDate || getActiveExpiryDate();
      pickerDraftDate = buildLocalDate(
        dayDate.getFullYear(),
        dayDate.getMonth(),
        dayDate.getDate(),
        current.getHours(),
        current.getMinutes(),
      );
      syncPickerTimeInputs();
      renderMinuteOptions();
      renderPickerCalendar();
    };

    for (let index = 0; index < 42; index += 1) {
      const dayDate = addDays(gridStart, index);
      const dayCell = document.createElement("div");
      dayCell.className = "sub-expiry-day";
      dayCell.textContent = String(dayDate.getDate());
      dayCell.dataset.dayValue = toDateTimeLocalValue(dayDate);
      dayCell.setAttribute("role", "button");
      dayCell.tabIndex = 0;

      if (!isSameCalendarMonth(dayDate, pickerViewDate)) {
        dayCell.classList.add("is-outside");
      }
      if (pickerDraftDate && isSameCalendarDay(dayDate, pickerDraftDate)) {
        dayCell.classList.add("is-selected");
      }
      if (isSameCalendarDay(dayDate, new Date())) {
        dayCell.classList.add("is-today");
      }

      const dayEnd = buildLocalDate(dayDate.getFullYear(), dayDate.getMonth(), dayDate.getDate(), 23, 59);
      if (dayEnd.getTime() <= minSelectableDate.getTime()) {
        dayCell.classList.add("is-disabled");
        dayCell.tabIndex = -1;
        dayCell.setAttribute("aria-disabled", "true");
      } else {
        dayCell.addEventListener("click", () => applyDaySelection(dayDate));
        dayCell.addEventListener("keydown", (event) => {
          if (event.key !== "Enter" && event.key !== " ") return;
          event.preventDefault();
          applyDaySelection(dayDate);
        });
      }
      expiryDaysEl.appendChild(dayCell);
    }
  };

  const closePicker = () => {
    if (!expiryPopover || !expiryTrigger) return;
    closeMinutePanel();
    setManualEditorOpen(false);
    expiryPopover.hidden = true;
    expiryTrigger.setAttribute("aria-expanded", "false");
    if (typeof removePickerOutsideListener === "function") {
      removePickerOutsideListener();
      removePickerOutsideListener = null;
    }
  };

  const openPicker = () => {
    if (!expiryPopover || !expiryTrigger) return;
    const baseDate = getActiveExpiryDate();
    pickerDraftDate = cloneDate(baseDate) || addDays(roundUpToNextMinute(), 1);
    pickerViewDate = buildLocalDate(pickerDraftDate.getFullYear(), pickerDraftDate.getMonth(), 1, 0, 0);
    syncPickerTimeInputs();
    renderPickerCalendar();
    setManualEditorOpen(false);
    expiryPopover.hidden = false;
    expiryTrigger.setAttribute("aria-expanded", "true");
    if (typeof removePickerOutsideListener === "function") removePickerOutsideListener();
    const onDocumentClick = (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      if (
        expiryMinutePanel
        && !expiryMinutePanel.hidden
        && expiryMinuteWrap
        && !expiryMinuteWrap.contains(target)
      ) {
        closeMinutePanel();
      }
      if (expiryPopover.contains(target) || expiryTrigger.contains(target)) return;
      closePicker();
    };
    const onDocumentKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closePicker();
      }
    };
    document.addEventListener("mousedown", onDocumentClick);
    document.addEventListener("keydown", onDocumentKeydown);
    removePickerOutsideListener = () => {
      document.removeEventListener("mousedown", onDocumentClick);
      document.removeEventListener("keydown", onDocumentKeydown);
    };
  };

  const buildExpiryPayload = () => {
    if (expiryMode === "permanent") {
      return { value: null, error: "" };
    }
    if (expiryMode === "custom") {
      if (!customExpiryDate) {
        return { value: null, error: "请选择订阅有效期。" };
      }
      const customDate = cloneDate(customExpiryDate);
      if (!customDate) {
        return { value: null, error: "有效期时间格式无效。" };
      }
      if (customDate.getTime() <= Date.now()) {
        return { value: null, error: "订阅有效期必须晚于当前时间。" };
      }
      return { value: customDate.toISOString(), error: "" };
    }
    const presetDays = getPresetDays();
    if (!presetDays) {
      return { value: null, error: "" };
    }
    return { value: new Date(Date.now() + presetDays * 86400000).toISOString(), error: "" };
  };

  const applyManualInputToDraft = () => {
    if (!expiryManualInput) return false;
    const parsed = parseManualDateTimeInput(expiryManualInput.value);
    if (!parsed) {
      setManualFeedback("时间格式无效，请使用 YYYY-MM-DD HH:mm。");
      expiryManualInput.focus();
      return false;
    }
    if (parsed.getTime() <= Date.now()) {
      setManualFeedback("手动输入的有效期必须晚于当前时间。");
      expiryManualInput.focus();
      return false;
    }
    pickerDraftDate = parsed;
    pickerViewDate = buildLocalDate(parsed.getFullYear(), parsed.getMonth(), 1, 0, 0);
    syncPickerTimeInputs();
    renderMinuteOptions();
    renderPickerCalendar();
    setManualFeedback("已同步到时间组件。", true);
    return true;
  };

  for (const button of expiryPresetButtons) {
    button.addEventListener("click", () => {
      const mode = String(button.dataset.expiryMode || "").trim();
      if (!mode) return;
      setExpiryMode(mode);
      if (mode === "custom") openPicker();
    });
  }
  for (const adjustButton of expiryAdjustButtons) {
    adjustButton.addEventListener("click", () => {
      if (!pickerDraftDate) return;
      const rawAdjust = String(adjustButton.dataset.expiryAdjust || "").trim();
      const [unit, deltaValue] = rawAdjust.split(":");
      const delta = Number(deltaValue);
      if (!unit || !Number.isFinite(delta)) return;
      if (unit === "hour") {
        pickerDraftDate.setHours(pickerDraftDate.getHours() + delta);
      }
      syncPickerTimeInputs();
      renderPickerCalendar();
    });
  }
  renderMinuteOptions();
  if (expiryMinuteTrigger) {
    expiryMinuteTrigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (expiryMinutePanel && !expiryMinutePanel.hidden) {
        closeMinutePanel();
      } else {
        openMinutePanel();
      }
    });
  }
  if (expiryMinuteOptionsEl) {
    expiryMinuteOptionsEl.addEventListener("click", (event) => {
      event.stopPropagation();
    });
  }
  if (expiryManualToggle) {
    expiryManualToggle.addEventListener("click", () => {
      const shouldOpen = !expiryManualEditor || expiryManualEditor.hidden;
      setManualEditorOpen(shouldOpen);
      if (shouldOpen && expiryManualInput) expiryManualInput.focus();
    });
  }
  if (expiryManualFillBtn) {
    expiryManualFillBtn.addEventListener("click", () => {
      applyManualInputToDraft();
    });
  }
  if (expiryManualInput) {
    expiryManualInput.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      applyManualInputToDraft();
    });
  }
  for (const navButton of expiryNavButtons) {
    navButton.addEventListener("click", () => {
      const step = Number(navButton.dataset.expiryNav || "0");
      if (!Number.isInteger(step) || !pickerViewDate) return;
      pickerViewDate = buildLocalDate(pickerViewDate.getFullYear(), pickerViewDate.getMonth() + step, 1, 0, 0);
      renderPickerCalendar();
    });
  }
  if (expiryTrigger) {
    expiryTrigger.addEventListener("click", () => {
      if (expiryPopover && !expiryPopover.hidden) {
        closePicker();
      } else {
        openPicker();
      }
    });
  }
  if (expiryCancelBtn) {
    expiryCancelBtn.addEventListener("click", () => {
      closePicker();
    });
  }
  if (expiryApplyBtn) {
    expiryApplyBtn.addEventListener("click", () => {
      const candidate = cloneDate(pickerDraftDate);
      if (!candidate) {
        markResult(resultEl, false, "请选择订阅有效期。");
        return;
      }
      if (candidate.getTime() <= Date.now()) {
        markResult(resultEl, false, "订阅有效期必须晚于当前时间。");
        return;
      }
      customExpiryDate = candidate;
      if (expiryInput) expiryInput.value = toDateTimeLocalValue(candidate);
      setExpiryMode("custom");
      closePicker();
    });
  }
  setExpiryMode("permanent");

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
    const expiryPayload = buildExpiryPayload();
    if (expiryPayload.error) {
      markResult(resultEl, false, expiryPayload.error);
      return;
    }

    const restore = setButtonLoading(genBtn, "生成中...");
    markResult(resultEl, null, "正在生成订阅访问地址...");
    try {
      const resp = await fetch("/api/subscription-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ server_ids: selectedIds, token, expires_at: expiryPayload.value }),
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
    const orderedItems = sortSubscriptionsForDisplay(items);
    if (!orderedItems.length) {
      setListText("暂无已保存订阅。");
      return;
    }

    for (const item of orderedItems) {
      const token = typeof item.token === "string" ? item.token : "";
      if (!token) continue;
      const expired = Boolean(item.expired);
      const expiryState = typeof item.expiry_state === "string" ? item.expiry_state : "permanent";
      const serverIds = Array.isArray(item.server_ids) ? item.server_ids.filter((x) => typeof x === "string" && x) : [];
      const serverNames = Array.isArray(item.server_names) ? item.server_names.filter((x) => typeof x === "string" && x) : [];
      const missingIds = Array.isArray(item.missing_server_ids)
        ? item.missing_server_ids.filter((x) => typeof x === "string" && x)
        : [];

      const row = document.createElement("article");
      row.className = "sub-token-item";
      if (expired) row.classList.add("is-expired");

      const head = document.createElement("div");
      head.className = "sub-token-head";
      const tokenLine = document.createElement("p");
      tokenLine.className = "sub-token-token";
      tokenLine.textContent = token;
      head.appendChild(tokenLine);

      const stateBadge = document.createElement("span");
      stateBadge.className = `sub-token-badge is-${expiryState}`;
      if (expiryState === "expired") stateBadge.textContent = "已过期";
      else if (expiryState === "active") stateBadge.textContent = "生效中";
      else stateBadge.textContent = "永久有效";
      head.appendChild(stateBadge);
      row.appendChild(head);

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

      const expiryLine = document.createElement("p");
      expiryLine.className = "sub-token-meta";
      expiryLine.textContent = `有效期: ${formatSubscriptionExpiry(item.expires_at, expired)}`;
      row.appendChild(expiryLine);

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
      if (expired) {
        copyBtn.disabled = true;
        copyBtn.title = "订阅已过期，请重新生成";
      }
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
        const confirmed = await showThemeConfirm({
          title: "删除订阅",
          message: `确认删除订阅 "${token}" 吗？该操作不可撤销。`,
          confirmText: "确认删除",
          cancelText: "取消",
          danger: true,
        });
        if (!confirmed) return;
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
    const trafficBtn = card.querySelector(".traffic-btn");
    if (!serverId || !input || !submitBtn || !statusBtn || !networkBtn || !trafficBtn) return;

    const initial = initialServers.find((item) => item.id === serverId);
    if (initial) {
      applyRuntimeToCard(card, initial);
      applyTrafficToCard(card, initial);
    }
    setServerResult(card, {
      ok: null,
      summary: "等待操作...",
      details: "",
      title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 运行详情`,
    });

    card.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const detailTrigger = target.closest(".server-result-detail");
      if (detailTrigger) {
        openServerResultDialog(card);
        return;
      }
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
        setServerResult(card, {
          ok: false,
          summary: "端口必须是 1-65535 的整数",
          details: "端口必须是 1-65535 的整数",
          title: `${card.querySelector(".server-head h2")?.textContent || serverId} · 切换端口`,
        });
        return;
      }
      await switchPort(serverId, port, submitBtn, card);
    });

    statusBtn.addEventListener("click", async () => {
      await checkStatus(serverId, statusBtn, card);
    });

    networkBtn.addEventListener("click", async () => {
      await checkNetwork(serverId, networkBtn, card);
    });

    trafficBtn.addEventListener("click", async () => {
      await checkTraffic(serverId, trafficBtn, card);
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
