const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const TAB_TITLES = {
  overview: "Обзор",
  tests: "Активные проверки",
  lists: "Списки",
  regions: "Регионы",
  logs: "Логи",
  settings: "Настройки",
  maintenance: "Обслуживание",
};

const STATUS_LABELS = {
  queued: "в очереди",
  testing: "проверяется",
  provisioning: "создается сервер",
  approved: "подтверждено",
  ip_not_suitable: "IP не подходит",
  phone_tcp_unreachable: "IP не подходит",
  vless_failed: "VLESS ошибка",
  exit_ip_mismatch: "выходной IP не совпал",
  phone_failed: "ошибка телефона",
  provision_failed: "ошибка создания",
  manual_banned: "забанен вручную",
  rejected: "отклонено",
  error: "ошибка",
  deleted: "удалено",
};

const ACTION_LABELS = {
  finder_start: "поиск запущен",
  finder_stop: "поиск остановлен",
  full_auto_on: "авто включено",
  full_auto_off: "авто выключено",
  settings_preset: "шаблон настроек",
  settings_update: "настройки изменены",
  retry_existing_server: "повтор на готовом сервере",
  retry_blocked_region: "повтор заблокирован регионом",
  retry_provisioning: "повтор с созданием сервера",
  delete_ip: "IP удален",
  bulk_delete_ip_not_suitable: "массовое удаление неподходящих IP",
  bulk_retry_vless_failed: "массовый повтор VLESS-ошибок",
  bulk_mark_region_provision_failed: "регион помечен ошибкой создания",
  bulk_delete_old_provision_failed: "старые ошибки создания удалены",
  reconcile_dry_run: "проверка лишних серверов",
  reconcile_cleanup: "лишние серверы удалены",
  list_update: "список сохранен",
  auto_start_provisioning: "авто запустило создание серверов",
};

const state = {
  snapshot: null,
  tests: [],
  settings: [],
  currentTab: "overview",
  currentList: "ipwhitelist_safe_cidr.txt",
};

function esc(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  }[char]));
}

function statusText(status) {
  return STATUS_LABELS[status] || status || "-";
}

function actionText(action) {
  return ACTION_LABELS[action] || action || "-";
}

function yesNo(value) {
  return value ? "да" : "-";
}

function age(seconds) {
  if (seconds == null) return "-";
  if (seconds < 60) return `${seconds} сек`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} мин`;
  return `${Math.round(seconds / 3600)} ч`;
}

function timeText(timestamp) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString() : "-";
}

function swiftShieldClass(item = {}) {
  const status = String(item.status || "").toUpperCase();
  if (!item.enabled) return "warn";
  if (status === "ACTIVE") return "ok";
  if (["SHUTOFF", "SHELVED", "SHELVED_OFFLOADED"].includes(status)) return "warn";
  if (item.ok === false || status === "ERROR") return "bad";
  return status ? "warn" : "bad";
}

function setAlert(message = "") {
  const alert = $("#alert");
  alert.textContent = message;
  alert.classList.toggle("hidden", !message);
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, { cache: "no-store", ...options });
  const data = await response.json().catch(() => ({ ok: false, error: "bad json" }));
  if (!response.ok || data.ok === false) {
    throw new Error(data.error || String(response.status));
  }
  return data;
}

function postJson(url, body) {
  return apiJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function badgeClass(status) {
  if (["approved", "queued", "testing"].includes(status)) return "ok";
  if (["provisioning", "exit_ip_mismatch"].includes(status)) return "warn";
  if (status) return "bad";
  return "";
}

function activeCount(queue = {}) {
  return (queue.queued || 0) + (queue.testing || 0) + (queue.provisioning || 0);
}

function renderInfoRows(target, rows) {
  target.innerHTML = rows.map(([label, value]) => (
    `<div class="info-row"><span class="muted">${esc(label)}</span><strong>${value}</strong></div>`
  )).join("");
}

function renderSnapshot(data) {
  state.snapshot = data;
  state.tests = data.tests || [];

  const counts = data.counts || {};
  const finder = data.finder || {};
  const control = data.control || {};
  const queue = data.queue || {};
  const workers = data.workers || [];
  const metrics = data.metrics || {};
  const last24 = metrics.last24 || {};
  const swiftshield = data.swiftshield || {};
  const active = activeCount(queue);
  const online = workers.filter((worker) => worker.online).length;

  $("#updated").textContent = `обновлено: ${new Date((data.generated_at || 0) * 1000).toLocaleString()}`;
  $("#sideStatus").textContent = control.full_auto_mode ? "авто включено" : "ручной режим";
  $("#statFinder").innerHTML = finder.running ? '<span class="ok">работает</span>' : '<span class="warn">стоп</span>';
  $("#statFinderMeta").textContent = `регион: ${finder.current_region || "-"}, попытка: ${finder.current_attempt || 0}`;
  $("#statApproved").textContent = counts.approved || 0;
  $("#statApprovedMeta").textContent = `цель: ${counts.target || 0}, кандидаты: ${counts.candidates || 0}, бан: ${counts.banned || 0}`;
  $("#statActive").textContent = active;
  $("#navTests").textContent = active;
  $("#testsMeta").textContent = `в очереди ${queue.queued || 0}, проверяется ${queue.testing || 0}, создается ${queue.provisioning || 0}`;
  $("#statQueueMeta").textContent = `подтверждено ${queue.approved || 0}, ошибка создания ${queue.provision_failed || 0}`;
  $("#statPhones").textContent = workers.length;
  $("#statPhonesMeta").textContent = `${online} на связи`;
  $("#statSwiftShield").innerHTML = `<span class="${swiftShieldClass(swiftshield)}">${esc(swiftshield.status || (swiftshield.enabled ? "unknown" : "off"))}</span>`;
  $("#statSwiftShieldMeta").textContent = `запуск: ${timeText(swiftshield.last_launch_at)}`;

  $("#finderStartBtn").disabled = Boolean(finder.running || control.full_auto_mode);
  $("#finderStopBtn").disabled = Boolean(!finder.running && !control.full_auto_mode);
  $("#autoModeBtn").dataset.enabled = control.full_auto_mode ? "1" : "0";
  $("#autoModeBtn").textContent = control.full_auto_mode ? "Выключить авто" : "Включить авто";
  $("#autoModeBtn").className = control.full_auto_mode ? "danger" : "secondary";

  renderInfoRows($("#statePanel"), [
    ["Авто-режим", `<span class="${control.full_auto_mode ? "ok" : "warn"}">${control.full_auto_mode ? "включен" : "выключен"}</span>`],
    ["Проверки телефоном", `<span class="${control.testing_paused ? "warn" : "ok"}">${control.testing_paused ? "пауза" : "работают"}</span>`],
    ["Создание серверов", `<span class="${control.provisioning_paused ? "warn" : "ok"}">${control.provisioning_paused ? "пауза" : (data.provisioning?.state === "running" ? "работает" : "ожидает")}</span>`],
    ["Последний IP", `<code>${esc(finder.last_ip || "-")}</code>`],
    ["Регионы", esc((finder.selected_regions || []).join(", ") || "-")],
    ["Последняя ошибка", `<span class="bad">${esc(finder.last_error || "-")}</span>`],
    ["SwiftShield статус", `<span class="${swiftShieldClass(swiftshield)}">${esc(swiftshield.status || (swiftshield.enabled ? "unknown" : "off"))}</span>`],
    ["SwiftShield последний запуск", esc(timeText(swiftshield.last_launch_at))],
    ["SwiftShield последняя проверка", esc(timeText(swiftshield.last_check_at))],
  ]);

  renderInfoRows($("#metricsPanel"), [
    ["За 24 ч подтверждено", `<span class="ok">${last24.approved || 0}</span>`],
    ["За 24 ч IP не подходит", `<span class="warn">${last24.ip_not_suitable_total || 0}</span>`],
    ["За 24 ч VLESS ошибка", `<span class="bad">${last24.vless_failed || 0}</span>`],
    ["Средняя задержка рабочих ключей", `${metrics.avg_approved_latency_ms || "-"} мс`],
  ]);

  renderWorkers(workers);
  renderAudit(data.audit || []);
  renderTests(state.tests);
  renderRegions(data.regions || []);
  renderLogs(data);
  renderBulkRegions(data.regions || []);
}

function renderWorkers(workers) {
  $("#workersPanel").innerHTML = workers.length ? workers.map((worker) => `
    <div class="stack-item">
      <span class="badge ${worker.online ? "ok" : "bad"}">${worker.online ? "на связи" : "нет связи"}</span>
      <strong>${esc(worker.worker)}</strong>
      <div class="muted">последний сигнал: ${age(worker.age_seconds)}, управление=${worker.control_ok ? "OK" : "нет"}, API=${worker.api_ok ? "OK" : "нет"}</div>
      <div class="muted">задача: ${esc(worker.current_task || "-")}</div>
      ${worker.last_error ? `<div class="bad">${esc(worker.last_error)}</div>` : ""}
    </div>
  `).join("") : '<div class="muted">нет сигнала от телефона</div>';
}

function renderAudit(events) {
  $("#auditPanel").innerHTML = events.length ? events.map((event) => `
    <div class="audit-item">
      <span class="badge">${esc(actionText(event.action))}</span>
      <span class="muted">${new Date((event.created_at || 0) * 1000).toLocaleString()}</span>
      <div>${esc(event.target || "")}</div>
      <div class="muted">${esc(event.details || "")}</div>
    </div>
  `).join("") : '<div class="muted">пока нет изменений</div>';
}

function isIpNotSuitable(status) {
  return ["ip_not_suitable", "phone_tcp_unreachable"].includes(status);
}

function canAct(status) {
  return ["ip_not_suitable", "phone_tcp_unreachable", "vless_failed", "exit_ip_mismatch", "phone_failed", "provision_failed", "rejected", "error"].includes(status);
}

function diagnosticHtml(test) {
  const raw = esc(test.error || "");
  if (isIpNotSuitable(test.status)) {
    return `<strong class="warn">IP не подходит</strong>${raw ? `<br><span class="muted">${raw}</span>` : ""}`;
  }
  return raw || "-";
}

function vlessHtml(test) {
  if (!test.vless_key) return "-";
  return `
    <div class="vless-key">
      <code>${esc(test.vless_key)}</code>
      <button class="secondary" data-copy-vless="${Number(test.id)}">Копировать</button>
    </div>
  `;
}

function actionButtons(test) {
  if (!canAct(test.status)) return "";
  const deleteLabel = isIpNotSuitable(test.status) ? "Отклонить IP" : "Удалить IP";
  return `
    <button class="secondary" data-test-action="retry" data-id="${Number(test.id)}">Повторить</button>
    <button class="danger" data-test-action="delete" data-id="${Number(test.id)}">${deleteLabel}</button>
  `;
}

function renderTests(tests) {
  $("#testsTable").innerHTML = tests.length ? tests.map((test) => `
    <tr>
      <td>${Number(test.id)}</td>
      <td><code>${esc(test.ip)}</code></td>
      <td>${esc(test.region)}</td>
      <td><span class="badge ${badgeClass(test.status)}">${esc(statusText(test.display_status || test.status))}</span></td>
      <td>${test.attempts || 0}</td>
      <td>${esc(test.worker || "-")}</td>
      <td>${esc(test.exit_ip || "-")}</td>
      <td>${esc(test.latency_ms || "-")}</td>
      <td>${vlessHtml(test)}</td>
      <td>${diagnosticHtml(test)}</td>
      <td>${actionButtons(test)}</td>
    </tr>
  `).join("") : '<tr><td colspan="11" class="muted">активных проверок нет</td></tr>';
}

function renderRegions(regions) {
  $("#regionsTable").innerHTML = regions.map((region) => {
    const statuses = region.statuses || {};
    return `
      <tr>
        <td><code>${esc(region.region)}</code></td>
        <td>${yesNo(region.selected)}</td>
        <td>${yesNo(region.preemptible)}</td>
        <td><span class="${region.can_provision ? "ok" : "bad"}">${region.can_provision ? "да" : "нет"}</span></td>
        <td>${region.good_ips || 0}</td>
        <td>${region.approved_keys || 0}</td>
        <td>${statuses.ip_not_suitable_total || 0}</td>
        <td>${statuses.vless_failed || 0}</td>
        <td>${statuses.provision_failed || 0}</td>
        <td>${region.success_rate == null ? "-" : `${region.success_rate}%`}</td>
        <td class="bad">${esc(region.last_error || "")}</td>
      </tr>
    `;
  }).join("");
}

function renderLogs(data) {
  const workers = data.workers || [];
  const lastWorker = workers[0];
  $("#phoneLog").textContent = lastWorker?.log_tail || "Пока нет логов телефона. Обнови termux_vless_tester.py до dashboard-версии.";
  $("#finderLog").textContent = data.logs?.finder || "лог пуст";
}

function renderBulkRegions(regions) {
  const select = $("#bulkRegion");
  const current = select.value;
  select.innerHTML = regions.map((region) => `<option value="${esc(region.region)}">${esc(region.region)}</option>`).join("");
  if (current) select.value = current;
}

async function loadSnapshot() {
  try {
    const data = await apiJson("/dashboard/api/status");
    setAlert("");
    renderSnapshot(data);
  } catch (error) {
    setAlert(`Ошибка загрузки дашборда: ${error.message}`);
  }
}

async function finderControl(action) {
  if (action === "start" && !confirm("Запустить поиск IP?")) return;
  if (action === "auto_toggle") {
    const enabled = $("#autoModeBtn").dataset.enabled === "1";
    const text = enabled
      ? "Выключить полный авто-режим?"
      : "Включить полный авто-режим? Он будет сам искать IP, запускать серверы и продолжать цикл после проверок.";
    if (!confirm(text)) return;
  }
  try {
    await postJson("/dashboard/api/finder_control", { action });
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

async function testAction(action, id) {
  const label = action === "delete" ? "удалить IP, сервер/Floating IP и добавить в бан" : "повторить проверку";
  if (!confirm(`ID ${id}: ${label}?`)) return;
  try {
    await postJson("/dashboard/api/action", { action, id });
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const temp = document.createElement("textarea");
  temp.value = text;
  document.body.appendChild(temp);
  temp.select();
  document.execCommand("copy");
  temp.remove();
}

function findTest(id) {
  return state.tests.find((test) => Number(test.id) === Number(id));
}

async function loadList() {
  const name = $("#listName").value;
  state.currentList = name;
  $("#listDownloadBtn").href = `/dashboard/api/list_download?name=${encodeURIComponent(name)}`;
  try {
    const data = await apiJson(`/dashboard/api/list?name=${encodeURIComponent(name)}`);
    $("#listEditor").value = data.content || "";
    const updated = data.updated_at ? new Date(data.updated_at * 1000).toLocaleString() : "файл еще не создан";
    $("#listMeta").textContent = `${data.title}: строк ${data.lines || 0}, байт ${data.bytes || 0}, обновлено: ${updated}`;
  } catch (error) {
    $("#listMeta").textContent = `ошибка загрузки: ${error.message}`;
  }
}

async function saveListContent(content) {
  try {
    const data = await postJson("/dashboard/api/list", { name: $("#listName").value, content });
    $("#listEditor").value = data.content || "";
    $("#listMeta").textContent = `${data.title}: сохранено, строк ${data.lines || 0}, байт ${data.bytes || 0}`;
    await loadSnapshot();
    return true;
  } catch (error) {
    alert(`Ошибка сохранения списка: ${error.message}`);
    return false;
  }
}

function inputHtml(setting) {
  if (setting.kind === "bool") {
    return `<label class="bool-label"><input type="checkbox" id="setting_${setting.key}" ${setting.value ? "checked" : ""}> включено</label>`;
  }
  if (setting.kind === "regions") {
    return `<div class="check-list">${(setting.choices || []).map((region) => `
      <label><input type="checkbox" data-setting="${setting.key}" value="${esc(region)}" ${(setting.value || []).includes(region) ? "checked" : ""}>${esc(region)}</label>
    `).join("")}</div>`;
  }
  return `<input type="number" id="setting_${setting.key}" value="${esc(setting.value)}" min="${esc(setting.min ?? "")}" max="${esc(setting.max ?? "")}">`;
}

function renderSettings() {
  const groups = {};
  for (const setting of state.settings) {
    (groups[setting.group] ||= []).push(setting);
  }
  $("#settingsRoot").innerHTML = Object.entries(groups).map(([group, items]) => `
    <section class="setting-group">
      <h3>${esc(group)}</h3>
      ${items.map((setting) => `
        <div class="setting-row">
          <div>
            <div class="setting-label">${esc(setting.label)}</div>
            <div class="setting-key">${esc(setting.key)}</div>
          </div>
          <div>
            ${inputHtml(setting)}
            <div class="muted">из .env/по умолчанию: ${Array.isArray(setting.default) ? esc(setting.default.join(", ")) : esc(setting.default)}</div>
          </div>
          <div>
            <span class="badge ${setting.overridden ? "warn" : ""}">${setting.overridden ? "из дашборда" : ".env"}</span>
            <button class="secondary" data-reset-setting="${esc(setting.key)}">Сброс</button>
          </div>
        </div>
      `).join("")}
    </section>
  `).join("");
}

function collectSettingValue(setting) {
  if (setting.kind === "bool") return $(`#setting_${setting.key}`).checked;
  if (setting.kind === "regions") {
    return $$(`[data-setting="${setting.key}"]:checked`).map((input) => input.value);
  }
  return Number($(`#setting_${setting.key}`).value);
}

async function loadSettings() {
  try {
    const data = await apiJson("/dashboard/api/settings");
    state.settings = data.settings || [];
    $("#settingsStatus").textContent = `обновлено: ${new Date((data.generated_at || 0) * 1000).toLocaleString()}`;
    renderSettings();
  } catch (error) {
    $("#settingsStatus").textContent = `ошибка: ${error.message}`;
  }
}

async function saveSettings() {
  const values = {};
  for (const setting of state.settings) {
    values[setting.key] = collectSettingValue(setting);
  }
  try {
    const data = await postJson("/dashboard/api/settings", { values });
    state.settings = data.settings || [];
    $("#settingsStatus").textContent = `сохранено: ${new Date().toLocaleString()}`;
    renderSettings();
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

async function resetSetting(key) {
  try {
    const data = await postJson("/dashboard/api/settings", { reset: [key] });
    state.settings = data.settings || [];
    $("#settingsStatus").textContent = `сброшено: ${key}`;
    renderSettings();
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

async function applyPreset(preset) {
  if (!confirm(`Применить шаблон: ${preset}?`)) return;
  try {
    const data = await postJson("/dashboard/api/settings", { preset });
    state.settings = data.settings || [];
    $("#settingsStatus").textContent = `шаблон применен: ${preset}`;
    renderSettings();
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

async function bulkAction(action) {
  const payload = { action, limit: 100 };
  if (action === "mark_region_provision_failed") payload.region = $("#bulkRegion").value;
  if (action === "delete_old_provision_failed") payload.days = Number($("#oldDays").value || 7);
  const destructive = ["delete_ip_not_suitable", "delete_old_provision_failed", "cleanup_stale_temp_servers"].includes(action);
  if (destructive && !confirm(`Запустить массовое действие: ${action}?`)) return;
  try {
    const data = await postJson("/dashboard/api/bulk_action", payload);
    $("#bulkResult").textContent = JSON.stringify(data.result || { count: data.count, errors: data.errors || [] }).slice(0, 900);
    await loadSnapshot();
  } catch (error) {
    alert(`Ошибка: ${error.message}`);
  }
}

function activateTab(tab, pushHash = true) {
  state.currentTab = tab;
  $("#pageTitle").textContent = TAB_TITLES[tab] || "Обзор";
  $$(".nav button").forEach((button) => button.classList.toggle("active", button.dataset.tab === tab));
  $$("[data-view]").forEach((view) => view.classList.toggle("active", view.dataset.view === tab));
  if (pushHash) history.replaceState(null, "", `#${tab}`);
  if (tab === "settings" && !state.settings.length) loadSettings();
  if (tab === "lists" && !$("#listEditor").value) loadList();
}

function bindEvents() {
  $$(".nav button").forEach((button) => {
    button.addEventListener("click", () => activateTab(button.dataset.tab));
  });
  $("#refreshBtn").addEventListener("click", loadSnapshot);
  $("#finderStartBtn").addEventListener("click", () => finderControl("start"));
  $("#finderStopBtn").addEventListener("click", () => finderControl("stop"));
  $("#autoModeBtn").addEventListener("click", () => finderControl("auto_toggle"));

  $("#testsTable").addEventListener("click", async (event) => {
    const actionButton = event.target.closest("[data-test-action]");
    if (actionButton) {
      await testAction(actionButton.dataset.testAction, Number(actionButton.dataset.id));
      return;
    }
    const copyButton = event.target.closest("[data-copy-vless]");
    if (copyButton) {
      const test = findTest(copyButton.dataset.copyVless);
      if (test?.vless_key) await copyText(test.vless_key);
    }
  });

  $("#listName").addEventListener("change", loadList);
  $("#listOpenBtn").addEventListener("click", loadList);
  $("#listSaveBtn").addEventListener("click", () => saveListContent($("#listEditor").value));
  $("#listUpload").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!confirm(`Заменить ${$("#listName").value} содержимым файла ${file.name}?`)) {
      event.target.value = "";
      return;
    }
    await saveListContent(await file.text());
    event.target.value = "";
  });

  $("#settingsSaveBtn").addEventListener("click", saveSettings);
  $("#settingsReloadBtn").addEventListener("click", loadSettings);
  $("#settingsRoot").addEventListener("click", (event) => {
    const button = event.target.closest("[data-reset-setting]");
    if (button) resetSetting(button.dataset.resetSetting);
  });
  $$("[data-preset]").forEach((button) => {
    button.addEventListener("click", () => applyPreset(button.dataset.preset));
  });

  $("#bulkDeleteBad").addEventListener("click", () => bulkAction("delete_ip_not_suitable"));
  $("#bulkRetryVless").addEventListener("click", () => bulkAction("retry_vless_failed"));
  $("#bulkRegionFailed").addEventListener("click", () => bulkAction("mark_region_provision_failed"));
  $("#bulkDeleteOld").addEventListener("click", () => bulkAction("delete_old_provision_failed"));
  $("#bulkDryRun").addEventListener("click", () => bulkAction("reconcile_dry_run"));
  $("#bulkCleanup").addEventListener("click", () => bulkAction("cleanup_stale_temp_servers"));
}

function initialTab() {
  if (location.pathname.endsWith("/settings")) return "settings";
  const hash = location.hash.replace("#", "");
  return TAB_TITLES[hash] ? hash : "overview";
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  activateTab(initialTab(), false);
  await Promise.all([loadSnapshot(), loadList()]);
  if (state.currentTab === "settings") await loadSettings();
  setInterval(loadSnapshot, 10000);
});
