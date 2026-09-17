const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let sessionToken = "";
let ports = [];
let rawPorts = [];
let projects = [];
let protocolFilter = "";
let activeView = "ports";
let refreshing = false;
const inFlightProjectActions = new Map();
const startingTimestamps = new Map();

const pageTitles = {
  ports: "我的项目端口",
  projects: "项目控制",
  activity: "操作记录",
};

const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
}[char]));

function toast(message, isError = false) {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast show${isError ? " error" : ""}`;
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => { element.className = "toast"; }, 3600);
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method === "POST") headers["X-Port-Console-Token"] = sessionToken;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function setConnection(ok) {
  $("#connectionDot").classList.toggle("ok", ok);
  $("#connectionText").textContent = ok ? "本机服务正常" : "本机服务连接异常";
}

function formatTime(value) {
  if (!value) return "暂无时间";
  try { return new Date(value).toLocaleString("zh-CN", { hour12: false }); }
  catch { return value; }
}

function formatPath(value) {
  if (!value) return "系统未提供路径";
  return value;
}

function renderMetrics() {
  $("#tcpMetric").textContent = projects.length;
  $("#udpMetric").textContent = projects.filter((item) => item.state === "running").length;
  $("#uniqueMetric").textContent = ports.length;
  $("#publicMetric").textContent = ports.filter((item) => item.scope === "all").length;
  $("#processMetric").textContent = projects.filter((item) => item.state !== "running").length;
}

function buildProjectPorts() {
  const entries = [];
  for (const project of projects) {
    if (project.enabled === false) continue;
    if (project.lifecycle === "archive_candidate" && project.state !== "running") continue;
    if (project.state === "missing") continue;
    const allPorts = [...project.expected_ports];
    if (project.discovered_ports) {
      for (const p of project.discovered_ports) {
        if (!allPorts.includes(p)) allPorts.push(p);
      }
    }
    for (const port of allPorts) {
      const candidates = rawPorts.filter((row) => row.protocol === "TCP" && row.port === port);
      const live = candidates.find((row) => row.scope === "loopback") || candidates[0];
      const isDrift = project.discovered_ports && project.discovered_ports.includes(port) && !project.expected_ports.includes(port);
      entries.push({
        ...(live || { protocol: "TCP", port, address: "—", pid: 0, process: "未启动", executable: "", services: [] }),
        project,
        project_state: live ? "running" : "stopped",
        scope: live?.scope || "stopped",
        scope_label: live ? (live.scope === "loopback" ? "只有本机" : live.scope === "all" ? "本机与局域网" : "指定网卡") : "尚未启动",
        function: (isDrift ? "【检测到端口漂移 · 运行时已动态生效】" : "") + (project.description || "这是你登记的本机项目。"),
        url: (isDrift && project.effective_url) ? project.effective_url : (project.url || live?.url || ""),
        is_drift: isDrift,
      });
    }
  }
  return entries;
}

function filteredPorts() {
  const query = $("#portSearch").value.trim().toLowerCase();
  const scope = $("#scopeFilter").value;
  return ports.filter((row) => {
    if (protocolFilter && row.project_state !== protocolFilter) return false;
    if (scope && row.scope !== scope) return false;
    if (!query) return true;
    const services = (row.services || []).map((service) => `${service.name} ${service.display_name}`).join(" ");
    const haystack = `${row.port} ${row.project.name} ${row.project.tags.join(" ")} ${row.address} ${row.process} ${row.function} ${services}`.toLowerCase();
    return haystack.includes(query);
  });
}

function serviceBadges(row) {
  if (!row.services?.length) return "";
  return row.services.slice(0, 2).map((service) => `<span class="mini-badge">${escapeHtml(service.name)}</span>`).join("");
}

function renderPorts() {
  const rows = filteredPorts();
  $("#resultCount").textContent = `${rows.length} 条`;
  const body = $("#portsBody");
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-cell">没有匹配的端口</td></tr>';
    return;
  }
  body.innerHTML = rows.map((row, index) => `
    <tr class="port-row" data-index="${ports.indexOf(row)}">
      <td>
        <div class="port-main"><span class="protocol protocol-${row.project_state === "running" ? "tcp" : "udp"}">${row.project_state === "running" ? "运行" : "待启"}</span><strong>${row.port}</strong></div>
        <span class="muted">${escapeHtml(row.project.name)}</span>
      </td>
      <td><span class="scope scope-${row.scope}">${escapeHtml(row.scope_label)}</span></td>
      <td>
        <strong class="process-name">${escapeHtml(row.project.process_label || row.process)}</strong>
        <span class="muted">PID ${row.pid || "—"}</span>
        <div class="mini-badges">${serviceBadges(row)}</div>
      </td>
      <td>
        <span>${escapeHtml(row.function)}</span>
        <small class="evidence">来自项目登记信息</small>
      </td>
      <td><span class="live-state"><i></i>${row.project_state === "running" ? "可以使用" : "尚未启动"}</span></td>
      <td class="row-actions">
        ${row.url ? `<a class="icon-link" href="${escapeHtml(row.url)}" target="_blank" rel="noreferrer" title="打开 ${escapeHtml(row.url)}">↗</a>` : ""}
        <button class="icon-button detail-button" type="button" data-index="${ports.indexOf(row)}" title="查看详情">···</button>
      </td>
    </tr>`).join("");
  $$(".detail-button").forEach((button) => button.addEventListener("click", () => showPortDetail(ports[Number(button.dataset.index)])));
}

function showPortDetail(row) {
  $("#detailTitle").textContent = `${row.project.name} · ${row.port}`;
  $("#detailContent").innerHTML = `
    <dl>
      <div><dt>用途</dt><dd>${escapeHtml(row.function)}</dd></div>
      <div><dt>端口</dt><dd class="mono">${row.port}</dd></div>
      <div><dt>谁能访问</dt><dd>${escapeHtml(row.scope_label)}</dd></div>
      <div><dt>当前状态</dt><dd>${row.project_state === "running" ? "正在运行，可以使用" : "尚未启动"}</dd></div>
      <div><dt>运行程序</dt><dd>${escapeHtml(row.project.process_label || row.process)}${row.pid ? ` · PID ${row.pid}` : ""}</dd></div>
      <div><dt>项目目录</dt><dd class="path-value">${escapeHtml(row.project.working_directory)}</dd></div>
      <div><dt>打开页面</dt><dd>${row.url ? `<a href="${escapeHtml(row.url)}" target="_blank" rel="noreferrer">${escapeHtml(row.url)}</a>` : "这个项目没有网页入口"}</dd></div>
    </dl>`;
  $("#detailDialog").showModal();
}

async function loadPorts(force = false) {
  const data = await api(`/api/ports${force ? "?refresh=1" : ""}`);
  rawPorts = data.items;
  $("#updatedAt").textContent = `${formatTime(data.generated_at)} · ${data.duration_ms} ms`;
}

function projectMatches(project) {
  const query = $("#projectSearch").value.trim().toLowerCase();
  if (!query) return true;
  return `${project.name} ${project.description} ${project.id} ${project.expected_ports.join(" ")} ${project.tags.join(" ")}`.toLowerCase().includes(query);
}

function typeLabel(type) {
  return { command: "本机命令", "docker-compose": "Docker Compose", "windows-service": "Windows 服务" }[type] || type;
}

function stateLabel(project) {
  if (project.enabled === false) return "已归档";
  if (project.state === "missing") return "目录失效";
  if (project.port_drift && project.state === "running") {
    return `运行中 (${project.effective_port || project.discovered_ports?.[0] || "新端口"})`;
  }
  if (project.port_drift) return "端口漂移";
  return { running: "运行中", starting: "启动中", stopped: "已停止", unknown: "待检测" }[project.state] || project.state;
}

function renderProjects() {
  const rows = projects.filter(projectMatches);
  const activeRows = rows.filter((project) => project.enabled !== false);
  const archivedRows = rows.filter((project) => project.enabled === false);
  $("#projectCount").textContent = `${activeRows.length} 个活动项目${archivedRows.length ? ` · ${archivedRows.length} 个已归档` : ""}`;
  const grid = $("#projectGrid");
  if (!rows.length) {
    grid.innerHTML = '<div class="empty-card">没有登记项目。把 port-console.project.json 放进项目目录后刷新即可。</div>';
    return;
  }
  const renderCard = (project) => {
    const inFlight = inFlightProjectActions.get(project.id);
    const isStarting = project.state === "starting" || inFlight === "start";
    const sLabel = stateLabel({ ...project, state: isStarting ? "starting" : project.state });
    const sClass = (project.enabled === false)
      ? "state-archived"
      : (project.state === "running" ? "state-running" : ((project.port_drift || isStarting) ? "state-starting" : `state-${project.state}`));
    const isAtlas = project.id === "port-atlas";
    const targetUrl = project.effective_url || project.url;
    const canStart = Boolean(project.can_start && !inFlight);
    const canStop = Boolean(project.can_stop && inFlight !== "stop");
    const startText = project.enabled === false
      ? "已归档"
      : (project.state === "running" ? "正在运行" : (isStarting ? "启动中…" : "启动项目"));
    const stopText = inFlight === "stop" ? "停止中…" : "停止";
    return `
    <article class="project-card ${project.state} ${project.enabled === false ? 'archived' : ''}">
      <div class="project-card-head">
        <div class="project-icon">${escapeHtml(project.name.slice(0, 1).toUpperCase())}</div>
        <div>
          <h3>${escapeHtml(project.name)}</h3>
          <span class="project-type">${escapeHtml(typeLabel(project.type))}</span>
        </div>
        <span class="project-state ${sClass}"><i></i>${escapeHtml(sLabel)}</span>
      </div>
      <p>${escapeHtml(project.description || "未填写项目说明")}</p>
      ${project.port_drift && project.discovered_ports?.length ? `
        <div class="drift-alert">
          🟢 实际监听端口 [${project.discovered_ports.join(", ")}] 已动态生效（原配置端口: ${project.expected_ports.join(", ")}）
          <span class="drift-hint">服务已正常运行，无需同步即可使用；亦可一键保存为默认配置</span>
        </div>` : ''}
      ${project.path_exists === false ? `<div class="missing-alert">❌ 项目目录不存在：${escapeHtml(project.working_directory)}</div>` : ''}
      ${project.last_crash ? `
        <div class="crash-alert">
          <div class="crash-title">⚠️ ${escapeHtml(project.last_crash.summary || "启动异常退出")}</div>
          <div class="crash-desc">${escapeHtml(project.last_crash.suggestion || "")}</div>
          ${project.last_crash.can_auto_repair ? `
            <div class="crash-action">
              <button class="button button-warn btn-sm project-repair" type="button" data-id="${escapeHtml(project.id)}" data-pkg="${escapeHtml(project.last_crash.package || "")}">🛠️ 一键自动修复依赖 (${escapeHtml(project.last_crash.package || "缺失模块")})</button>
            </div>` : ''}
        </div>` : ''}
      <div class="project-meta">
        <span>配置端口 ${project.expected_ports.length ? project.expected_ports.join(", ") : "未指定"}${project.port_drift && project.effective_port ? ` · 实际生效: ${project.effective_port}` : ''}</span>
        <span title="${escapeHtml(project.working_directory)}">${escapeHtml(project.working_directory)}</span>
      </div>
      <div class="tag-row">${project.tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>
      <div class="project-actions">
        ${targetUrl && project.enabled !== false ? `<a class="button button-ghost" href="${escapeHtml(targetUrl)}" target="_blank" rel="noreferrer">打开页面 ↗</a>` : ""}
        <button class="button button-primary project-start" type="button" data-id="${escapeHtml(project.id)}" ${canStart ? "" : "disabled"}>${escapeHtml(startText)}</button>
        <button class="button button-danger project-stop" type="button" data-id="${escapeHtml(project.id)}" title="${escapeHtml(project.stop_reason || '停止这个项目')}" ${canStop ? "" : "disabled"}>${escapeHtml(stopText)}</button>
        ${project.port_drift && project.discovered_ports?.length ? `<button class="button button-warn project-sync-port" type="button" data-id="${escapeHtml(project.id)}" data-port="${project.discovered_ports[0]}">保存为默认端口 (${project.discovered_ports[0]})</button>` : ''}
        ${!isAtlas ? (project.enabled === false
          ? `<button class="button button-ghost project-restore" type="button" data-id="${escapeHtml(project.id)}">恢复</button>
             <button class="button button-danger project-delete" type="button" data-id="${escapeHtml(project.id)}" data-name="${escapeHtml(project.name)}" title="从配置文件中彻底删除">删除配置</button>`
          : `<button class="button button-ghost project-archive" type="button" data-id="${escapeHtml(project.id)}" title="归档此项目">归档</button>`) : ''}
      </div>
      ${project.stop_reason && (project.state === 'running' || project.state === 'starting') ? `<p class="stop-reason">${escapeHtml(project.stop_reason)}</p>` : ''}
    </article>`;
  };
  let html = activeRows.map(renderCard).join("");
  if (archivedRows.length) {
    html += `
    <div class="archived-divider-card">
      <div class="archived-divider-title">
        <span>📦 已归档项目 (${archivedRows.length})</span>
        <span class="archived-hint">已结案、停用或合流的项目在此归档保存，不干扰日常活跃视线，可随时恢复</span>
      </div>
    </div>
    ` + archivedRows.map(renderCard).join("");
  }
  grid.innerHTML = html;
  $$(".project-start").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "start", button)));
  $$(".project-stop").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "stop", button)));
  $$(".project-sync-port").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "sync-port", button, { port: Number(button.dataset.port) })));
  $$(".project-archive").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "archive", button)));
  $$(".project-restore").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "restore", button)));
  $$(".project-delete").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "delete", button)));
  $$(".project-repair").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "repair", button, { package: button.dataset.pkg })));
}

function renderCapabilities(capabilities = {}) {
  const labels = [
    ["PowerShell", capabilities.powershell],
    ["Docker", capabilities.docker],
    ["Process Compose", capabilities.process_compose],
  ];
  $("#capabilityBadges").innerHTML = labels.map(([name, ok]) => `<span class="capability ${ok ? "available" : "missing"}"><i></i>${name} ${ok ? "可用" : "未安装"}</span>`).join("");
}

async function loadProjects() {
  const data = await api("/api/projects");
  const now = Date.now();
  projects = data.items.map((item) => {
    const inFlight = inFlightProjectActions.get(item.id);
    if (inFlight === "start" && item.state !== "running") {
      return { ...item, state: "starting", can_start: false };
    }
    if (item.state === "starting") {
      const startTime = startingTimestamps.get(item.id);
      if (!startTime || (now - startTime > 15000)) {
        startingTimestamps.delete(item.id);
        return { ...item, state: "stopped", can_start: true };
      }
    } else if (item.state === "running" || item.state === "stopped") {
      startingTimestamps.delete(item.id);
    }
    return item;
  });
  renderCapabilities(data.capabilities);
  const errors = $("#projectErrors");
  if (data.errors.length) {
    errors.textContent = data.errors.join("；");
    errors.classList.remove("hidden");
  } else {
    errors.classList.add("hidden");
  }
  renderProjects();
}

async function runProjectAction(projectId, action, button, extraPayload = {}) {
  const project = projects.find((item) => item.id === projectId);
  if (!project) return;
  if (action === "stop" && !window.confirm(`确定停止“${project.name}”吗？`)) return;
  if (action === "archive" && !window.confirm(`确定归档“${project.name}”吗？归档后不再出现在活动端口列表中。`)) return;
  if (action === "delete" && !window.confirm(`⚠️ 危险操作：确定要彻底删除已归档项目“${project.name}”的配置吗？\n\n删除后将从 projects.json 彻底移除（系统会自动保存带时间戳的备份文件）。此操作不可撤销。`)) return;

  inFlightProjectActions.set(projectId, action);
  if (action === "start") {
    startingTimestamps.set(projectId, Date.now());
    project.state = "starting";
    project.can_start = false;
  }
  if (action === "repair") {
    if (button) {
      button.disabled = true;
      button.textContent = "正在安装修复依赖…";
    }
    toast(`正在为“${project.name}”安装缺失依赖 (${extraPayload.package || ""})，请稍候...`);
  }
  renderProjects();

  try {
    const data = await api(`/api/projects/${encodeURIComponent(projectId)}/${action}`, {
      method: "POST",
      body: JSON.stringify(extraPayload),
    });
    projects = data.projects.items;
    if (action === "start") {
      const updated = projects.find((item) => item.id === projectId);
      if (updated && updated.state === "running") {
        startingTimestamps.delete(projectId);
      }
    }
    renderProjects();
    await loadPorts(true);
    ports = buildProjectPorts();
    renderMetrics();
    renderPorts();
    const msgMap = {
      start: "项目启动操作已完成",
      stop: "项目已停止",
      archive: "项目已归档",
      restore: "项目已恢复",
      delete: "项目配置已永久删除（已自动生成备份）",
      "sync-port": "端口配置已保存为默认",
      repair: `依赖 ${extraPayload.package || ""} 修复完成！正在自动尝试启动项目...`,
    };
    toast(msgMap[action] || "操作成功");
    if (action === "repair") {
      setTimeout(() => {
        const startBtn = document.querySelector(`.project-start[data-id="${projectId}"]`);
        runProjectAction(projectId, "start", startBtn);
      }, 600);
    }
  } catch (error) {
    inFlightProjectActions.delete(projectId);
    startingTimestamps.delete(projectId);
    toast(error.message, true);
    const target = projects.find((item) => item.id === projectId);
    if (target && action === "start") {
      target.state = "stopped";
      target.can_start = true;
    }
    renderProjects();
    await loadProjects().catch(() => {});
  } finally {
    inFlightProjectActions.delete(projectId);
    renderProjects();
  }
}

async function loadActivity() {
  const data = await api("/api/actions");
  $("#activityLog").textContent = data.items.length ? data.items.join("\n") : "暂无操作记录";
  $("#activityLog").scrollTop = $("#activityLog").scrollHeight;
}

async function refreshAll(force = false) {
  if (refreshing) return;
  refreshing = true;
  const button = $("#refreshButton");
  button.disabled = true;
  button.classList.add("spinning");
  try {
    await Promise.all([loadPorts(force), loadProjects()]);
    ports = buildProjectPorts();
    renderMetrics();
    renderPorts();
    if (activeView === "activity") await loadActivity();
    setConnection(true);
    if (force) toast("端口和项目数据已刷新");
  } catch (error) {
    setConnection(false);
    toast(error.message, true);
  } finally {
    refreshing = false;
    button.disabled = false;
    button.classList.remove("spinning");
  }
}

function switchView(view) {
  if (!Object.hasOwn(pageTitles, view)) view = 'ports';
  activeView = view;
  if (location.hash !== '#' + view) location.hash = view;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `${view}View`));
  $("#pageTitle").textContent = pageTitles[view];
  if (view === "activity") loadActivity().catch((error) => toast(error.message, true));
}

$$(".nav-item[data-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
window.addEventListener('hashchange', () => switchView(location.hash.slice(1)));
$("#refreshButton").addEventListener("click", () => refreshAll(true));
$("#refreshActivity").addEventListener("click", () => loadActivity().catch((error) => toast(error.message, true)));
$("#portSearch").addEventListener("input", renderPorts);
$("#scopeFilter").addEventListener("change", renderPorts);
$("#projectSearch").addEventListener("input", renderProjects);

async function openDoctorModal() {
  const btn = $("#doctorBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "体检中…";
  }
  try {
    const data = await api("/api/doctor");
    const rep = data.report;
    const sum = rep.summary;
    const content = $("#doctorContent");
    content.innerHTML = `
      <div class="doctor-summary-grid">
        <div class="doctor-summary-card">
          <span>登记项目</span>
          <strong>${sum.total}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>健康正常</span>
          <strong style="color: #166534;">${sum.healthy}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>目录失效</span>
          <strong style="${sum.missing_paths > 0 ? 'color: #991b1b;' : ''}">${sum.missing_paths}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>端口漂移</span>
          <strong style="${sum.drift_ports > 0 ? 'color: #92400e;' : ''}">${sum.drift_ports}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>端口冲突</span>
          <strong style="${sum.port_conflicts > 0 ? 'color: #991b1b;' : ''}">${sum.port_conflicts}</strong>
        </div>
      </div>
      <div class="doctor-projects-list">
        ${rep.projects.map(p => `
          <div class="doctor-item-card">
            <div class="doctor-item-head">
              <span>${escapeHtml(p.name)} ${p.enabled === false ? '<small class="muted">(已归档)</small>' : ''}</span>
              <span class="doctor-check-badge ${p.healthy ? 'ok' : 'error'}">${p.healthy ? '✓ 健康' : '需处理'}</span>
            </div>
            ${p.checks.map(c => `
              <div class="doctor-check-row">
                <span class="doctor-check-badge ${c.level}">${c.level === 'info' || c.ok ? '正常' : (c.level === 'warn' ? '提示' : '异常')}</span>
                <span style="font-weight: 500;">${escapeHtml(c.item)}:</span>
                <span>${escapeHtml(c.message)}</span>
                ${c.suggestion ? `<small class="muted">(${escapeHtml(c.suggestion)})</small>` : ''}
                ${c.can_repair ? `<button class="button button-warn btn-sm doctor-repair-btn" style="margin-left:auto;" data-id="${escapeHtml(p.id)}" data-pkg="${escapeHtml(c.package || '')}">🛠️ 一键修复</button>` : ''}
              </div>
            `).join('')}
          </div>
        `).join('')}
      </div>
    `;
    $$(".doctor-repair-btn").forEach(b => b.addEventListener("click", () => {
      $("#doctorDialog").close();
      runProjectAction(b.dataset.id, "repair", null, { package: b.dataset.pkg });
    }));
    $("#doctorDialog").showModal();
  } catch (err) {
    toast(`体检失败: ${err.message}`, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "🩺 环境体检";
    }
  }
}

async function reconcileStaleProjects() {
  if (!window.confirm("确定自动扫描并归档所有路径失效/已搬家的项目吗？\n\n注意：此操作仅将目录不存在的项目移入【已归档】区域，立即释放端口，绝不物理删除任何文件，之后随时可以在下方归档区一键【恢复】。")) return;
  const btn = $("#reconcileStaleBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "扫描归档中…";
  }
  try {
    const data = await api("/api/projects/reconcile-stale", { method: "POST" });
    const count = data.result?.archived_count || 0;
    if (count > 0) {
      toast(`对账完成：已自动将 ${count} 个失效项目移入归档区`);
    } else {
      toast("对账完成：所有项目的工作目录均有效，无需归档");
    }
    await refreshAll(true);
  } catch (err) {
    toast(`自动归档失败: ${err.message}`, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "🧹 自动归档失效项";
    }
  }
}

$("#closeDialog").addEventListener("click", () => $("#detailDialog").close());
$("#detailDialog").addEventListener("click", (event) => { if (event.target === $("#detailDialog")) $("#detailDialog").close(); });
$("#closeDoctorDialog")?.addEventListener("click", () => $("#doctorDialog").close());
$("#doctorDialog")?.addEventListener("click", (event) => { if (event.target === $("#doctorDialog")) $("#doctorDialog").close(); });
$("#doctorBtn")?.addEventListener("click", openDoctorModal);
$("#reconcileStaleBtn")?.addEventListener("click", reconcileStaleProjects);
$$(".filter-chip").forEach((button) => button.addEventListener("click", () => {
  protocolFilter = button.dataset.protocol;
  $$(".filter-chip").forEach((item) => item.classList.toggle("active", item === button));
  renderPorts();
}));

(async () => {
  try {
    const session = await api("/api/session");
    sessionToken = session.token;
    switchView(location.hash.slice(1));
    await refreshAll(true);
    let pollTimer = null;
    const scheduleNextPoll = () => {
      clearTimeout(pollTimer);
      const hasStarting = projects.some((p) => p.state === "starting");
      const delay = hasStarting ? 2500 : 12000;
      pollTimer = setTimeout(async () => {
        await refreshAll(false).catch(() => {});
        scheduleNextPoll();
      }, delay);
    };
    scheduleNextPoll();
  } catch (error) {
    setConnection(false);
    toast(`控制台初始化失败：${error.message}`, true);
  }
})();
