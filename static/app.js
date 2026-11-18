const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let sessionToken = "";
let ports = [];
let rawPorts = [];
let projects = [];
let activityItems = [];
let protocolFilter = "";
let showAllListeningPorts = false;
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
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString("zh-CN", { hour12: false });
}

// 为具体端口推导准确的网页访问地址，避免多端口项目所有行都指向同一个端口
function resolvePortRowUrl(project, port, live, isDrift) {
  if (isDrift && project.effective_url) return project.effective_url;
  const configured = project.url || "";
  if (configured) {
    if (configured.includes(`:${port}`)) return configured;
    // 若配置了代理路径（如 8787/skills）且该项目只有一个预期端口，直接沿用配置入口
    if ((project.expected_ports || []).length <= 1) return configured;
  }
  if (live?.url) return live.url;
  if (configured) return `http://127.0.0.1:${port}/`;
  return "";
}

function renderMetrics() {
  const activeProjects = projects.filter((item) => item.enabled !== false && item.state !== "missing");
  const projectOnlyPorts = ports.filter((item) => !item.is_unregistered);
  $("#tcpMetric").textContent = activeProjects.length;
  $("#udpMetric").textContent = activeProjects.filter((item) => item.state === "running").length;
  $("#uniqueMetric").textContent = projectOnlyPorts.length;
  $("#publicMetric").textContent = projectOnlyPorts.filter((item) => item.project_state === "running" && item.scope === "all").length;
  $("#processMetric").textContent = activeProjects.filter((item) => item.state !== "running").length;
}

function buildProjectPorts() {
  const entries = [];
  const claimedPorts = new Set();

  for (const project of projects) {
    if (project.enabled === false) continue;
    if (project.lifecycle === "archive_candidate" && project.state !== "running") continue;
    if (project.state === "missing") continue;

    const conflictMap = new Map((project.port_conflicts || []).map((c) => [Number(c.port), c]));
    const allPorts = [...project.expected_ports];
    if (project.discovered_ports) {
      for (const p of project.discovered_ports) {
        if (!allPorts.includes(p)) allPorts.push(p);
      }
    }

    for (const port of allPorts) {
      claimedPorts.add(port);
      const candidates = rawPorts.filter((row) => row.protocol === "TCP" && row.port === port);
      const live = candidates.find((row) => row.scope === "loopback") || candidates[0];
      const conflict = conflictMap.get(Number(port));
      const isDrift = Boolean(project.discovered_ports && project.discovered_ports.includes(port) && !project.expected_ports.includes(port));

      let rowState = "stopped";
      if (conflict && project.state !== "running") {
        rowState = "conflict";
      } else if (live && (project.state === "running" || !conflict)) {
        rowState = conflict ? "conflict" : "running";
      }

      const scope = live?.scope || "stopped";
      const scopeLabel = live
        ? (live.scope === "loopback" ? "只有本机" : live.scope === "all" ? "本机与局域网" : "指定网卡")
        : "尚未启动";

      let desc = project.description || "这是你登记的本机项目。";
      if (rowState === "conflict" && conflict) {
        desc = `⚠️ 端口被外部程序 ${conflict.process} (PID ${conflict.pid}${conflict.cwd ? ` · ${conflict.cwd}` : ""}) 占用，未确认属于本项目`;
      } else if (isDrift) {
        desc = `【检测到端口漂移 · 已动态切换】${desc}`;
      }

      entries.push({
        ...(live || { protocol: "TCP", port, address: "—", pid: 0, process: "未启动", executable: "", services: [] }),
        project,
        conflict,
        is_unregistered: false,
        project_state: rowState,
        scope,
        scope_label: scopeLabel,
        function: desc,
        url: rowState === "running" ? resolvePortRowUrl(project, port, live, isDrift) : "",
        configured_url: resolvePortRowUrl(project, port, live, isDrift),
        is_drift: isDrift,
      });
    }
  }

  // 开启全机监听排查开关时，合并展示未登记的本机其他 TCP 监听端口
  if (showAllListeningPorts) {
    const byPort = new Map();
    for (const row of rawPorts) {
      if (row.protocol !== "TCP" || claimedPorts.has(row.port)) continue;
      const existing = byPort.get(row.port);
      if (!existing || (existing.scope !== "loopback" && row.scope === "loopback")) {
        byPort.set(row.port, row);
      }
    }
    for (const live of byPort.values()) {
      entries.push({
        ...live,
        project: {
          id: `unregistered-${live.port}`,
          name: "未登记监听服务",
          process_label: live.process,
          working_directory: live.executable || "系统或外部未登记进程",
          tags: ["未登记", "全机排查"],
        },
        conflict: null,
        is_unregistered: true,
        project_state: "running",
        scope_label: live.scope === "loopback" ? "只有本机" : live.scope === "all" ? "本机与局域网" : "指定网卡",
        url: live.url || "",
        configured_url: live.url || "",
        is_drift: false,
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
    const haystack = `${row.port} ${row.project.name} ${(row.project.tags || []).join(" ")} ${row.address} ${row.process} ${row.function} ${services}`.toLowerCase();
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
    body.innerHTML = '<tr><td colspan="6" class="empty-cell">没有匹配的端口记录</td></tr>';
    return;
  }
  body.innerHTML = rows.map((row) => {
    const badgeClass = row.project_state === "running"
      ? (row.is_unregistered ? "ext" : "tcp")
      : (row.project_state === "conflict" ? "conflict" : "udp");
    const badgeText = row.project_state === "running"
      ? (row.is_unregistered ? "外部" : "运行")
      : (row.project_state === "conflict" ? "冲突" : "待启");
    const stateClass = row.project_state === "running"
      ? "is-running"
      : (row.project_state === "conflict" ? "is-conflict" : "is-stopped");
    const stateText = row.project_state === "running"
      ? "可以使用"
      : (row.project_state === "conflict" ? "端口被占" : "尚未启动");
    const procTitle = row.project_state === "conflict" && row.conflict
      ? `${row.conflict.process} (外部占用)`
      : (row.project.process_label || row.process);
    const evidenceText = row.is_unregistered
      ? "来自全机活跃监听扫描"
      : (row.project_state === "conflict" ? "检测到外部目录进程占用此项目端口" : "来自项目登记信息");

    return `
    <tr class="port-row ${row.project_state === "conflict" ? "row-conflict" : ""}" data-index="${ports.indexOf(row)}">
      <td class="col-port">
        <div class="port-main"><span class="protocol protocol-${badgeClass}">${badgeText}</span><strong>${row.port}</strong></div>
        <span class="muted">${escapeHtml(row.project.name)}</span>
      </td>
      <td class="col-scope"><span class="scope scope-${row.scope}">${escapeHtml(row.scope_label)}</span></td>
      <td class="col-proc">
        <strong class="process-name" title="${escapeHtml(procTitle)}">${escapeHtml(procTitle)}</strong>
        <span class="muted">PID ${row.pid || "—"}</span>
        <div class="mini-badges">${serviceBadges(row)}</div>
      </td>
      <td class="col-desc">
        <span class="${row.project_state === "conflict" ? "conflict-inline-text" : ""}">${escapeHtml(row.function)}</span>
        <small class="evidence">${evidenceText}</small>
      </td>
      <td class="col-state"><span class="live-state ${stateClass}"><i></i>${stateText}</span></td>
      <td class="row-actions col-actions">
        ${row.url ? `<a class="icon-link" href="${escapeHtml(row.url)}" target="_blank" rel="noreferrer" title="打开 ${escapeHtml(row.url)}">↗</a>` : ""}
        <button class="icon-button detail-button" type="button" data-index="${ports.indexOf(row)}" title="查看端口详情">···</button>
      </td>
    </tr>`;
  }).join("");
  $$(".detail-button").forEach((button) => button.addEventListener("click", () => showPortDetail(ports[Number(button.dataset.index)])));
}

function showPortDetail(row) {
  $("#detailTitle").textContent = `${row.project.name} · 端口 ${row.port}`;
  const lanWarning = row.project_state === "running" && row.scope === "all"
    ? `<div class="drift-alert">⚠️ 当前服务绑定在所有网卡 (0.0.0.0 / ::)，同一局域网下的其他设备也可能访问该端口。若无需跨设备访问，建议在启动参数中指定 <code>--host 127.0.0.1</code>。</div>`
    : "";
  const conflictAction = row.project_state === "conflict" && row.conflict && !row.is_unregistered
    ? `<div class="crash-alert">
        <div class="crash-title">⚠️ 端口冲突排障</div>
        <div class="crash-desc">该端口被外部程序 <strong>${escapeHtml(row.conflict.process)}</strong> (PID ${row.conflict.pid}${row.conflict.cwd ? `，工作目录：${escapeHtml(row.conflict.cwd)}` : ""}) 占用。</div>
        <div class="crash-action">
          <button id="dialogReleaseBtn" class="button button-danger btn-sm" type="button"
            data-project="${escapeHtml(row.project.id)}"
            data-port="${row.port}"
            data-pid="${row.conflict.pid}"
            data-proc="${escapeHtml(row.conflict.process)}">释放占用端口 (${row.port})</button>
        </div>
      </div>`
    : "";

  const openSection = row.project_state === "running" && row.url
    ? `<a href="${escapeHtml(row.url)}" target="_blank" rel="noreferrer">${escapeHtml(row.url)} ↗</a>`
    : (row.configured_url
      ? `<span class="muted-inline">服务尚未运行（启动后访问地址：${escapeHtml(row.configured_url)}）</span>`
      : "该项目未配置网页入口");

  $("#detailContent").innerHTML = `
    ${lanWarning}
    ${conflictAction}
    <dl>
      <div><dt>用途说明</dt><dd>${escapeHtml(row.project.description || row.function)}</dd></div>
      <div><dt>端口号</dt><dd class="mono">${row.port}</dd></div>
      <div><dt>谁能访问</dt><dd>${escapeHtml(row.scope_label)}${row.address && row.address !== "—" ? ` (${escapeHtml(row.address)})` : ""}</dd></div>
      <div><dt>当前状态</dt><dd>${row.project_state === "running" ? "正在运行，可直接访问" : (row.project_state === "conflict" ? "端口被外部进程占用" : "尚未启动")}</dd></div>
      <div><dt>监听程序</dt><dd>${escapeHtml(row.process || "未启动")}${row.pid ? ` · PID ${row.pid}` : ""}</dd></div>
      <div><dt>所在目录</dt><dd class="path-value">${escapeHtml(row.conflict?.cwd || row.project.working_directory || "系统未提供路径")}</dd></div>
      <div><dt>网页入口</dt><dd>${openSection}</dd></div>
    </dl>`;

  const releaseBtn = $("#dialogReleaseBtn");
  if (releaseBtn) {
    releaseBtn.addEventListener("click", async () => {
      $("#detailDialog").close();
      await releaseConflictPort(
        releaseBtn.dataset.project,
        Number(releaseBtn.dataset.port),
        Number(releaseBtn.dataset.pid),
        releaseBtn.dataset.proc
      );
    });
  }
  $("#detailDialog").showModal();
}

async function releaseConflictPort(projectId, port, pid, procName) {
  if (!window.confirm(`确定要结束占用端口 ${port} 的外部进程“${procName} (PID ${pid})”吗？\n\n请确认该外部程序当前没有未保存的重要任务。`)) return;
  try {
    const data = await api("/api/ports/release-conflict", {
      method: "POST",
      body: JSON.stringify({ project_id: projectId, port, pid }),
    });
    projects = data.projects.items;
    renderProjects();
    await loadPorts(true);
    ports = buildProjectPorts();
    renderMetrics();
    renderPorts();
    toast(`端口 ${port} 已成功释放，现在可以正常启动项目`);
  } catch (err) {
    toast(`释放端口失败：${err.message}`, true);
  }
}

async function openProjectLogsModal(projectId, projectName) {
  $("#logTitle").textContent = `${projectName} · 运行日志`;
  $("#logContent").innerHTML = `<p class="muted">正在读取控制台输出…</p>`;
  $("#logDialog").showModal();
  try {
    const data = await api(`/api/projects/${encodeURIComponent(projectId)}/logs`);
    if (!data.exists || !data.lines.length) {
      $("#logContent").innerHTML = `
        <div class="empty-log-box">
          <p>暂无工作台捕获的控制台输出记录。</p>
          <small>当通过工作台点击「启动项目」运行本机命令时，标准输出与报错会自动记录于：${escapeHtml(data.log_path)}</small>
        </div>`;
      return;
    }
    $("#logContent").innerHTML = `
      <div class="log-meta">日志文件：<span class="mono">${escapeHtml(data.log_path)}</span>（最近 ${data.lines.length} 行）</div>
      <pre class="project-log-pre">${escapeHtml(data.lines.join("\n"))}</pre>`;
    const pre = $("#logContent .project-log-pre");
    if (pre) pre.scrollTop = pre.scrollHeight;
  } catch (err) {
    $("#logContent").innerHTML = `<div class="missing-alert">读取日志失败：${escapeHtml(err.message)}</div>`;
  }
}

async function loadPorts(force = false) {
  const data = await api(`/api/ports${force ? "?refresh=1" : ""}`);
  rawPorts = data.items;
  $("#updatedAt").textContent = `${formatTime(data.generated_at)} · 耗时 ${data.duration_ms} ms`;
}

function projectMatches(project) {
  const query = $("#projectSearch").value.trim().toLowerCase();
  if (!query) return true;
  return `${project.name} ${project.description} ${project.id} ${project.working_directory} ${project.expected_ports.join(" ")} ${project.tags.join(" ")}`.toLowerCase().includes(query);
}

function typeLabel(type) {
  return { command: "本机命令", "docker-compose": "Docker Compose", "windows-service": "Windows 服务" }[type] || type;
}

function stateLabel(project) {
  if (project.enabled === false) return "已归档";
  if (project.state === "missing") return "目录失效";
  if (project.port_conflict && project.state !== "running") {
    const cPort = project.port_conflicts?.[0]?.port;
    return cPort ? `端口被占 (${cPort})` : "端口被占";
  }
  if (project.port_drift && project.state === "running") {
    return `运行中 (${project.effective_port || project.discovered_ports?.[0] || "动态端口"})`;
  }
  return { running: "运行中", starting: "启动中", stopped: "已停止", unknown: "待检测" }[project.state] || project.state;
}

function renderProjects() {
  const rows = projects.filter(projectMatches);
  const activeRows = rows.filter((project) => project.enabled !== false);
  const archivedRows = rows.filter((project) => project.enabled === false);
  $("#projectCount").textContent = `${activeRows.length} 个活动项目${archivedRows.length ? ` · ${archivedRows.length} 个已归档` : ""}`;
  const grid = $("#projectGrid");
  if (!rows.length) {
    grid.innerHTML = '<div class="empty-card">没有匹配的项目。清空搜索词或将 port-console.project.json 放入项目根目录后刷新。</div>';
    return;
  }
  const renderCard = (project) => {
    const inFlight = inFlightProjectActions.get(project.id);
    const isStarting = project.state === "starting" || inFlight === "start";
    const sLabel = stateLabel({ ...project, state: isStarting ? "starting" : project.state });
    const sClass = (project.enabled === false)
      ? "state-archived"
      : (project.state === "running"
        ? "state-running"
        : ((project.port_conflict || project.port_drift || isStarting) ? "state-starting" : `state-${project.state}`));
    const isAtlas = project.id === "port-atlas";
    const targetUrl = project.effective_url || project.url;
    const isRunning = project.state === "running";
    const canStart = Boolean(project.can_start && !inFlight);
    const canStop = Boolean(project.can_stop && inFlight !== "stop");
    const startText = project.enabled === false
      ? "已归档"
      : (isRunning ? "正在运行" : (isStarting ? "启动中…" : "启动项目"));
    const stopText = inFlight === "stop" ? "停止中…" : "停止";
    const firstConflict = project.port_conflicts?.[0];

    return `
    <article class="project-card ${project.state} ${project.port_conflict ? "has-conflict" : ""} ${project.enabled === false ? "archived" : ""}">
      <div class="project-card-head">
        <div class="project-icon">${escapeHtml(project.name.slice(0, 1).toUpperCase())}</div>
        <div class="project-head-main">
          <h3>${escapeHtml(project.name)}</h3>
          <span class="project-type">${escapeHtml(typeLabel(project.type))}</span>
        </div>
        <span class="project-state ${sClass}"><i></i>${escapeHtml(sLabel)}</span>
      </div>
      <p>${escapeHtml(project.description || "未填写项目说明")}</p>
      ${project.port_drift && project.discovered_ports?.length ? `
        <div class="drift-alert">
          <div>🟢 实际监听端口 [${project.discovered_ports.join(", ")}] 已动态生效（原配置: ${project.expected_ports.join(", ")}）</div>
          <div class="drift-bar">
            <span class="drift-hint">打开页面已自动指向实际端口</span>
            <button class="link-btn project-sync-port" type="button" data-id="${escapeHtml(project.id)}" data-port="${project.discovered_ports[0]}">设为默认端口</button>
          </div>
        </div>` : ""}
      ${project.port_conflict && firstConflict ? `
        <div class="crash-alert">
          <div class="crash-title">⚠️ 端口 ${firstConflict.port} 被外部进程占用</div>
          <div class="crash-desc">占用程序：${escapeHtml(firstConflict.process)} (PID ${firstConflict.pid}${firstConflict.cwd ? ` · ${escapeHtml(firstConflict.cwd)}` : ""})</div>
          <div class="crash-action">
            <button class="button button-danger btn-sm project-release-conflict" type="button"
              data-id="${escapeHtml(project.id)}"
              data-port="${firstConflict.port}"
              data-pid="${firstConflict.pid}"
              data-proc="${escapeHtml(firstConflict.process)}">释放占用端口 (${firstConflict.port})</button>
          </div>
        </div>` : ""}
      ${project.path_exists === false ? `<div class="missing-alert">❌ 项目目录不存在：${escapeHtml(project.working_directory)}</div>` : ""}
      ${project.last_crash ? `
        <div class="crash-alert">
          <div class="crash-title">⚠️ ${escapeHtml(project.last_crash.summary || "启动异常退出")}</div>
          <div class="crash-desc">${escapeHtml(project.last_crash.suggestion || "")}</div>
          ${project.last_crash.can_auto_repair ? `
            <div class="crash-action">
              <button class="button button-warn btn-sm project-repair" type="button" data-id="${escapeHtml(project.id)}" data-pkg="${escapeHtml(project.last_crash.package || "")}">🛠️ 一键修复依赖 (${escapeHtml(project.last_crash.package || "缺失模块")})</button>
            </div>` : ""}
        </div>` : ""}
      <div class="project-meta">
        <span>配置端口：${project.expected_ports.length ? project.expected_ports.join(", ") : "桌面/无固定端口"}${project.port_drift && project.effective_port ? ` → 实际生效 ${project.effective_port}` : ""}</span>
        <span title="${escapeHtml(project.working_directory)}">${escapeHtml(project.working_directory)}</span>
      </div>
      <div class="tag-row">${project.tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>
      <div class="project-actions">
        ${isRunning && targetUrl && project.enabled !== false
          ? `<a class="button button-primary" href="${escapeHtml(targetUrl)}" target="_blank" rel="noreferrer">打开页面 ↗</a>`
          : `<button class="button button-primary project-start" type="button" data-id="${escapeHtml(project.id)}" ${canStart ? "" : "disabled"}>${escapeHtml(startText)}</button>`}
        ${isRunning ? `<button class="button button-danger project-stop" type="button" data-id="${escapeHtml(project.id)}" title="${escapeHtml(project.stop_reason || "停止这个项目")}" ${canStop ? "" : "disabled"}>${escapeHtml(stopText)}</button>` : ""}
        ${project.type === "command" && !isAtlas ? `<button class="button button-ghost project-log" type="button" data-id="${escapeHtml(project.id)}" data-name="${escapeHtml(project.name)}" title="查看控制台输出日志">日志</button>` : ""}
        ${!isAtlas ? (project.enabled === false
          ? `<button class="button button-ghost project-restore" type="button" data-id="${escapeHtml(project.id)}">恢复</button>
             <button class="button button-danger project-delete" type="button" data-id="${escapeHtml(project.id)}" data-name="${escapeHtml(project.name)}" title="从配置文件中彻底删除">删除</button>`
          : `<button class="button button-ghost project-archive" type="button" data-id="${escapeHtml(project.id)}" title="归档此项目">归档</button>`) : ""}
      </div>
      ${project.stop_reason && isRunning && !canStop ? `<p class="stop-reason">${escapeHtml(project.stop_reason)}</p>` : ""}
    </article>`;
  };

  let html = activeRows.map(renderCard).join("");
  if (archivedRows.length) {
    html += `
    <div class="archived-divider-card">
      <div class="archived-divider-title">
        <span>📦 已归档项目 (${archivedRows.length})</span>
        <span class="archived-hint">已停用或归档的项目折叠于此，不干扰日常列表，可随时一键恢复</span>
      </div>
    </div>
    ` + archivedRows.map(renderCard).join("");
  }
  grid.innerHTML = html;

  $$(".project-start").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "start", button)));
  $$(".project-stop").forEach((button) => button.addEventListener("click", () => runProjectAction(button.dataset.id, "stop", button)));
  $$(".project-sync-port").forEach((button) => button.addEventListener("click", () => {
    const port = Number(button.dataset.port);
    if (!window.confirm(`确定将该项目的默认配置端口更新为 ${port} 吗？`)) return;
    runProjectAction(button.dataset.id, "sync-port", button, { port });
  }));
  $$(".project-release-conflict").forEach((button) => button.addEventListener("click", () => {
    releaseConflictPort(button.dataset.id, Number(button.dataset.port), Number(button.dataset.pid), button.dataset.proc);
  }));
  $$(".project-log").forEach((button) => button.addEventListener("click", () => openProjectLogsModal(button.dataset.id, button.dataset.name)));
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
  if (action === "delete" && !window.confirm(`⚠️ 危险操作：确定要彻底删除已归档项目“${project.name}”的配置吗？\n\n删除后将从 projects.json 移除（系统会自动保存备份文件）。`)) return;

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
      start: "项目启动指令已执行",
      stop: "项目已停止",
      archive: "项目已移入归档区",
      restore: "项目已恢复至活动列表",
      delete: "项目配置已移除（已自动备份）",
      "sync-port": "默认端口配置已更新",
      repair: `依赖 ${extraPayload.package || ""} 安装完成！正在自动尝试启动项目...`,
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

// 将后端审计日志行解析为用户易读的中文事件卡片
function parseAuditLine(rawLine) {
  const m = rawLine.match(/^(\S+)\s+(.*)$/);
  const timeText = m ? formatTime(m[1]) : "";
  const body = m ? m[2] : rawLine;
  const findProjectName = (id) => projects.find((p) => p.id === id)?.name || id;

  if (body.startsWith("SERVER start")) return { badge: "工作台启动", tone: "ok", summary: "本机工作台后台服务已启动", detail: body, timeText };
  if (body.startsWith("SERVER stop")) return { badge: "工作台停止", tone: "muted", summary: "本机工作台后台服务已关闭", detail: body, timeText };

  const startReq = body.match(/^START requested project=(\S+)/);
  if (startReq) return { badge: "发起启动", tone: "info", summary: `请求启动项目「${findProjectName(startReq[1])}」`, detail: body, timeText };

  const startOk = body.match(/^START completed project=(\S+)/);
  if (startOk) return { badge: "启动完成", tone: "ok", summary: `项目「${findProjectName(startOk[1])}」已完成启动`, detail: body, timeText };

  const stopReq = body.match(/^STOP requested project=(\S+)/);
  if (stopReq) return { badge: "发起停止", tone: "warn", summary: `请求停止项目「${findProjectName(stopReq[1])}」`, detail: body, timeText };

  const stopOk = body.match(/^STOP completed project=(\S+)/);
  if (stopOk) return { badge: "已停止", tone: "muted", summary: `项目「${findProjectName(stopOk[1])}」已安全停止`, detail: body, timeText };

  const archiveMatch = body.match(/^PROJECT (archive|restore|delete|sync_port) id=(\S+)/);
  if (archiveMatch) {
    const map = { archive: "归档项目", restore: "恢复项目", delete: "删除配置", sync_port: "更新端口" };
    return { badge: map[archiveMatch[1]] || "配置变更", tone: "info", summary: `项目「${findProjectName(archiveMatch[2])}」执行了${map[archiveMatch[1]] || "变更"}`, detail: body, timeText };
  }

  const conflictMatch = body.match(/^CONFLICT released project=(\S+) port=(\d+) pid=(\d+)/);
  if (conflictMatch) {
    return { badge: "冲突释放", tone: "ok", summary: `已释放「${findProjectName(conflictMatch[1])}」被占用的端口 ${conflictMatch[2]} (PID ${conflictMatch[3]})`, detail: body, timeText };
  }

  if (body.includes("failed") || body.includes("error=") || /" [45]\d\d /.test(body)) {
    return { badge: "操作异常", tone: "error", summary: body, detail: "", timeText };
  }

  return { badge: "系统记录", tone: "muted", summary: body, detail: "", timeText };
}

function renderActivity() {
  const listEl = $("#activityList");
  const query = ($("#activitySearch")?.value || "").trim().toLowerCase();
  const parsed = [...activityItems].reverse().map(parseAuditLine).filter((item) => {
    if (!query) return true;
    return `${item.badge} ${item.summary} ${item.detail}`.toLowerCase().includes(query);
  });

  if (!parsed.length) {
    listEl.innerHTML = `<div class="empty-cell">${query ? "没有匹配的操作记录" : "暂无用户操作记录（常规后台轮询已自动过滤降噪）"}</div>`;
    return;
  }

  listEl.innerHTML = parsed.map((item) => `
    <div class="audit-row">
      <span class="audit-badge tone-${item.tone}">${escapeHtml(item.badge)}</span>
      <div class="audit-main">
        <strong>${escapeHtml(item.summary)}</strong>
        ${item.detail && item.detail !== item.summary ? `<small class="mono">${escapeHtml(item.detail)}</small>` : ""}
      </div>
      <time>${escapeHtml(item.timeText)}</time>
    </div>
  `).join("");
}

async function loadActivity() {
  const data = await api("/api/actions");
  activityItems = data.items || [];
  renderActivity();
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
    if (force) toast("本机项目与端口状态已刷新");
  } catch (error) {
    setConnection(false);
    toast(error.message, true);
  } finally {
    refreshing = false;
    button.disabled = false;
    button.classList.remove("spinning");
  }
}

function switchView(view, fromHash = false) {
  if (!Object.hasOwn(pageTitles, view)) view = "ports";
  const changed = activeView !== view;
  activeView = view;
  if (!fromHash && location.hash !== "#" + view) {
    history.replaceState(null, "", "#" + view);
  }
  $$(".nav-item[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `${view}View`));
  $("#pageTitle").textContent = pageTitles[view];
  if (view === "activity" && (changed || !activityItems.length)) {
    loadActivity().catch((error) => toast(error.message, true));
  }
}

$$(".nav-item[data-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
window.addEventListener("hashchange", () => switchView(location.hash.slice(1), true));
$("#refreshButton").addEventListener("click", () => refreshAll(true));
$("#refreshActivity").addEventListener("click", () => loadActivity().then(() => toast("操作记录已刷新")).catch((error) => toast(error.message, true)));
$("#activitySearch")?.addEventListener("input", renderActivity);
$("#portSearch").addEventListener("input", renderPorts);
$("#scopeFilter").addEventListener("change", renderPorts);
$("#projectSearch").addEventListener("input", renderProjects);
$("#showAllPortsToggle")?.addEventListener("change", (e) => {
  showAllListeningPorts = Boolean(e.target.checked);
  ports = buildProjectPorts();
  renderMetrics();
  renderPorts();
});

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
          <strong class="text-ok">${sum.healthy}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>目录失效</span>
          <strong class="${sum.missing_paths > 0 ? "text-error" : ""}">${sum.missing_paths}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>动态端口</span>
          <strong class="${sum.drift_ports > 0 ? "text-warn" : ""}">${sum.drift_ports}</strong>
        </div>
        <div class="doctor-summary-card">
          <span>端口冲突</span>
          <strong class="${sum.port_conflicts > 0 ? "text-error" : ""}">${sum.port_conflicts}</strong>
        </div>
      </div>
      <div class="doctor-projects-list">
        ${rep.projects.map((p) => `
          <div class="doctor-item-card">
            <div class="doctor-item-head">
              <span>${escapeHtml(p.name)} ${p.enabled === false ? '<small class="muted-inline">(已归档)</small>' : ""}</span>
              <span class="doctor-check-badge ${p.healthy ? "ok" : "error"}">${p.healthy ? "✓ 健康" : "需关注"}</span>
            </div>
            ${p.checks.map((c) => `
              <div class="doctor-check-row">
                <span class="doctor-check-badge ${c.level === "info" || c.ok ? "ok" : c.level}">${c.level === "info" || c.ok ? "正常" : (c.level === "warn" ? "提示" : "异常")}</span>
                <span class="doctor-check-label">${escapeHtml(c.item)}:</span>
                <span>${escapeHtml(c.message)}</span>
                ${c.suggestion ? `<small class="muted-inline">(${escapeHtml(c.suggestion)})</small>` : ""}
                ${c.can_repair ? `<button class="button button-warn btn-sm doctor-repair-btn ml-auto" type="button" data-id="${escapeHtml(p.id)}" data-pkg="${escapeHtml(c.package || "")}">🛠️ 一键修复</button>` : ""}
              </div>
            `).join("")}
          </div>
        `).join("")}
      </div>
    `;
    $$(".doctor-repair-btn").forEach((b) => b.addEventListener("click", () => {
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
  if (!window.confirm("确定自动扫描并归档所有路径失效的项目吗？\n\n此操作仅将目录不存在的项目移入【已归档】区域，绝不删除任何文件，之后随时可一键【恢复】。")) return;
  const btn = $("#reconcileStaleBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "扫描归档中…";
  }
  try {
    const data = await api("/api/projects/reconcile-stale", { method: "POST" });
    const count = data.result?.archived_count || 0;
    toast(count > 0 ? `对账完成：已自动将 ${count} 个失效项目移入归档区` : "对账完成：所有活动项目工作目录均正常");
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
$("#closeLogDialog")?.addEventListener("click", () => $("#logDialog").close());
$("#logDialog")?.addEventListener("click", (event) => { if (event.target === $("#logDialog")) $("#logDialog").close(); });
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
    const initialView = location.hash.slice(1) || "ports";
    switchView(initialView, true);
    await refreshAll(false);
    if (activeView === "activity") await loadActivity();
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
