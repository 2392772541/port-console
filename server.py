from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import shutil
import subprocess
import threading
import time
import psutil
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse, urlunparse


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
SKILL_STATIC = Path(r'D:\AI-Skills\web\static')
CONFIG_PATH = ROOT / "config" / "projects.json"
LOG_DIR = ROOT / "logs"
RUNTIME_DIR = ROOT / ".runtime"
ACTION_LOG = LOG_DIR / "actions.log"
HOST = os.environ.get("PORT_CONSOLE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT_CONSOLE_PORT", "8787"))
STARTED_AT = datetime.now().astimezone().isoformat(timespec="seconds")
SESSION_TOKEN = secrets.token_urlsafe(32)
ACTION_LOCK = threading.Lock()
PORT_CACHE_LOCK = threading.Lock()
PORT_CACHE: dict[str, Any] = {"time": 0.0, "data": None}
MANAGED_PROCESSES: dict[str, subprocess.Popen[Any]] = {}

LOG_DIR.mkdir(parents=True, exist_ok=True)
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


KNOWN_PORTS = {
    21: "FTP 文件传输",
    22: "SSH 安全远程连接",
    53: "DNS 域名解析",
    80: "HTTP 网站服务",
    135: "Windows RPC",
    137: "NetBIOS 名称服务",
    138: "NetBIOS 数据报",
    139: "NetBIOS 会话服务",
    443: "HTTPS 加密网站服务",
    445: "Windows SMB 文件共享",
    500: "IPsec IKE",
    1433: "Microsoft SQL Server",
    1900: "SSDP 设备发现",
    2179: "Hyper-V 虚拟机连接",
    3000: "常见前端/Node 开发服务器",
    3306: "MySQL 数据库",
    3389: "Windows 远程桌面",
    4500: "IPsec NAT-T",
    5000: "常见 Python/开发服务器",
    5040: "Windows 连接设备平台",
    5054: "Reprise License Manager 管理页",
    5173: "Vite 前端开发服务器",
    5353: "mDNS 局域网发现",
    5355: "LLMNR 名称解析",
    5357: "Web Services for Devices",
    5432: "PostgreSQL 数据库",
    6379: "Redis 数据库",
    7680: "Windows 传递优化",
    7897: "Clash/Mihomo 本地代理",
    8000: "常见开发服务器",
    8080: "常见 HTTP 服务/代理",
    8317: "CLI Proxy API",
    8765: "本机技能管家",
    8888: "宝塔面板或开发服务",
    9128: "Quark 本机服务",
    9222: "Chromium DevTools",
    27036: "Steam 本地服务",
}

WEB_PORTS = {
    80,
    443,
    3000,
    5000,
    5054,
    5173,
    8000,
    8080,
    8317,
    8765,
    8888,
    9128,
    9180,
    9222,
    47100,
    47235,
}

WEB_PROCESS_WORDS = (
    "nginx",
    "apache",
    "httpd",
    "node",
    "python",
    "uvicorn",
    "gunicorn",
    "java",
    "tomcat",
    "web",
    "panel",
    "tunnel-client",
    "cli-proxy",
)

PROJECT_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")
SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,128}$")
IGNORED_SCAN_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
}


PORT_QUERY_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$processes = @{}
Get-CimInstance Win32_Process | ForEach-Object {
  $processes[[string]$_.ProcessId] = @{
    process = [string]$_.Name
    executable = [string]$_.ExecutablePath
  }
}
$services = @{}
Get-CimInstance Win32_Service | ForEach-Object {
  $key = [string]$_.ProcessId
  if (-not $services.ContainsKey($key)) { $services[$key] = @() }
  if ($_.ProcessId -gt 0) {
    $services[$key] += @{
      name = [string]$_.Name
      display_name = [string]$_.DisplayName
      state = [string]$_.State
      start_mode = [string]$_.StartMode
    }
  }
}
$rows = @()
Get-NetTCPConnection -State Listen | ForEach-Object {
  $pidKey = [string]$_.OwningProcess
  $proc = $processes[$pidKey]
  $svc = $services[$pidKey]
  $rows += @{
    protocol = 'TCP'
    address = [string]$_.LocalAddress
    port = [int]$_.LocalPort
    pid = [int]$_.OwningProcess
    process = if ($proc) { [string]$proc.process } else { '' }
    executable = if ($proc) { [string]$proc.executable } else { '' }
    services = if ($svc) { @($svc) } else { @() }
    state = 'Listen'
  }
}
Get-NetUDPEndpoint | ForEach-Object {
  $pidKey = [string]$_.OwningProcess
  $proc = $processes[$pidKey]
  $svc = $services[$pidKey]
  $rows += @{
    protocol = 'UDP'
    address = [string]$_.LocalAddress
    port = [int]$_.LocalPort
    pid = [int]$_.OwningProcess
    process = if ($proc) { [string]$proc.process } else { '' }
    executable = if ($proc) { [string]$proc.executable } else { '' }
    services = if ($svc) { @($svc) } else { @() }
    state = 'Bound'
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 6 -Compress
"""


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_action(message: str) -> None:
    line = f"{now_text()} {message}\n"
    with ACTION_LOG.open("a", encoding="utf-8") as handle:
        handle.write(line)


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def powershell_executable() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        raise RuntimeError("未找到 PowerShell，无法读取 Windows 端口")
    return executable


def scope_for_address(address: str) -> str:
    if address in {"127.0.0.1", "::1"}:
        return "loopback"
    if address in {"0.0.0.0", "::", "::0", "*"}:
        return "all"
    return "interface"


def display_scope(scope: str) -> str:
    return {"loopback": "仅本机", "all": "所有网卡", "interface": "指定网卡"}.get(scope, scope)


def infer_function(port: int, process: str, services: list[dict[str, Any]]) -> tuple[str, str]:
    service_names = "、".join(
        str(item.get("display_name") or item.get("name") or "") for item in services if item
    ).strip("、")
    if service_names:
        return service_names, "service"
    process_lower = process.casefold()
    if "filezilla" in process_lower:
        return "FileZilla FTP 服务", "process"
    if "mysqld" in process_lower:
        return "MySQL 数据库", "process"
    if "nginx" in process_lower:
        return "Nginx Web/代理服务", "process"
    if "clash" in process_lower or "mihomo" in process_lower:
        return "Clash/Mihomo 代理", "process"
    if "steam" in process_lower:
        return "Steam 本地服务", "process"
    if "tailscale" in process_lower:
        return "Tailscale 虚拟网络", "process"
    if "chrome" in process_lower or "msedge" in process_lower:
        return "浏览器内部服务", "process"
    if "python" in process_lower:
        return "Python 本机应用", "process"
    if "node" in process_lower:
        return "Node.js 本机应用", "process"
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port], "port"
    if process:
        return f"{process} 提供的本机服务", "process"
    return "未识别服务", "unknown"


def possible_web_url(row: dict[str, Any]) -> str | None:
    if row["protocol"] != "TCP":
        return None
    process = str(row.get("process", "")).casefold()
    port = int(row["port"])
    if port not in WEB_PORTS and not any(word in process for word in WEB_PROCESS_WORDS):
        return None
    scheme = "https" if port == 443 else "http"
    address = str(row.get("address", ""))
    scope = row.get("scope")
    if scope in {"loopback", "all"}:
        host = "127.0.0.1"
    elif ":" in address:
        host = f"[{address.split('%', 1)[0]}]"
    else:
        host = address
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def collect_ports_uncached() -> dict[str, Any]:
    started = time.monotonic()
    command = [
        powershell_executable(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        PORT_QUERY_PS,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell 端口读取失败")
    raw = completed.stdout.strip()
    rows = json.loads(raw) if raw else []
    if isinstance(rows, dict):
        rows = [rows]
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in rows:
        protocol = str(item.get("protocol", "")).upper()
        address = str(item.get("address", ""))
        port = int(item.get("port", 0))
        pid = int(item.get("pid", 0))
        key = (protocol, address, port, pid)
        if port <= 0 or key in seen:
            continue
        seen.add(key)
        services = item.get("services") or []
        if isinstance(services, dict):
            services = [services]
        process = str(item.get("process") or "")
        function, evidence = infer_function(port, process, services)
        row = {
            "protocol": protocol,
            "address": address,
            "port": port,
            "pid": pid,
            "process": process or "<unknown>",
            "executable": str(item.get("executable") or ""),
            "services": services,
            "state": str(item.get("state") or ""),
            "scope": scope_for_address(address),
            "scope_label": "",
            "function": function,
            "evidence": evidence,
        }
        row["scope_label"] = display_scope(row["scope"])
        row["url"] = possible_web_url(row)
        normalized.append(row)
    normalized.sort(key=lambda row: (row["port"], row["protocol"], row["address"], row["pid"]))
    unique_ports = {row["port"] for row in normalized}
    unique_processes = {row["pid"] for row in normalized if row["pid"] > 0}
    summary = {
        "tcp": sum(1 for row in normalized if row["protocol"] == "TCP"),
        "udp": sum(1 for row in normalized if row["protocol"] == "UDP"),
        "unique_ports": len(unique_ports),
        "processes": len(unique_processes),
        "loopback": sum(1 for row in normalized if row["scope"] == "loopback"),
        "all_interfaces": sum(1 for row in normalized if row["scope"] == "all"),
    }
    return {
        "ok": True,
        "generated_at": now_text(),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "summary": summary,
        "items": normalized,
    }


def collect_ports(force: bool = False) -> dict[str, Any]:
    with PORT_CACHE_LOCK:
        if not force and PORT_CACHE["data"] is not None and time.monotonic() - PORT_CACHE["time"] < 2.0:
            return PORT_CACHE["data"]
        data = collect_ports_uncached()
        PORT_CACHE["time"] = time.monotonic()
        PORT_CACHE["data"] = data
        return data


def load_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def normalized_path(value: str, base: Path = ROOT) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(value)))
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def normalize_project(raw: dict[str, Any], source: Path) -> dict[str, Any]:
    project_id = str(raw.get("id") or "").strip()
    if not PROJECT_ID_RE.fullmatch(project_id):
        raise ValueError(f"项目 ID 不合法：{project_id or '<empty>'}")
    name = str(raw.get("name") or project_id).strip()
    project_type = str(raw.get("type") or "command").strip().lower()
    if project_type not in {"command", "docker-compose", "windows-service"}:
        raise ValueError(f"项目 {project_id} 的 type 不支持：{project_type}")
    working_directory = normalized_path(str(raw.get("working_directory") or source.parent), source.parent)
    expected_ports = sorted({int(port) for port in raw.get("expected_ports", []) if 0 < int(port) <= 65535})
    path_exists = working_directory.is_dir()
    project: dict[str, Any] = {
        "id": project_id,
        "name": name,
        "process_label": str(raw.get("process_label") or "").strip(),
        "description": str(raw.get("description") or ""),
        "type": project_type,
        "working_directory": str(working_directory),
        "path_exists": path_exists,
        "expected_ports": expected_ports,
        "url": str(raw.get("url") or ""),
        "enabled": bool(raw.get("enabled", True)),
        "allow_stop": bool(raw.get("allow_stop", False)),
        "stop_disabled_reason": str(raw.get("stop_disabled_reason") or ""),
        "tags": [str(tag) for tag in raw.get("tags", [])][:12],
        "source": str(source),
    }
    if project_type == "command":
        command = raw.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(part, str) and part for part in command):
            raise ValueError(f"项目 {project_id} 的 command 必须是非空字符串数组")
        project["command"] = command
        stop_command = raw.get("stop_command")
        if stop_command is not None:
            if not isinstance(stop_command, list) or not stop_command or not all(isinstance(part, str) and part for part in stop_command):
                raise ValueError(f"项目 {project_id} 的 stop_command 必须是非空字符串数组")
            project["stop_command"] = stop_command
        environment = raw.get("environment") or {}
        if not isinstance(environment, dict):
            raise ValueError(f"项目 {project_id} 的 environment 必须是对象")
        project["environment"] = {str(key): str(value) for key, value in environment.items()}
    elif project_type == "docker-compose":
        compose_file = normalized_path(str(raw.get("compose_file") or "compose.yaml"), working_directory)
        project["compose_file"] = str(compose_file)
    else:
        service_name = str(raw.get("service_name") or "")
        if not SERVICE_NAME_RE.fullmatch(service_name):
            raise ValueError(f"项目 {project_id} 的 Windows 服务名不合法")
        project["service_name"] = service_name
    return project


def discover_manifests(scan_roots: list[str], max_depth: int = 4) -> list[Path]:
    manifests: list[Path] = []
    for root_text in scan_roots:
        root = normalized_path(root_text)
        if not root.is_dir():
            continue
        root_depth = len(root.parts)
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.parts) - root_depth
            dirs[:] = [name for name in dirs if name not in IGNORED_SCAN_DIRS and depth < max_depth]
            if "port-console.project.json" in files:
                manifests.append(current_path / "port-console.project.json")
            if len(manifests) >= 250:
                return manifests
    return manifests


def load_project_catalog() -> tuple[list[dict[str, Any]], list[str]]:
    config = load_json(CONFIG_PATH, {"projects": [], "scan_roots": []})
    projects: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    sources: list[tuple[dict[str, Any], Path]] = [
        (raw, CONFIG_PATH) for raw in config.get("projects", []) if isinstance(raw, dict)
    ]
    for manifest in discover_manifests([str(item) for item in config.get("scan_roots", [])]):
        data = load_json(manifest, None)
        if isinstance(data, dict):
            sources.append((data, manifest))
        else:
            errors.append(f"无法读取项目清单：{manifest}")
    for raw, source in sources:
        try:
            project = normalize_project(raw, source)
            if project["id"] in seen:
                errors.append(f"项目 ID 重复，已忽略后项：{project['id']} ({source})")
                continue
            seen.add(project["id"])
            projects.append(project)
        except (ValueError, OSError) as exc:
            errors.append(f"{source}: {exc}")
    projects.sort(key=lambda item: item["name"].casefold())
    return projects, errors


def listening_ports() -> set[int]:
    return {int(row["port"]) for row in collect_ports().get("items", []) if row["protocol"] == "TCP"}


def is_owned_by_project(
    process: psutil.Process,
    root: Path,
    project: dict[str, Any],
    all_projects: list[dict[str, Any]] | None = None,
) -> bool:
    managed = MANAGED_PROCESSES.get(project["id"])
    if managed and managed.poll() is None:
        if process.pid == managed.pid:
            return True
        try:
            if managed.pid in {p.pid for p in process.parents()}:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        exe = process.exe()
        if exe:
            exe_path = Path(exe).resolve()
            if exe_path.is_relative_to(root) or os.path.normcase(str(exe_path)).startswith(os.path.normcase(str(root))):
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
        pass

    try:
        cwd = process.cwd()
        if cwd:
            cwd_path = Path(cwd).resolve()
            if all_projects:
                for other in all_projects:
                    if other["id"] != project["id"]:
                        other_root = Path(other["working_directory"]).resolve()
                        if len(other_root.parts) > len(root.parts) and (cwd_path == other_root or cwd_path.is_relative_to(other_root)):
                            return False
            if cwd_path == root or cwd_path.is_relative_to(root) or os.path.normcase(str(cwd_path)).startswith(os.path.normcase(str(root))):
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
        pass

    try:
        cmdline = process.cmdline()
        if cmdline:
            cmd_str = " ".join(cmdline)
            root_str = str(root)
            if root_str in cmd_str or os.path.normcase(root_str) in os.path.normcase(cmd_str):
                return True
            orig_cmd = project.get("command") or []
            for part in orig_cmd[1:]:
                if any(part.lower().endswith(ext) for ext in [".py", ".ps1", ".bat", ".cmd", ".mjs", ".js"]):
                    script_path = (root / part).resolve()
                    if str(script_path) in cmd_str or os.path.normcase(str(script_path)) in os.path.normcase(cmd_str):
                        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
        pass

    return False


def build_process_cache(tcp_items: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    protected = {os.getpid(), 0, 4, *(p.pid for p in psutil.Process().parents())}
    pids = {row.get("pid") for row in tcp_items if row.get("pid") and row["pid"] not in protected}
    cache: dict[int, dict[str, Any]] = {}
    for pid in pids:
        try:
            p = psutil.Process(pid)
            cache[pid] = {
                "process": p,
                "cwd": p.cwd(),
                "cmdline": p.cmdline(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            continue
    return cache


def discover_project_drift_ports(
    project: dict[str, Any],
    tcp_items: list[dict[str, Any]],
    all_projects: list[dict[str, Any]] | None = None,
    proc_cache: dict[int, dict[str, Any]] | None = None,
) -> list[int]:
    expected = set(project.get("expected_ports", []))
    root = Path(project["working_directory"]).resolve()
    protected = {os.getpid(), 0, 4, *(p.pid for p in psutil.Process().parents())}
    pid_ports: dict[int, set[int]] = {}
    for row in tcp_items:
        pid = row.get("pid")
        port = row.get("port")
        if pid and pid not in protected and port and 0 < port <= 65535:
            pid_ports.setdefault(pid, set()).add(port)

    all_other_expected: set[int] = set()
    if all_projects:
        for p in all_projects:
            if p["id"] != project["id"]:
                for ep in p.get("expected_ports", []):
                    all_other_expected.add(ep)

    discovered: set[int] = set()
    for pid, ports in pid_ports.items():
        if proc_cache is not None:
            if pid not in proc_cache:
                continue
            proc = proc_cache[pid]["process"]
        else:
            try:
                proc = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            if is_owned_by_project(proc, root, project, all_projects):
                for port in ports:
                    if port not in expected and port not in all_other_expected:
                        discovered.add(port)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(discovered)


def owned_listeners(project: dict[str, Any]) -> list[psutil.Process]:
    """Re-discover ownership after console restarts; never kill by port alone."""
    check_ports = set(project.get("expected_ports", []))
    if "discovered_ports" in project:
        check_ports.update(project.get("discovered_ports", []))
    rows = [row for row in collect_ports().get("items", [])
            if row["protocol"] == "TCP" and row["port"] in check_ports]
    root = Path(project["working_directory"]).resolve()
    protected = {os.getpid(), 0, 4, *(p.pid for p in psutil.Process().parents())}
    found = []
    has_foreign = False
    for pid in sorted({row["pid"] for row in rows}):
        if pid in protected or any(row.get("services") for row in rows if row["pid"] == pid):
            raise RuntimeError("端口由系统服务或工作台自身使用，不能作为普通项目停止")
        try:
            process = psutil.Process(pid)
            process.create_time()  # Cache identity to guard against PID reuse during termination.
            if is_owned_by_project(process, root, project):
                found.append(process)
            else:
                has_foreign = True
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            has_foreign = True
            continue
    if not found and has_foreign:
        raise RuntimeError("端口被其他目录的程序占用，未确认属于这个项目")
    return found


def derive_effective_url(configured_url: str, old_ports: list[int], new_port: int | None) -> str:
    if not new_port:
        return configured_url or ""
    if not configured_url:
        return f"http://127.0.0.1:{new_port}/"
    for op in old_ports:
        if f":{op}" in configured_url:
            return configured_url.replace(f":{op}", f":{new_port}")
    m = re.search(r":(\d+)", configured_url)
    if m:
        return configured_url[:m.start()] + f":{new_port}" + configured_url[m.end():]
    parsed = urlparse(configured_url)
    if parsed.netloc and ":" not in parsed.netloc:
        netloc = f"{parsed.netloc}:{new_port}"
        return urlunparse(parsed._replace(netloc=netloc))
    return configured_url


def project_state(
    project: dict[str, Any],
    active_ports: set[int],
    tcp_items: list[dict[str, Any]] | None = None,
    all_projects: list[dict[str, Any]] | None = None,
    proc_cache: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    tracked = MANAGED_PROCESSES.get(project["id"])
    managed_running = bool(tracked and tracked.poll() is None)

    drift_ports: list[int] = []
    if tcp_items is not None:
        drift_ports = discover_project_drift_ports(project, tcp_items, all_projects, proc_cache)

    expected_listening = bool(project["expected_ports"] and any(port in active_ports for port in project["expected_ports"]))
    drift_listening = bool(drift_ports)
    path_exists = project.get("path_exists", True)

    if managed_running:
        if expected_listening or drift_listening:
            state = "running"
        elif project["expected_ports"]:
            state = "starting"
        else:
            state = "running"
        pid = tracked.pid
    elif expected_listening or drift_listening:
        state = "running"
        pid = None
    elif not path_exists:
        state = "missing"
        pid = None
    elif tracked and tracked.poll() is not None:
        state = "stopped"
        pid = tracked.pid
    else:
        state = "stopped" if project["expected_ports"] else "unknown"
        pid = None

    if not project.get("enabled", True):
        lifecycle = "archived"
    elif state == "missing":
        lifecycle = "archive_candidate"
    else:
        lifecycle = "tracked"

    if state == "missing":
        consistency = "definition_missing"
    elif drift_listening:
        consistency = "port_drift"
    else:
        consistency = "synced"

    active_expected = [p for p in project.get("expected_ports", []) if p in active_ports]
    if drift_listening:
        effective_port = drift_ports[0]
        effective_ports = drift_ports
    elif active_expected:
        effective_port = active_expected[0]
        effective_ports = active_expected
    elif project.get("expected_ports"):
        effective_port = project["expected_ports"][0]
        effective_ports = project["expected_ports"]
    else:
        effective_port = None
        effective_ports = []

    configured_url = project.get("url", "")
    if drift_listening or (active_expected and configured_url):
        effective_url = derive_effective_url(configured_url, project.get("expected_ports", []), effective_port)
    else:
        effective_url = configured_url

    public = {key: value for key, value in project.items() if key not in {"command", "stop_command", "environment"}}
    public.update({
        "state": state,
        "lifecycle": lifecycle,
        "consistency": consistency,
        "port_drift": drift_listening,
        "discovered_ports": drift_ports,
        "effective_port": effective_port,
        "effective_ports": effective_ports,
        "effective_url": effective_url,
        "configured_url": configured_url,
        "url": effective_url,
        "path_exists": path_exists,
        "managed_pid": pid,
        "can_start": bool(project["enabled"] and state not in ("running", "starting") and path_exists),
    })
    stoppable_owner = project["type"] != "command" or managed_running or bool(project.get("stop_command"))
    public["can_stop"] = bool(project["allow_stop"] and state in ("running", "starting") and stoppable_owner)
    reason = ""
    if not project["allow_stop"]:
        reason = project.get("stop_disabled_reason") or "该项目尚未配置网页停止方式"
    elif state not in ("running", "starting"):
        if state == "missing":
            reason = "项目目录不存在，无法在此启动或停止"
        else:
            reason = "项目没有运行"
    elif not stoppable_owner:
        try:
            public["can_stop"] = bool(owned_listeners(public))
            if not public["can_stop"]:
                reason = "没有找到可核对的运行程序，请刷新后重试"
        except RuntimeError as exc:
            reason = str(exc)
    public["stop_reason"] = reason
    return public


def save_observed_state(items: list[dict[str, Any]]) -> None:
    try:
        observed = {
            "updated_at": now_text(),
            "projects": {
                item["id"]: {
                    "state": item["state"],
                    "lifecycle": item.get("lifecycle", "tracked"),
                    "consistency": item.get("consistency", "synced"),
                    "expected_ports": item.get("expected_ports", []),
                    "discovered_ports": item.get("discovered_ports", []),
                    "effective_port": item.get("effective_port"),
                    "effective_url": item.get("effective_url"),
                    "port_drift": item.get("port_drift", False),
                    "path_exists": item.get("path_exists", True),
                }
                for item in items
            }
        }
        obs_path = ROOT / "config" / "observed-state.json"
        temp_path = obs_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(observed, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(temp_path, obs_path)
    except OSError as exc:
        append_action(f"OBSERVED_STATE save_failed error={exc}")


def save_config_atomic(config: dict[str, Any]) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = CONFIG_PATH.parent / f"projects.backup-{ts}.json"
    if CONFIG_PATH.exists() and not backup_path.exists():
        shutil.copy2(CONFIG_PATH, backup_path)
    temp_path = CONFIG_PATH.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(temp_path, CONFIG_PATH)


def toggle_project_archive(project_id: str, archive: bool) -> dict[str, Any]:
    config = load_json(CONFIG_PATH, None)
    if not isinstance(config, dict) or "projects" not in config:
        raise RuntimeError("无法读取配置文件 projects.json")
    target = None
    for p in config.get("projects", []):
        if isinstance(p, dict) and p.get("id") == project_id:
            target = p
            break
    if not target:
        raise KeyError(f"项目 {project_id} 不存在于主配置文件中")
    target["enabled"] = not archive
    tags = list(target.get("tags", []))
    if archive:
        if "已归档" not in tags:
            tags.append("已归档")
    else:
        tags = [t for t in tags if t != "已归档"]
    target["tags"] = tags
    save_config_atomic(config)
    append_action(f"PROJECT {'archive' if archive else 'restore'} id={project_id}")
    return {"id": project_id, "enabled": target["enabled"], "tags": tags}


def sync_project_drift_port(project_id: str, target_port: int | None = None) -> dict[str, Any]:
    projects, _ = load_project_catalog()
    current_proj = next((p for p in projects if p["id"] == project_id), None)
    if not current_proj:
        raise KeyError("项目不存在")

    if target_port is None:
        ports_data = collect_ports()
        tcp_items = [row for row in ports_data.get("items", []) if row.get("protocol") == "TCP"]
        drift_ports = discover_project_drift_ports(current_proj, tcp_items, projects)
        if not drift_ports:
            raise ValueError("未检测到该项目有漂移端口")
        target_port = drift_ports[0]

    config = load_json(CONFIG_PATH, None)
    if not isinstance(config, dict) or "projects" not in config:
        raise RuntimeError("无法读取配置文件 projects.json")
    target = None
    for p in config.get("projects", []):
        if isinstance(p, dict) and p.get("id") == project_id:
            target = p
            break
    if not target:
        raise KeyError(f"项目 {project_id} 不存在于主配置文件中")

    old_ports = list(target.get("expected_ports", []))
    if target_port not in old_ports:
        if len(old_ports) <= 1:
            target["expected_ports"] = [target_port]
        else:
            target["expected_ports"] = sorted(set(old_ports + [target_port]))

    url = target.get("url", "")
    if url and old_ports:
        for op in old_ports:
            if f":{op}" in url:
                target["url"] = url.replace(f":{op}", f":{target_port}")
                break

    save_config_atomic(config)
    append_action(f"PROJECT sync_port id={project_id} old_ports={old_ports} new_ports={target['expected_ports']}")
    return {"id": project_id, "expected_ports": target["expected_ports"], "url": target.get("url")}


def delete_project(project_id: str) -> dict[str, Any]:
    config = load_json(CONFIG_PATH, None)
    if not isinstance(config, dict) or "projects" not in config:
        raise RuntimeError("无法读取配置文件 projects.json")
    if project_id == "port-atlas":
        raise ValueError("工作台控制台自身 (port-atlas) 不允许删除")
    target_idx = None
    target = None
    for idx, p in enumerate(config.get("projects", [])):
        if isinstance(p, dict) and p.get("id") == project_id:
            target_idx = idx
            target = p
            break
    if target is None or target_idx is None:
        raise KeyError(f"项目 {project_id} 不存在于主配置文件中")

    deleted_item = config["projects"].pop(target_idx)
    save_config_atomic(config)
    append_action(f"PROJECT delete id={project_id} name={deleted_item.get('name')}")
    return {"id": project_id, "deleted": True, "name": deleted_item.get("name")}


def catalog_payload() -> dict[str, Any]:
    projects, errors = load_project_catalog()
    ports_data = collect_ports()
    tcp_items = [row for row in ports_data.get("items", []) if row.get("protocol") == "TCP"]
    active_ports = {int(row["port"]) for row in tcp_items if row.get("port")}
    proc_cache = build_process_cache(tcp_items)
    items = [project_state(project, active_ports, tcp_items, projects, proc_cache) for project in projects]
    payload = {
        "ok": True,
        "generated_at": now_text(),
        "items": items,
        "errors": errors,
        "capabilities": {
            "docker": bool(shutil.which("docker")),
            "process_compose": bool(shutil.which("process-compose")),
            "powershell": bool(shutil.which("pwsh") or shutil.which("powershell")),
        },
    }
    save_observed_state(items)
    return payload


def find_project(project_id: str) -> dict[str, Any]:
    projects, _ = load_project_catalog()
    for project in projects:
        if project["id"] == project_id:
            return project
    raise KeyError("项目不存在")


def run_checked(command: list[str], cwd: str, timeout: int = 30) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    return {
        "ok": completed.returncode == 0,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip()[-4000:],
        "stderr": completed.stderr.strip()[-4000:],
    }


def validate_command(command: list[str], cwd: Path) -> list[str]:
    executable = os.path.expandvars(os.path.expanduser(command[0]))
    executable_path = Path(executable)
    if executable_path.is_absolute():
        if not executable_path.is_file():
            raise RuntimeError(f"启动程序不存在：{executable_path}")
        resolved = str(executable_path)
    else:
        resolved = shutil.which(executable, path=os.environ.get("PATH")) or ""
        if not resolved:
            candidate = cwd / executable
            if candidate.is_file():
                resolved = str(candidate)
            else:
                raise RuntimeError(f"找不到启动程序：{executable}")
    return [resolved, *command[1:]]


def start_project(project: dict[str, Any]) -> dict[str, Any]:
    if not project["enabled"]:
        raise RuntimeError("项目已禁用")
    active = listening_ports()
    if project["expected_ports"] and any(port in active for port in project["expected_ports"]):
        return {"ok": True, "already_running": True, "message": "项目端口已经在监听"}
    cwd = Path(project["working_directory"])
    if not cwd.is_dir():
        raise RuntimeError(f"工作目录不存在：{cwd}")
    project_type = project["type"]
    append_action(f"START requested project={project['id']} type={project_type}")
    if project_type == "windows-service":
        result = run_checked(["sc.exe", "start", project["service_name"]], str(cwd))
        if not result["ok"]:
            raise RuntimeError(result["stderr"] or result["stdout"] or "Windows 服务启动失败")
        response: dict[str, Any] = result
    elif project_type == "docker-compose":
        if not shutil.which("docker"):
            raise RuntimeError("未安装 Docker")
        compose_file = Path(project["compose_file"])
        if not compose_file.is_file():
            raise RuntimeError(f"Compose 文件不存在：{compose_file}")
        response = run_checked(["docker", "compose", "-f", str(compose_file), "up", "-d"], str(cwd), 120)
        if not response["ok"]:
            raise RuntimeError(response["stderr"] or response["stdout"] or "Docker Compose 启动失败")
    else:
        command = validate_command(project["command"], cwd)
        log_path = LOG_DIR / f"project-{project['id']}.log"
        log_handle = log_path.open("a", encoding="utf-8")
        env = {**os.environ, **project.get("environment", {})}
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            shell=False,
            env=env,
            creationflags=creationflags,
        )
        log_handle.close()
        MANAGED_PROCESSES[project["id"]] = process
        response = {"ok": True, "pid": process.pid, "log": str(log_path)}
    PORT_CACHE["time"] = 0.0
    deadline = time.monotonic() + 8.0
    observed = False
    while project["expected_ports"] and time.monotonic() < deadline:
        if project_type == "command" and process.poll() is not None:
            # 进程意外提前退出，提取日志末尾错误
            MANAGED_PROCESSES.pop(project["id"], None)
            err_msg = ""
            if log_path.exists():
                try:
                    err_msg = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-10:])
                except Exception:
                    pass
            raise RuntimeError(f"进程启动后立即退出 (ExitCode: {process.returncode}):\n{err_msg or '请查看控制台日志'}")
        time.sleep(0.3)
        PORT_CACHE["time"] = 0.0
        if any(port in listening_ports() for port in project["expected_ports"]):
            observed = True
            break
    response["ports_observed"] = observed if project["expected_ports"] else None
    append_action(f"START completed project={project['id']} ok=true")
    return response


def kill_process_targets(targets: list[psutil.Process]) -> None:
    protected = {os.getpid(), 0, 4}
    all_pids: set[int] = set()
    for target in targets:
        if target.pid in protected:
            continue
        all_pids.add(target.pid)
        try:
            for child in target.children(recursive=True):
                if child.pid not in protected:
                    all_pids.add(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    for pid in all_pids:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill.exe", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception:
                pass
        try:
            p = psutil.Process(pid)
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def stop_project(project: dict[str, Any]) -> dict[str, Any]:
    if not project["allow_stop"]:
        raise RuntimeError("该项目未允许从网页停止")
    project_type = project["type"]
    append_action(f"STOP requested project={project['id']} type={project_type}")
    if project_type == "windows-service":
        response = run_checked(["sc.exe", "stop", project["service_name"]], project["working_directory"])
    elif project_type == "docker-compose":
        compose_file = Path(project["compose_file"])
        response = run_checked(
            ["docker", "compose", "-f", str(compose_file), "stop"],
            project["working_directory"],
            120,
        )
    else:
        if project.get("stop_command"):
            command = validate_command(project["stop_command"], Path(project["working_directory"]))
            response = run_checked(command, project["working_directory"], 180)
        else:
            process = MANAGED_PROCESSES.get(project["id"])
            PORT_CACHE["time"] = 0.0
            targets = owned_listeners(project)
            if process and process.poll() is None:
                try:
                    targets.append(psutil.Process(process.pid))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if not targets:
                raise RuntimeError("没有找到属于该项目的运行程序，请刷新后重试")
            kill_process_targets(targets)
            response = {"ok": True, "exit_code": 0, "stdout": "", "stderr": ""}
    if not response.get("ok"):
        raise RuntimeError(response.get("stderr") or response.get("stdout") or "停止失败")
    PORT_CACHE["time"] = 0.0
    deadline = time.monotonic() + 15
    while project["expected_ports"]:
        remaining = set(project["expected_ports"]) & listening_ports()
        if not remaining:
            break
        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError(f"停止指令已执行，但端口 {sorted(remaining)} 仍在运行，可能有自动重启程序")
        # 兜底：如果停止指令发出 8 秒后端口仍未释放，尝试识别并清除属于该项目的残留监听进程
        if now > deadline - 7:
            try:
                lingering = owned_listeners(project)
                if lingering:
                    kill_process_targets(lingering)
            except Exception:
                pass
        time.sleep(0.5)
        PORT_CACHE["time"] = 0.0
    MANAGED_PROCESSES.pop(project["id"], None)
    append_action(f"STOP completed project={project['id']} ok=true")
    return response


def allowed_host(value: str) -> bool:
    host = value.strip().lower()
    if host.startswith("["):
        hostname = host.split("]", 1)[0] + "]"
    else:
        hostname = host.split(":", 1)[0]
    return hostname in {"127.0.0.1", "localhost", "[::1]"}


class Handler(BaseHTTPRequestHandler):
    server_version = "PortConsole/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        append_action(f"HTTP client={self.client_address[0]} {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
        )
        super().end_headers()

    def valid_request_host(self) -> bool:
        return allowed_host(self.headers.get("Host", "")) and self.client_address[0] in {"127.0.0.1", "::1"}

    def send_json(self, value: Any, status: int = 200) -> None:
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, path: Path) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def send_skills(self) -> None:
        try:
            page = (SKILL_STATIC / 'personal.html').read_text(encoding='utf-8')
        except OSError:
            self.send_json({'error': '技能页面文件不可用，请检查技能管理台安装目录'}, 503)
            return
        page = page.replace('href="/personal.css"', 'href="/skills-assets/personal.css"').replace('src="/personal.js"', 'src="/skills-assets/personal.js"').replace('<body>', '<body data-integrated="true">')
        body = page.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(body)

    def proxy_skills(self, method='GET', payload=None) -> None:
        # A fixed local backend and explicit route list; never proxy arbitrary URLs.
        conn = HTTPConnection('127.0.0.1', 8765, timeout=25)
        try:
            headers = {'Content-Type': 'application/json'}
            conn.request(method, self.path, body=json_bytes(payload) if payload is not None else None, headers=headers)
            response = conn.getresponse()
            value = json.loads(response.read(20_000_001))
            self.send_json(value, response.status)
        except (OSError, ValueError) as exc:
            self.send_json({'error': '技能服务暂时无法连接，请到项目控制启动“个人技能库”。项目端口功能仍可使用。'}, 503)
        finally:
            conn.close()

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            raise ValueError("请求体过大")
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def require_action_token(self) -> bool:
        if not secrets.compare_digest(self.headers.get("X-Port-Console-Token", ""), SESSION_TOKEN):
            self.send_json({"ok": False, "error": "操作令牌无效，请刷新页面"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def do_GET(self) -> None:
        if not self.valid_request_host():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            if path in {'/skills', '/skills/'}:
                self.send_skills()
                return
            if path in {'/skills-assets/personal.js', '/skills-assets/personal.css'}:
                self.send_static(SKILL_STATIC / path.rsplit('/', 1)[1])
                return
            if path in {'/api/personal', '/api/personal/detail'}:
                self.proxy_skills()
                return
            if path == "/api/health":
                self.send_json(
                    {
                        "ok": True,
                        "host": HOST,
                        "port": self.server.server_address[1],
                        "pid": os.getpid(),
                        "started_at": STARTED_AT,
                    }
                )
                return
            if path == "/api/session":
                self.send_json({"ok": True, "token": SESSION_TOKEN})
                return
            if path == "/api/ports":
                self.send_json(collect_ports(force=parsed.query == "refresh=1"))
                return
            if path == "/api/projects":
                self.send_json(catalog_payload())
                return
            if path == "/api/actions":
                lines = []
                if ACTION_LOG.exists():
                    lines = ACTION_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-80:]
                self.send_json({"ok": True, "items": lines})
                return
            if path == "/":
                self.send_static(STATIC_ROOT / "index.html")
                return
            candidate = (STATIC_ROOT / path.lstrip("/")).resolve()
            if candidate != STATIC_ROOT.resolve() and STATIC_ROOT.resolve() not in candidate.parents:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            self.send_static(candidate)
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:
        if not self.valid_request_host():
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not self.require_action_token():
            return
        parsed = urlparse(self.path)
        if parsed.path in {'/api/personal/label', '/api/personal/scan'}:
            if self.headers.get('Origin') not in {None, 'http://' + self.headers.get('Host', '')}:
                self.send_json({'error': '不接受其他网站发来的修改'}, 403)
                return
            try:
                payload = self.read_json()
                if not isinstance(payload, dict): raise ValueError('请求格式无效')
                self.proxy_skills('POST', payload)
            except (ValueError, OSError) as exc:
                self.send_json({'error': str(exc)}, 400)
            return
        match = re.fullmatch(r"/api/projects/([a-zA-Z0-9_.-]+)/(start|stop|archive|restore|sync-port|delete)", parsed.path)
        if not match:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        project_id = match.group(1)
        action = match.group(2)
        try:
            payload = self.read_json() if action == "sync-port" else {}
            with ACTION_LOCK:
                if action == "start":
                    project = find_project(project_id)
                    result = start_project(project)
                elif action == "stop":
                    project = find_project(project_id)
                    result = stop_project(project)
                elif action == "archive":
                    result = toggle_project_archive(project_id, archive=True)
                elif action == "restore":
                    result = toggle_project_archive(project_id, archive=False)
                elif action == "sync-port":
                    target_port = payload.get("port") if isinstance(payload, dict) else None
                    result = sync_project_drift_port(project_id, target_port)
                elif action == "delete":
                    result = delete_project(project_id)
            self.send_json({"ok": True, "result": result, "projects": catalog_payload()})
        except KeyError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
        except (ValueError, RuntimeError, OSError, psutil.Error, subprocess.TimeoutExpired) as exc:
            append_action(f"ACTION failed path={parsed.path} error={exc}")
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)


def create_server(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> int:
    server = create_server()
    pid_file = RUNTIME_DIR / "server.pid"
    pid_file.write_text(str(os.getpid()), encoding="ascii")
    append_action(f"SERVER start host={HOST} port={PORT} pid={os.getpid()}")
    print(f"本机端口控制台：http://{HOST}:{PORT}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            if pid_file.read_text(encoding="ascii").strip() == str(os.getpid()):
                pid_file.unlink()
        except OSError:
            pass
        append_action("SERVER stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
