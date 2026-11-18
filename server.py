from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
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
SERVICE_CACHE_LOCK = threading.Lock()
SERVICE_CACHE: dict[str, Any] = {"time": 0.0, "by_pid": {}}
MANIFEST_CACHE_LOCK = threading.Lock()
MANIFEST_CACHE: dict[tuple[Any, ...], tuple[float, list[Path]]] = {}
MANAGED_PROCESSES: dict[str, subprocess.Popen[Any]] = {}
MANAGED_START_TIMES: dict[str, float] = {}
PROJECT_CRASH_INFO: dict[str, dict[str, Any]] = {}

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
    "env",
    ".conda",
    "node_modules",
    ".pnpm",
    ".cache",
    "dist",
    "build",
    "out",
    "outputs",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
    "vendor",
    "models",
    "checkpoints",
    "_backups",
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


def _collect_services_by_pid(target_pids: set[int]) -> dict[int, list[dict[str, Any]]]:
    """按进程 PID 获取关联的 Windows 服务列表，仅对目标监听 PID 查询属性以降低 SCM 句柄开销。"""
    if os.name != "nt" or not target_pids or not hasattr(psutil, "win_service_iter"):
        return {}
    now_mono = time.monotonic()
    with SERVICE_CACHE_LOCK:
        cached: dict[int, list[dict[str, Any]]] = SERVICE_CACHE["by_pid"]
        if SERVICE_CACHE["time"] > 0 and now_mono - SERVICE_CACHE["time"] < 45.0:
            missing = [pid for pid in target_pids if pid not in cached]
            if not missing:
                return {pid: cached[pid] for pid in target_pids if cached.get(pid)}
        by_pid: dict[int, list[dict[str, Any]]] = {pid: [] for pid in target_pids}
        try:
            for svc in psutil.win_service_iter():
                try:
                    spid = svc.pid()
                    if spid and int(spid) in target_pids:
                        by_pid.setdefault(int(spid), []).append({
                            "name": str(svc.name() or ""),
                            "display_name": str(svc.display_name() or ""),
                            "state": str(svc.status() or ""),
                            "start_mode": str(svc.start_type() or ""),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except OSError:
            return {}
        SERVICE_CACHE["time"] = now_mono
        SERVICE_CACHE["by_pid"] = {**cached, **by_pid}
        return {pid: by_pid[pid] for pid in target_pids if by_pid.get(pid)}


def _collect_ports_via_psutil() -> list[dict[str, Any]]:
    """优先使用 psutil 进程内直接读取本机监听套接字，将单次扫描从秒级降至毫秒级。"""
    connections = psutil.net_connections(kind="inet")
    raw_entries: list[tuple[str, str, int, int, str]] = []
    pids: set[int] = set()
    for conn in connections:
        if not conn.laddr:
            continue
        address = str(conn.laddr.ip or "")
        port = int(conn.laddr.port or 0)
        if port <= 0:
            continue
        pid = int(conn.pid or 0)
        if conn.type == socket.SOCK_STREAM:
            if conn.status != psutil.CONN_LISTEN:
                continue
            protocol, state = "TCP", "Listen"
        elif conn.type == socket.SOCK_DGRAM:
            protocol, state = "UDP", "Bound"
        else:
            continue
        raw_entries.append((protocol, address, port, pid, state))
        if pid > 0:
            pids.add(pid)

    proc_map: dict[int, tuple[str, str]] = {}
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            pname = str(proc.name() or "")
            try:
                pexe = str(proc.exe() or "")
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pexe = ""
            proc_map[pid] = (pname, pexe)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            proc_map[pid] = ("", "")

    svc_map = _collect_services_by_pid(pids)
    rows: list[dict[str, Any]] = []
    for protocol, address, port, pid, state in raw_entries:
        pname, pexe = proc_map.get(pid, ("", ""))
        rows.append({
            "protocol": protocol,
            "address": address,
            "port": port,
            "pid": pid,
            "process": pname,
            "executable": pexe,
            "services": svc_map.get(pid, []),
            "state": state,
        })
    return rows


def collect_ports_uncached() -> dict[str, Any]:
    started = time.monotonic()
    rows: list[dict[str, Any]]
    try:
        rows = _collect_ports_via_psutil()
    except Exception:
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
        parsed_rows = json.loads(raw) if raw else []
        rows = [parsed_rows] if isinstance(parsed_rows, dict) else parsed_rows
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


def discover_manifests(scan_roots: list[str], max_depth: int = 4, use_cache: bool = False) -> list[Path]:
    cache_key = (tuple(str(normalized_path(r)) for r in scan_roots), max_depth)
    if use_cache:
        with MANIFEST_CACHE_LOCK:
            hit = MANIFEST_CACHE.get(cache_key)
            if hit and time.monotonic() - hit[0] < 60.0:
                return list(hit[1])

    manifests: list[Path] = []
    for root_text in scan_roots:
        root = normalized_path(root_text)
        if not root.is_dir():
            continue
        root_depth = len(root.parts)
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.parts) - root_depth
            dirs[:] = [name for name in dirs if name not in IGNORED_SCAN_DIRS and not name.startswith(".") and depth < max_depth]
            if "port-console.project.json" in files:
                manifests.append(current_path / "port-console.project.json")
                if len(manifests) >= 250:
                    break
        if len(manifests) >= 250:
            break

    if use_cache:
        with MANIFEST_CACHE_LOCK:
            MANIFEST_CACHE[cache_key] = (time.monotonic(), list(manifests))
    return manifests


def load_project_catalog() -> tuple[list[dict[str, Any]], list[str]]:
    config = load_json(CONFIG_PATH, {"projects": [], "scan_roots": []})
    projects: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    sources: list[tuple[dict[str, Any], Path]] = [
        (raw, CONFIG_PATH) for raw in config.get("projects", []) if isinstance(raw, dict)
    ]
    for manifest in discover_manifests([str(item) for item in config.get("scan_roots", [])], use_cache=True):
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


GENERIC_RUNNER_EXES = {
    "python", "python.exe", "pythonw", "pythonw.exe",
    "node", "node.exe", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "npm", "npm.cmd", "npx", "npx.cmd", "pnpm", "pnpm.cmd", "yarn", "yarn.cmd",
    "uv", "uv.exe", "schtasks", "schtasks.exe",
}

SIDECAR_PROCESS_EXES = {
    "cloudflared.exe", "ngrok.exe", "frpc.exe", "tunnel-client.exe",
    "language_server.exe", "code.exe", "antigravity.exe",
}

SCRIPT_EXTENSIONS = (".py", ".ps1", ".bat", ".cmd", ".mjs", ".js", ".cjs", ".ts", ".yaml", ".yml")


def _is_claimed_by_deeper_project(
    target_path: Path,
    root: Path,
    project_id: str,
    all_projects: list[dict[str, Any]] | None,
) -> bool:
    """当父目录与子目录同时登记为不同项目时，子目录内的进程归属子项目而非父项目。"""
    if not all_projects:
        return False
    for other in all_projects:
        if other["id"] == project_id:
            continue
        try:
            other_root = Path(other["working_directory"]).resolve()
            if len(other_root.parts) > len(root.parts) and (target_path == other_root or target_path.is_relative_to(other_root)):
                return True
        except (ValueError, OSError):
            continue
    return False


def _path_within_root(target_path: Path, root: Path) -> bool:
    try:
        if target_path == root or target_path.is_relative_to(root):
            return True
    except ValueError:
        pass
    norm_target = os.path.normcase(str(target_path)).rstrip("\\/")
    norm_root = os.path.normcase(str(root)).rstrip("\\/")
    return norm_target == norm_root or norm_target.startswith(norm_root + os.sep)


def _extract_entry_signatures(orig_cmd: list[str], root: Path) -> tuple[list[Path], list[str]]:
    """提取启动命令中真正具备项目身份特征的入口脚本路径与 Python -m 模块名，剔除 /c、run、127.0.0.1 等通用词。"""
    script_paths: list[Path] = []
    module_names: list[str] = []
    generic_modules = {"pip", "venv", "unittest", "http.server", " npm", "npx"}

    for idx, part in enumerate(orig_cmd[1:], start=1):
        if not part or part.startswith("-") or part.startswith("/"):
            continue
        prev = orig_cmd[idx - 1]
        if prev == "-m" and part.lower() not in generic_modules:
            module_names.append(part)
            continue
        lower = part.lower()
        base_name = Path(part).name.lower()
        if base_name in GENERIC_RUNNER_EXES:
            continue
        if lower.endswith(SCRIPT_EXTENSIONS):
            try:
                candidate = Path(os.path.expandvars(os.path.expanduser(part)))
                resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
                script_paths.append(resolved)
            except (ValueError, OSError):
                continue
    return script_paths, module_names


def is_owned_by_project(
    process: psutil.Process,
    root: Path,
    project: dict[str, Any],
    all_projects: list[dict[str, Any]] | None = None,
    strict_for_drift: bool = False,
    proc_meta: dict[str, Any] | None = None,
) -> bool:
    if project.get("id") == "port-atlas" and process.pid == os.getpid():
        return True

    managed = MANAGED_PROCESSES.get(project["id"])
    if managed and managed.poll() is None:
        if process.pid == managed.pid:
            return True
        if proc_meta and "parent_pids" in proc_meta:
            if managed.pid in proc_meta["parent_pids"]:
                return True
        else:
            try:
                if managed.pid in {p.pid for p in process.parents()}:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    orig_cmd = project.get("command") or []
    cmd_exe_name = Path(orig_cmd[0]).name.lower() if orig_cmd else ""
    if proc_meta is not None and "name" in proc_meta:
        proc_name = str(proc_meta["name"] or "").lower()
    else:
        try:
            proc_name = (process.name() or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            proc_name = ""

    # 严格漂移探测时排除隧道客户端与 IDE 语言服务等非项目主服务进程
    if strict_for_drift and proc_name in SIDECAR_PROCESS_EXES and proc_name != cmd_exe_name:
        return False

    script_paths, module_names = _extract_entry_signatures(orig_cmd, root)

    if proc_meta is not None and "cmdline" in proc_meta:
        cmdline = proc_meta["cmdline"] or []
    else:
        try:
            cmdline = process.cmdline() or []
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            cmdline = []

    if cmdline:
        cmd_norm = os.path.normcase(" ".join(cmdline))
        norm_args = [os.path.normcase(arg.strip("\"'")) for arg in cmdline if arg]
        # 1. 精确匹配入口脚本绝对路径
        for sp in script_paths:
            sp_norm = os.path.normcase(str(sp))
            if sp_norm in norm_args or sp_norm in cmd_norm:
                if not _is_claimed_by_deeper_project(sp, root, project["id"], all_projects):
                    return True
        # 2. 精确匹配 Python -m 业务模块名
        for mod in module_names:
            if mod in cmdline:
                return True
        # 3. 非漂移严格模式下，若命令行参数直接引用了项目根目录下的文件则视为归属
        if not strict_for_drift:
            root_norm = os.path.normcase(str(root)).rstrip("\\/")
            if any(arg == root_norm or arg.startswith(root_norm + os.sep) for arg in norm_args):
                return True

    exe: str = ""
    if proc_meta is not None and "exe" in proc_meta:
        exe = str(proc_meta["exe"] or "")
    else:
        try:
            exe = process.exe() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            exe = ""
    if exe:
        try:
            exe_path = Path(exe).resolve()
            if _path_within_root(exe_path, root) and not _is_claimed_by_deeper_project(exe_path, root, project["id"], all_projects):
                if not strict_for_drift or exe_path.name.lower() not in GENERIC_RUNNER_EXES or not module_names:
                    return True
        except (ValueError, OSError):
            pass

    cwd: str = ""
    if proc_meta is not None and "cwd" in proc_meta:
        cwd = str(proc_meta["cwd"] or "")
    else:
        try:
            cwd = process.cwd() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            cwd = ""
    if cwd:
        try:
            cwd_path = Path(cwd).resolve()
            if _path_within_root(cwd_path, root) and not _is_claimed_by_deeper_project(cwd_path, root, project["id"], all_projects):
                if not strict_for_drift:
                    return True
                uses_wrapper = any(str(p).lower().endswith((".ps1", ".bat", ".cmd")) for p in script_paths)
                strict_port_locked = "--strictPort" in orig_cmd
                if uses_wrapper and not strict_port_locked and proc_name in {"python.exe", "pythonw.exe", "node.exe", "uvicorn.exe"}:
                    return True
        except (ValueError, OSError):
            pass

    return False


def build_process_cache(tcp_items: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    protected = {0, 4}
    pids = {int(row.get("pid") or 0) for row in tcp_items if row.get("pid") and int(row["pid"]) not in protected}
    row_hints: dict[int, tuple[str, str]] = {}
    for row in tcp_items:
        rpid = int(row.get("pid") or 0)
        if rpid > 0 and rpid not in row_hints:
            row_hints[rpid] = (str(row.get("process") or ""), str(row.get("executable") or ""))

    cache: dict[int, dict[str, Any]] = {}
    need_parents = bool(MANAGED_PROCESSES)
    for pid in pids:
        try:
            p = psutil.Process(pid)
            hint_name, hint_exe = row_hints.get(pid, ("", ""))
            if not hint_name:
                try:
                    hint_name = p.name()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    hint_name = ""
            if not hint_exe:
                try:
                    hint_exe = p.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    hint_exe = ""
            try:
                cwd = p.cwd()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                cwd = ""
            try:
                cmdline = p.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                cmdline = []
            parent_pids: set[int] = set()
            if need_parents:
                try:
                    parent_pids = {pp.pid for pp in p.parents()}
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    parent_pids = set()
            cache[pid] = {
                "process": p,
                "name": hint_name,
                "exe": hint_exe,
                "cwd": cwd,
                "cmdline": cmdline,
                "parent_pids": parent_pids,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, OSError):
            continue
    return cache


def _inspect_expected_port_ownership(
    project: dict[str, Any],
    tcp_items: list[dict[str, Any]],
    all_projects: list[dict[str, Any]] | None = None,
    proc_cache: dict[int, dict[str, Any]] | None = None,
) -> tuple[list[int], list[dict[str, Any]]]:
    """核查项目配置端口上的监听进程归属，返回 (确认归属本项目的端口列表, 外部占用冲突列表)。"""
    expected = project.get("expected_ports") or []
    if not expected:
        return [], []
    root = Path(project["working_directory"]).resolve()
    owned_ports: list[int] = []
    conflicts: list[dict[str, Any]] = []

    for ep in expected:
        rows = [r for r in tcp_items if int(r.get("port") or 0) == ep]
        if not rows:
            continue
        if project.get("type") in {"docker-compose", "windows-service"}:
            owned_ports.append(ep)
            continue
        if project.get("id") == "port-atlas" and any(int(r.get("pid") or 0) == os.getpid() for r in rows):
            owned_ports.append(ep)
            continue

        port_owned = False
        foreign_detail: dict[str, Any] | None = None
        for row in rows:
            pid = int(row.get("pid") or 0)
            if pid <= 0:
                continue
            proc_entry = proc_cache.get(pid) if proc_cache is not None else None
            proc = proc_entry["process"] if proc_entry else None
            if proc is None and proc_cache is None:
                try:
                    proc = psutil.Process(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = None
            if proc is not None:
                try:
                    if is_owned_by_project(proc, root, project, all_projects, strict_for_drift=False, proc_meta=proc_entry):
                        port_owned = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if foreign_detail is None:
                cwd_val = proc_entry.get("cwd", "") if proc_entry else ""
                if not cwd_val and proc is not None and proc_cache is None:
                    try:
                        cwd_val = proc.cwd()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        cwd_val = ""
                foreign_detail = {
                    "port": ep,
                    "pid": pid,
                    "process": str(row.get("process") or "<unknown>"),
                    "executable": str(row.get("executable") or ""),
                    "cwd": cwd_val,
                }
        if port_owned:
            owned_ports.append(ep)
        elif foreign_detail is not None:
            conflicts.append(foreign_detail)

    return owned_ports, conflicts


_PROTECTED_BASE_PIDS: set[int] | None = None


def _get_protected_pids() -> set[int]:
    global _PROTECTED_BASE_PIDS
    if _PROTECTED_BASE_PIDS is None:
        try:
            _PROTECTED_BASE_PIDS = {os.getpid(), 0, 4, *(p.pid for p in psutil.Process().parents())}
        except Exception:
            _PROTECTED_BASE_PIDS = {os.getpid(), 0, 4}
    return _PROTECTED_BASE_PIDS


def discover_project_drift_ports(
    project: dict[str, Any],
    tcp_items: list[dict[str, Any]],
    all_projects: list[dict[str, Any]] | None = None,
    proc_cache: dict[int, dict[str, Any]] | None = None,
) -> list[int]:
    expected = set(project.get("expected_ports", []))
    if not expected or "--strictPort" in (project.get("command") or []):
        return []
    if project.get("type") != "command":
        return []

    owned_expected, _ = _inspect_expected_port_ownership(project, tcp_items, all_projects, proc_cache)
    if owned_expected:
        return []

    root = Path(project["working_directory"]).resolve()
    protected = _get_protected_pids()
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
        proc_entry = proc_cache.get(pid) if proc_cache is not None else None
        if proc_cache is not None:
            if proc_entry is None:
                continue
            proc = proc_entry["process"]
        else:
            try:
                proc = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            if is_owned_by_project(proc, root, project, all_projects, strict_for_drift=True, proc_meta=proc_entry):
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
    owned_expected_ports: list[int] = []
    port_conflicts: list[dict[str, Any]] = []
    if tcp_items is not None:
        owned_expected_ports, port_conflicts = _inspect_expected_port_ownership(
            project, tcp_items, all_projects, proc_cache
        )
        drift_ports = discover_project_drift_ports(project, tcp_items, all_projects, proc_cache)

    if tcp_items is not None and project.get("type") == "command" and not managed_running:
        expected_listening = bool(owned_expected_ports)
    else:
        expected_listening = bool(project["expected_ports"] and any(port in active_ports for port in project["expected_ports"]))

    drift_listening = bool(drift_ports)
    path_exists = project.get("path_exists", True)

    start_time = MANAGED_START_TIMES.get(project["id"])
    is_start_timeout = bool(start_time and (time.monotonic() - start_time > 30.0))

    if managed_running:
        if expected_listening or drift_listening:
            state = "running"
            MANAGED_START_TIMES.pop(project["id"], None)
        elif project["expected_ports"]:
            if is_start_timeout:
                state = "stopped"
                MANAGED_START_TIMES.pop(project["id"], None)
            else:
                state = "starting"
        else:
            state = "running"
        pid = tracked.pid
    elif expected_listening or drift_listening:
        state = "running"
        pid = None
        MANAGED_START_TIMES.pop(project["id"], None)
    elif not path_exists:
        state = "missing"
        pid = None
        MANAGED_START_TIMES.pop(project["id"], None)
    elif tracked and tracked.poll() is not None:
        state = "stopped"
        pid = tracked.pid
        MANAGED_PROCESSES.pop(project["id"], None)
        MANAGED_START_TIMES.pop(project["id"], None)
    else:
        state = "stopped" if project["expected_ports"] else "unknown"
        pid = None
        MANAGED_START_TIMES.pop(project["id"], None)

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
    elif port_conflicts and state != "running":
        consistency = "port_conflict"
    else:
        consistency = "synced"

    active_expected = owned_expected_ports if (tcp_items is not None and project.get("type") == "command") else [
        p for p in project.get("expected_ports", []) if p in active_ports
    ]
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

    # 仅在真正发生端口漂移时改写 URL 端口号，防止覆盖自定义代理路径（如 8787/skills）
    configured_url = project.get("url", "")
    if drift_listening:
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
        "port_conflict": bool(port_conflicts and state != "running"),
        "port_conflicts": port_conflicts,
        "effective_port": effective_port,
        "effective_ports": effective_ports,
        "effective_url": effective_url,
        "configured_url": configured_url,
        "url": effective_url,
        "path_exists": path_exists,
        "managed_pid": pid,
        "can_start": bool(project["enabled"] and state not in ("running", "starting") and path_exists),
        "last_crash": PROJECT_CRASH_INFO.get(project["id"]),
    })
    stoppable_owner = project["type"] != "command" or managed_running or bool(project.get("stop_command"))
    public["can_stop"] = bool(project["allow_stop"] and state in ("running", "starting") and stoppable_owner)
    reason = ""
    if not project["allow_stop"]:
        reason = project.get("stop_disabled_reason") or "该项目尚未配置网页停止方式"
    elif state not in ("running", "starting"):
        if port_conflicts:
            c0 = port_conflicts[0]
            reason = f"端口 {c0['port']} 被其他目录的程序 ({c0['process']} · PID {c0['pid']}) 占用，未确认属于这个项目"
        elif is_start_timeout:
            reason = "启动超时（30秒内未检测到监听端口），请检查日志或重试"
        elif state == "missing":
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



COMMON_MODULE_TO_PACKAGE = {
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "yaml": "PyYAML",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "serial": "pyserial",
    "fitz": "PyMuPDF",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "psutil": "psutil",
}


def analyze_crash_log(log_text: str) -> dict[str, Any]:
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    last_lines = lines[-15:] if len(lines) >= 15 else lines
    joined = "\n".join(last_lines)

    m = re.search(r"ModuleNotFoundError:\s+No module named\s+['\"]([^'\"]+)['\"]", joined)
    if m:
        mod = m.group(1).split(".")[0]
        pkg = COMMON_MODULE_TO_PACKAGE.get(mod, mod)
        return {
            "type": "missing_dependency",
            "module": mod,
            "package": pkg,
            "summary": f"缺少 Python 依赖包: {pkg} (模块名: {mod})",
            "suggestion": f"建议点击【一键安装依赖】安装 {pkg}",
            "can_auto_repair": True,
            "raw_log": joined,
        }

    m_imp = re.search(r"ImportError:\s+(?:cannot import name\s+['\"][^'\"]+['\"]\s+from\s+['\"]([^'\"]+)['\"]|(.*))", joined)
    if m_imp:
        mod = (m_imp.group(1) or m_imp.group(2) or "").split(".")[0]
        pkg = COMMON_MODULE_TO_PACKAGE.get(mod, mod) if mod else ""
        return {
            "type": "import_error",
            "module": mod,
            "package": pkg,
            "summary": f"模块导入错误: {joined.splitlines()[-1]}",
            "suggestion": f"建议重新安装或更新依赖: {pkg or '对应依赖'}",
            "can_auto_repair": bool(pkg),
            "raw_log": joined,
        }

    if "address already in use" in joined.lower() or "winerror 10048" in joined.lower():
        return {
            "type": "port_conflict",
            "summary": "端口冲突：目标端口已被其他进程占用",
            "suggestion": "请在工作台中查看占用该端口的进程，或更改服务端口",
            "can_auto_repair": False,
            "raw_log": joined,
        }

    m_fnf = re.search(r"FileNotFoundError:\s+(.*)", joined)
    if m_fnf:
        return {
            "type": "file_not_found",
            "summary": f"关键文件缺失: {m_fnf.group(1)}",
            "suggestion": "请检查工作目录或文件路径是否完整",
            "can_auto_repair": False,
            "raw_log": joined,
        }

    return {
        "type": "unknown",
        "summary": "进程启动后异常退出",
        "suggestion": "请查看控制台输出定位原因",
        "can_auto_repair": False,
        "raw_log": joined,
    }


def repair_project_dependency(project_id: str, package: str | None = None) -> dict[str, Any]:
    project = find_project(project_id)
    cwd = Path(project["working_directory"]).resolve()
    if not cwd.is_dir():
        raise RuntimeError(f"工作目录不存在: {cwd}")

    if not package:
        crash = PROJECT_CRASH_INFO.get(project_id)
        if crash and crash.get("package"):
            package = crash["package"]
        else:
            log_path = LOG_DIR / f"project-{project_id}.log"
            if log_path.exists():
                text = log_path.read_text(encoding="utf-8", errors="replace")
                analyzed = analyze_crash_log(text)
                package = analyzed.get("package")

    if not package:
        raise ValueError("无法自动识别需要修复的依赖包名称，请指定包名")

    command = project.get("command", [])
    if not command:
        raise RuntimeError("项目未配置启动命令，无法定位 Python 环境")

    raw_exe = os.path.expandvars(os.path.expanduser(command[0]))
    exe_path = Path(raw_exe)
    if not exe_path.is_absolute():
        exe_path = (cwd / exe_path).resolve()

    if not exe_path.is_file():
        candidates = [
            cwd / ".venv" / "Scripts" / "python.exe",
            cwd / "venv" / "Scripts" / "python.exe",
            Path(sys.executable),
        ]
        found = False
        for c in candidates:
            if c.is_file():
                exe_path = c
                found = True
                break
        if not found:
            raise RuntimeError(f"无法定位可用的 Python 解释器: {command[0]}")

    append_action(f"REPAIR start project={project_id} package={package} exe={exe_path}")

    uv_bin = shutil.which("uv")
    if uv_bin:
        cmd = [uv_bin, "pip", "install", "--python", str(exe_path), package]
    else:
        cmd = [str(exe_path), "-m", "pip", "install", package]

    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )

    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "依赖安装失败"
        append_action(f"REPAIR failed project={project_id} package={package} error={err[:100]}")
        raise RuntimeError(f"安装依赖 {package} 失败:\n{err}")

    PROJECT_CRASH_INFO.pop(project_id, None)
    append_action(f"REPAIR success project={project_id} package={package}")
    return {
        "ok": True,
        "project_id": project_id,
        "package": package,
        "message": f"成功为环境安装依赖包 {package}",
    }


def auto_archive_stale_projects() -> dict[str, Any]:
    config = load_json(CONFIG_PATH, None)
    if not isinstance(config, dict) or "projects" not in config:
        raise RuntimeError("无法读取配置文件 projects.json")

    archived_ids = []
    for p in config.get("projects", []):
        if not isinstance(p, dict):
            continue
        pid = p.get("id")
        if pid == "port-atlas":
            continue
        if p.get("enabled", True):
            wd = p.get("working_directory", "")
            if wd and not Path(wd).exists():
                p["enabled"] = False
                tags = list(p.get("tags", []))
                if "已归档" not in tags:
                    tags.append("已归档")
                p["tags"] = tags
                archived_ids.append(pid)

    if archived_ids:
        save_config_atomic(config)
        append_action(f"RECONCILE auto-archived {len(archived_ids)} projects: {', '.join(archived_ids)}")

    return {
        "ok": True,
        "archived_count": len(archived_ids),
        "archived_ids": archived_ids,
    }


def run_system_doctor() -> dict[str, Any]:
    projects, _ = load_project_catalog()
    ports_data = collect_ports()
    tcp_items = [row for row in ports_data.get("items", []) if row.get("protocol") == "TCP"]
    active_ports = {int(row["port"]) for row in tcp_items if row.get("port")}
    proc_cache = build_process_cache(tcp_items)

    items_report = []
    healthy_count = 0
    missing_count = 0
    drift_count = 0
    conflict_count = 0

    for p in projects:
        pid = p["id"]
        name = p["name"]
        enabled = p.get("enabled", True)
        path_exists = p.get("path_exists", True)
        wd = p.get("working_directory", "")

        checks = []
        project_ok = True

        if not path_exists:
            checks.append({
                "item": "工作目录",
                "ok": False,
                "level": "error",
                "message": f"目录已丢失或路径不存在: {wd}",
                "suggestion": "建议点击【归档】以移出活动列表，或修正路径",
            })
            project_ok = False
            missing_count += 1
        else:
            checks.append({"item": "工作目录", "ok": True, "level": "info", "message": "工作目录正常"})

        if p.get("type") == "command" and p.get("command"):
            raw_exe = os.path.expandvars(os.path.expanduser(p["command"][0]))
            exe_p = Path(raw_exe)
            if not exe_p.is_absolute() and path_exists:
                exe_p = (Path(wd) / exe_p).resolve()
            if not exe_p.is_file() and not shutil.which(p["command"][0]):
                checks.append({
                    "item": "启动程序",
                    "ok": False,
                    "level": "error",
                    "message": f"找不到执行程序: {p['command'][0]}",
                    "suggestion": "请检查该项目的 Python/虚拟环境是否配置正确",
                })
                project_ok = False
            else:
                checks.append({"item": "启动程序", "ok": True, "level": "info", "message": "启动程序有效"})

        drift_ports = discover_project_drift_ports(p, tcp_items, projects, proc_cache)
        expected_ports = p.get("expected_ports", [])
        if drift_ports:
            checks.append({
                "item": "端口状态",
                "ok": True,
                "level": "warn",
                "message": f"实际监听端口 [{', '.join(map(str, drift_ports))}] 已动态生效 (配置: {expected_ports})",
                "suggestion": "运行正常；可按需保存为默认端口",
            })
            drift_count += 1
        elif expected_ports:
            st = project_state(p, active_ports, tcp_items, projects, proc_cache)
            if st["state"] == "stopped":
                for ep in expected_ports:
                    if ep in active_ports:
                        checks.append({
                            "item": "端口占用",
                            "ok": False,
                            "level": "warn",
                            "message": f"端口 {ep} 疑似被外部未关联程序占用",
                            "suggestion": "启动前请确认是否有其它工具使用了该端口",
                        })
                        conflict_count += 1
                        project_ok = False
                        break

        crash = PROJECT_CRASH_INFO.get(pid)
        if crash:
            checks.append({
                "item": "运行自检",
                "ok": False,
                "level": "error",
                "message": crash.get("summary", "最近一次启动异常退出"),
                "suggestion": crash.get("suggestion", "请检查控制台日志"),
                "can_repair": crash.get("can_auto_repair", False),
                "package": crash.get("package"),
            })
            project_ok = False

        if project_ok and enabled:
            healthy_count += 1

        items_report.append({
            "id": pid,
            "name": name,
            "enabled": enabled,
            "healthy": project_ok,
            "checks": checks,
        })

    return {
        "summary": {
            "total": len(projects),
            "healthy": healthy_count,
            "missing_paths": missing_count,
            "drift_ports": drift_count,
            "port_conflicts": conflict_count,
        },
        "projects": items_report,
    }


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
    MANAGED_PROCESSES.pop(project_id, None)
    MANAGED_START_TIMES.pop(project_id, None)
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
    expanded_args = [os.path.expandvars(os.path.expanduser(arg)) for arg in command[1:]]
    return [resolved, *expanded_args]


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
        MANAGED_START_TIMES[project["id"]] = time.monotonic()
        response = {"ok": True, "pid": process.pid, "log": str(log_path)}
    PORT_CACHE["time"] = 0.0
    deadline = time.monotonic() + 8.0
    observed = False
    while project["expected_ports"] and time.monotonic() < deadline:
        if project_type == "command" and process.poll() is not None:
            # 进程意外提前退出，提取日志末尾错误并分析
            MANAGED_PROCESSES.pop(project["id"], None)
            MANAGED_START_TIMES.pop(project["id"], None)
            err_msg = ""
            if log_path.exists():
                try:
                    err_msg = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-15:])
                except Exception:
                    pass
            crash = analyze_crash_log(err_msg)
            PROJECT_CRASH_INFO[project["id"]] = crash
            diag = crash.get("summary", "")
            sugg = crash.get("suggestion", "")
            raise RuntimeError(f"进程启动后立即退出 (ExitCode: {process.returncode}):\n【诊断】{diag}\n【建议】{sugg}\n{err_msg or '请查看控制台日志'}")
        time.sleep(0.3)
        PORT_CACHE["time"] = 0.0
        active = listening_ports()
        if any(port in active for port in project["expected_ports"]):
            observed = True
            MANAGED_START_TIMES.pop(project["id"], None)
            PROJECT_CRASH_INFO.pop(project["id"], None)
            break
        if project_type == "command":
            ports_data = collect_ports()
            tcp_items = [row for row in ports_data.get("items", []) if row.get("protocol") == "TCP"]
            drift = discover_project_drift_ports(project, tcp_items)
            if drift:
                observed = True
                MANAGED_START_TIMES.pop(project["id"], None)
                PROJECT_CRASH_INFO.pop(project["id"], None)
                break
    if project["expected_ports"] and not observed:
        if project_type == "command" and process.poll() is not None:
            MANAGED_PROCESSES.pop(project["id"], None)
            MANAGED_START_TIMES.pop(project["id"], None)
            err_msg = ""
            if log_path.exists():
                try:
                    err_msg = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-15:])
                except Exception:
                    pass
            crash = analyze_crash_log(err_msg)
            PROJECT_CRASH_INFO[project["id"]] = crash
            diag = crash.get("summary", "")
            sugg = crash.get("suggestion", "")
            raise RuntimeError(f"进程启动后退出 (ExitCode: {process.returncode}):\n【诊断】{diag}\n【建议】{sugg}\n{err_msg or '请查看控制台日志'}")
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
    MANAGED_START_TIMES.pop(project["id"], None)
    append_action(f"STOP completed project={project['id']} ok=true")
    return response


def read_project_logs(project_id: str, max_lines: int = 120) -> dict[str, Any]:
    """读取受管项目的控制台日志文件末尾内容，辅助排查启动异常。"""
    project = find_project(project_id)
    log_path = LOG_DIR / f"project-{project['id']}.log"
    if not log_path.exists():
        return {
            "ok": True,
            "project_id": project["id"],
            "name": project["name"],
            "log_path": str(log_path),
            "exists": False,
            "lines": [],
        }
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:]
    return {
        "ok": True,
        "project_id": project["id"],
        "name": project["name"],
        "log_path": str(log_path),
        "exists": True,
        "lines": lines,
    }


def release_port_conflict(project_id: str, target_port: int, target_pid: int) -> dict[str, Any]:
    """安全释放占用已登记项目预期端口的外部普通进程（排除系统服务、IDE 宿主与工作台自身）。"""
    project = find_project(project_id)
    if target_port not in project.get("expected_ports", []):
        raise ValueError(f"端口 {target_port} 不在项目“{project['name']}”的配置端口清单中")

    ports_data = collect_ports(force=True)
    matching = [
        row for row in ports_data.get("items", [])
        if row.get("protocol") == "TCP" and int(row.get("port") or 0) == target_port and int(row.get("pid") or 0) == target_pid
    ]
    if not matching:
        raise RuntimeError(f"未发现 PID {target_pid} 正在监听端口 {target_port}，请刷新后确认")

    protected = {os.getpid(), 0, 4, *(p.pid for p in psutil.Process().parents())}
    if target_pid in protected or any(row.get("services") for row in matching):
        raise RuntimeError("占用该端口的是系统服务、当前宿主环境或工作台自身，为保障系统稳定已拒绝强制结束")

    proc = psutil.Process(target_pid)
    pname = (proc.name() or "").lower()
    if pname in {"antigravity.exe", "code.exe", "explorer.exe", "svchost.exe", "lsass.exe", "services.exe"}:
        raise RuntimeError(f"占用进程 {pname} 属于关键桌面或开发环境进程，请手动确认处理")

    kill_process_targets([proc])
    PORT_CACHE["time"] = 0.0
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if target_port not in listening_ports():
            break
        time.sleep(0.25)
        PORT_CACHE["time"] = 0.0
    if target_port in listening_ports():
        raise RuntimeError(f"已发送结束信号，但端口 {target_port} 仍被占用（可能存在守护自启机制）")

    append_action(f"CONFLICT released project={project_id} port={target_port} pid={target_pid} process={pname}")
    return {"ok": True, "project_id": project_id, "port": target_port, "pid": target_pid}


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
        # 过滤常规只读轮询与静态资源访问噪音，仅记录写操作与异常请求
        rendered = fmt % args
        if '"GET ' in rendered and ('" 200 ' in rendered or '" 304 ' in rendered or '" 204 ' in rendered):
            return
        append_action(f"HTTP client={self.client_address[0]} {rendered}")

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
                lines: list[str] = []
                if ACTION_LOG.exists():
                    raw_lines = ACTION_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
                    # 按 ISO 时间戳聚合多行日志，并过滤常规只读轮询与损坏碎片行
                    iso_re = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
                    merged: list[str] = []
                    for ln in raw_lines:
                        stripped = ln.strip()
                        if not stripped:
                            continue
                        if iso_re.match(stripped):
                            if 'HTTP client=' in stripped and ('" 200 ' in stripped or '" 304 ' in stripped or '" 204 ' in stripped):
                                continue
                            merged.append(stripped)
                        elif merged and not stripped.startswith("HTTP/") and '" 200 ' not in stripped:
                            merged[-1] = f"{merged[-1]} | {stripped}"
                    lines = merged[-100:]
                self.send_json({"ok": True, "items": lines})
                return
            if path == "/api/doctor":
                self.send_json({"ok": True, "report": run_system_doctor()})
                return
            match_logs = re.fullmatch(r"/api/projects/([a-zA-Z0-9_.-]+)/logs", path)
            if match_logs:
                proj_id = match_logs.group(1)
                try:
                    self.send_json(read_project_logs(proj_id))
                except KeyError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
                return
            match_diag = re.fullmatch(r"/api/projects/([a-zA-Z0-9_.-]+)/diagnose", path)
            if match_diag:
                proj_id = match_diag.group(1)
                report = run_system_doctor()
                item = next((it for it in report["projects"] if it["id"] == proj_id), None)
                if not item:
                    self.send_json({"ok": False, "error": "项目不存在"}, HTTPStatus.NOT_FOUND)
                else:
                    self.send_json({"ok": True, "project": item})
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
        if parsed.path == "/api/projects/reconcile-stale":
            with ACTION_LOCK:
                result = auto_archive_stale_projects()
            self.send_json({"ok": True, "result": result, "projects": catalog_payload()})
            return
        if parsed.path == "/api/ports/release-conflict":
            try:
                payload = self.read_json()
                proj_id = str(payload.get("project_id") or "")
                target_port = int(payload.get("port") or 0)
                target_pid = int(payload.get("pid") or 0)
                with ACTION_LOCK:
                    result = release_port_conflict(proj_id, target_port, target_pid)
                self.send_json({"ok": True, "result": result, "projects": catalog_payload()})
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except (ValueError, RuntimeError, OSError, psutil.Error) as exc:
                append_action(f"CONFLICT release_failed error={exc}")
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        match = re.fullmatch(r"/api/projects/([a-zA-Z0-9_.-]+)/(start|stop|archive|restore|sync-port|delete|repair)", parsed.path)
        if not match:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        project_id = match.group(1)
        action = match.group(2)
        try:
            payload = self.read_json() if action in ("sync-port", "repair") else {}
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
                elif action == "repair":
                    target_pkg = payload.get("package") if isinstance(payload, dict) else None
                    result = repair_project_dependency(project_id, target_pkg)
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
    # 后台异步预热端口与项目目录缓存，确保首次打开网页毫秒级秒开
    threading.Thread(target=lambda: catalog_payload(), daemon=True, name="warmup-cache").start()
    try:
        print(f"本机端口控制台：http://{HOST}:{PORT}")
    except Exception:
        pass
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
