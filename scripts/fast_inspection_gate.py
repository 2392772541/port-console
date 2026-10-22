# -*- coding: utf-8 -*-
"""Fast local inspection gate for port console and AI skills."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

PORT_CONSOLE_ROOT = Path(r"E:\工程项目\codex项目合集\个人用\port-console")
PROJECTS_JSON = PORT_CONSOLE_ROOT / "config" / "projects.json"
LEDGER_JSON = PORT_CONSOLE_ROOT / ".runtime" / "discovery-ledger.json"
RUNTIME_DIR = PORT_CONSOLE_ROOT / ".runtime"

AI_SKILLS_ROOT = Path(r"D:\AI-Skills")
AI_SKILLS_WEB = AI_SKILLS_ROOT / "web"
GUIDE_REVISIONS_JSON = AI_SKILLS_WEB / "guide-revisions.json"
LABELS_JSON = AI_SKILLS_ROOT / "registry" / "personal-console" / "labels.json"


def get_current_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="microseconds")


def read_json_safe(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return default


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def check_tcp_listeners(known_ports: dict[int, dict[str, Any]]) -> tuple[list[dict[str, Any]], set[int]]:
    current_ports: set[int] = set()
    new_candidates: list[dict[str, Any]] = []

    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr:
            port = conn.laddr.port
            current_ports.add(port)
            if port not in known_ports:
                proc_name = "unknown"
                cmdline = ""
                cwd = ""
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                        cmdline = " ".join(p.cmdline()[:5])
                        cwd = p.cwd()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                new_candidates.append({
                    "port": port,
                    "pid": conn.pid,
                    "process": proc_name,
                    "cmdline": cmdline,
                    "cwd": cwd,
                })

    return new_candidates, current_ports


def check_skills() -> tuple[list[dict[str, Any]], int]:
    sys.path.insert(0, str(AI_SKILLS_WEB))
    try:
        from personal import Catalog
        catalog = Catalog()
        found, _ = catalog.discover()
    except Exception as e:
        return [{"error": f"Failed to run Catalog.discover: {e}"}], 0

    revisions = read_json_safe(GUIDE_REVISIONS_JSON, {})
    unreviewed = []
    for sid, row in found.items():
        name = row["name"]
        md_hash = row["md_hash"]
        revs = revisions.get(name, [])
        if isinstance(revs, str):
            revs = [revs]
        if md_hash not in revs:
            unreviewed.append({
                "name": name,
                "path": row["path"],
                "md_hash": md_hash,
            })

    return unreviewed, len(found)


def check_services() -> list[str]:
    issues = []
    for port, label in [(8787, "Port Console (8787)"), (8765, "Personal Console (8765)")]:
        try:
            req = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.5)
            if req.status != 200:
                issues.append(f"{label} HTTP status: {req.status}")
        except Exception as e:
            issues.append(f"{label} connection failed: {e}")
    return issues


def update_ledger(current_ports: set[int], known_classifications: list[dict[str, Any]]) -> None:
    ledger_data = read_json_safe(LEDGER_JSON, {})
    if not ledger_data:
        return

    ts_compact = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = RUNTIME_DIR / f"discovery-ledger.json.bak-{ts_compact}"
    try:
        shutil.copy2(LEDGER_JSON, backup_path)
    except Exception:
        pass

    stamp = get_current_timestamp()
    ledger_data["last_run"] = stamp

    active_classifications = []
    reg_count = 0
    internal_count = 0
    candidate_count = 0

    for item in known_classifications:
        port = item["port"]
        if port in current_ports:
            item["status"] = "active"
            item["last_seen"] = stamp
            active_classifications.append(item)
            if item.get("category_key") == "registered_main":
                reg_count += 1
            elif item.get("category_key") == "confirmed_internal":
                internal_count += 1
            elif item.get("category_key") == "candidate":
                candidate_count += 1

    counts = {
        "registered_main": reg_count,
        "confirmed_internal": internal_count,
        "candidate": candidate_count
    }

    # A fast gate only compares the live listeners with the last reviewed
    # snapshot. It cannot upgrade an incomplete full-disk discovery run.
    current_complete = bool(ledger_data.get("current_complete", False))
    scan_coverage = ledger_data.get("current_scan_coverage", ["system_listen_tcp_fast_gate"])
    scan_failures = ledger_data.get("current_scan_failures", [])
    skill_maintenance = ledger_data.get("current_skill_maintenance", {
        "changed_skills": [],
        "active_pending_after": [],
        "backend_status": "ok",
    })

    ledger_data["current_complete"] = current_complete
    ledger_data["current_classification_counts"] = counts
    ledger_data["current_port_classifications"] = active_classifications

    runs = ledger_data.get("runs", [])
    new_run = {
        "scan_time": stamp,
        "complete": current_complete,
        "listener_records": len(current_ports),
        "unique_tcp_ports": len(current_ports),
        "classification_counts": counts,
        "classifications": active_classifications,
        "scan_coverage": scan_coverage,
        "scan_failures": scan_failures,
        "entry_files": [],
        "changed_entry_files": [],
        "project_changes": [],
        "skill_maintenance": skill_maintenance,
        "validation": {
            "gate": "fast_inspection_gate passed; 0 candidates; 0 unreviewed skills; services healthy"
        }
    }
    runs.append(new_run)
    if len(runs) > 30:
        runs = runs[-30:]
    ledger_data["runs"] = runs

    write_json_atomic(LEDGER_JSON, ledger_data)


def main():
    parser = argparse.ArgumentParser(description="Fast local inspection gate")
    parser.add_argument("--check-only", action="store_true", help="Only inspect, do not update ledger")
    args = parser.parse_args()

    ledger_data = read_json_safe(LEDGER_JSON, {})
    latest_run = (ledger_data.get("runs") or [{}])[-1]
    known_classifications = latest_run.get("classifications", [])
    known_ports = {item["port"]: item for item in known_classifications}

    new_port_candidates, current_ports = check_tcp_listeners(known_ports)
    unreviewed_skills, active_skill_count = check_skills()
    service_issues = check_services()

    has_changes = bool(new_port_candidates or unreviewed_skills or service_issues)

    if has_changes:
        print("[FAST-GATE: CHANGES_DETECTED]")
        if new_port_candidates:
            print(f"  [新端口候选] 发现 {len(new_port_candidates)} 个新监听端口:")
            for c in new_port_candidates:
                print(f"    - 端口 {c['port']} (PID: {c['pid']}, 进程: {c['process']}, 路径: {c['cwd']})")
        if unreviewed_skills:
            print(f"  [新技能/变更] 发现 {len(unreviewed_skills)} 个待核对技能:")
            for s in unreviewed_skills:
                print(f"    - {s.get('name')}: {s.get('path')}")
        if service_issues:
            print(f"  [服务异常] 检测到服务问题:")
            for issue in service_issues:
                print(f"    - {issue}")
        sys.exit(1)
    else:
        if not args.check_only:
            update_ledger(current_ports, known_classifications)

        print("[FAST-GATE: NO_CHANGES]")
        print(f"  [OK] 全机 TCP 监听端口 {len(current_ports)} 个已全部归类 (无新候选)")
        print(f"  [OK] 活跃 Skill {active_skill_count} 个均已核对记录 (无待办)")
        print("  [OK] Port Console (8787) 与 Personal Console (8765) 运行正常")
        sys.exit(0)


if __name__ == "__main__":
    main()
