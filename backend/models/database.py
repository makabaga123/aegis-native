from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "security_platform.db"
DB_PATH = Path(os.environ.get("SECURITY_PLATFORM_DB", str(DEFAULT_DB_PATH)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                summary_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER,
                rule_id TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                fix TEXT,
                source TEXT,
                target TEXT,
                category TEXT,
                created_at TEXT,
                extra_json TEXT,
                FOREIGN KEY(task_id) REFERENCES scan_tasks(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS falco_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule TEXT,
                priority TEXT,
                namespace TEXT,
                pod TEXT,
                container TEXT,
                message TEXT,
                raw_event TEXT,
                created_at TEXT
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn():
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def create_task(task_type: str, target: str, status: str = "running") -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scan_tasks(task_type,target,status,created_at) VALUES(?,?,?,?)",
            (task_type, target, status, _now()),
        )
        return int(cur.lastrowid)


def finish_task(task_id: int, status: str, summary: Dict[str, Any] | None = None) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_tasks SET status=?, finished_at=?, summary_json=? WHERE id=?",
            (status, _now(), json.dumps(summary or {}, ensure_ascii=False), task_id),
        )


def save_findings(task_id: int | None, findings: Iterable[Dict[str, Any]]) -> None:
    rows = []
    for item in findings:
        rows.append((
            task_id,
            item.get("rule_id"),
            item.get("severity"),
            item.get("title"),
            item.get("description"),
            item.get("evidence"),
            item.get("fix"),
            item.get("source"),
            item.get("target"),
            item.get("category"),
            item.get("created_at") or _now(),
            json.dumps(item.get("extra", {}), ensure_ascii=False),
        ))
    if not rows:
        return
    with get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO findings(
                task_id, rule_id, severity, title, description, evidence, fix,
                source, target, category, created_at, extra_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )


def list_findings(limit: int = 500) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["extra"] = json.loads(item.pop("extra_json") or "{}")
        except json.JSONDecodeError:
            item["extra"] = {}
        return_item = {k: v for k, v in item.items() if k != "extra_json"}
        result.append(return_item)
    return result


def list_tasks(limit: int = 100) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_tasks ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    tasks = []
    for row in rows:
        item = dict(row)
        try:
            item["summary"] = json.loads(item.pop("summary_json") or "{}")
        except json.JSONDecodeError:
            item["summary"] = {}
        tasks.append(item)
    return tasks


def save_falco_event(event: Dict[str, Any], finding: Dict[str, Any]) -> None:
    fields = event.get("output_fields") or {}
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO falco_events(rule, priority, namespace, pod, container, message, raw_event, created_at)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                event.get("rule") or event.get("rule_name"),
                event.get("priority") or event.get("level"),
                fields.get("k8s.ns.name") or event.get("namespace"),
                fields.get("k8s.pod.name") or event.get("pod"),
                fields.get("container.name") or event.get("container_name"),
                event.get("output") or event.get("message"),
                json.dumps(event, ensure_ascii=False),
                _now(),
            ),
        )
    save_findings(None, [finding])


def save_runtime_event(event: Dict[str, Any], findings: Iterable[Dict[str, Any]]) -> None:
    """Store normalized runtime/EDR events and related findings."""
    init_db()
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                namespace TEXT,
                pod TEXT,
                container TEXT,
                process TEXT,
                path TEXT,
                dst TEXT,
                raw_event TEXT,
                created_at TEXT
            )
            """
        )
        fields = event.get("output_fields") or {}
        conn.execute(
            """
            INSERT INTO runtime_events(event_type, namespace, pod, container, process, path, dst, raw_event, created_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                event.get("event_type") or event.get("type") or fields.get("evt.type"),
                event.get("namespace") or fields.get("k8s.ns.name"),
                event.get("pod") or fields.get("k8s.pod.name"),
                event.get("container") or fields.get("container.name"),
                event.get("process_name") or fields.get("proc.name"),
                event.get("path") or fields.get("fd.name"),
                event.get("dst") or event.get("dst_ip") or fields.get("fd.sip"),
                json.dumps(event, ensure_ascii=False),
                _now(),
            ),
        )
    save_findings(None, findings)


def list_runtime_events(limit: int = 200) -> List[Dict[str, Any]]:
    init_db()
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                namespace TEXT,
                pod TEXT,
                container TEXT,
                process TEXT,
                path TEXT,
                dst TEXT,
                raw_event TEXT,
                created_at TEXT
            )
            """
        )
        rows = conn.execute("SELECT * FROM runtime_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["raw_event"] = json.loads(item.get("raw_event") or "{}")
        except json.JSONDecodeError:
            pass
        result.append(item)
    return result
