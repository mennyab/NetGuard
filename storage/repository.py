"""שמירה וטעינה של תוצאות סריקה ל-SQLite (היסטוריה והשוואה)."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime

from core.models import (
    Device,
    DeviceType,
    Interface,
    Link,
    OpenPort,
    ScanResult,
    Severity,
    Vulnerability,
)
from core.models import Category
from storage.db import connect


def save_scan(result: ScanResult) -> int:
    """שומר סריקה שלמה ומחזיר את מזהה הסריקה."""
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, finished_at, subnets, risk_score) "
            "VALUES (?, ?, ?, ?)",
            (result.started_at.isoformat(),
             result.finished_at.isoformat() if result.finished_at else None,
             json.dumps(result.subnets), result.risk_score))
        scan_id = cur.lastrowid

        for dev in result.devices.values():
            data = {
                "interfaces": [asdict(i) for i in dev.interfaces],
                "open_ports": [asdict(p) for p in dev.open_ports],
                "netmiko_type": dev.netmiko_type,
                "discovered_by": dev.discovered_by,
                "running_config": dev.running_config,
                "alt_ips": dev.alt_ips,
                "access_base": dev.access_base,
                "access_hops": dev.access_hops,
                "uid": dev.uid,
            }
            conn.execute(
                "INSERT INTO devices (scan_id, device_id, ip, mac, hostname, vendor, "
                "model, os, device_type, managed, data_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, dev.id, dev.ip, dev.mac, dev.hostname, dev.vendor,
                 dev.model, dev.os, dev.device_type.value, int(dev.managed),
                 json.dumps(data, ensure_ascii=False)))

        for lk in result.links:
            conn.execute(
                "INSERT INTO links (scan_id, device_a, port_a, device_b, port_b, source) "
                "VALUES (?,?,?,?,?,?)",
                (scan_id, lk.device_a, lk.port_a, lk.device_b, lk.port_b, lk.source))

        for v in result.vulnerabilities:
            conn.execute(
                "INSERT INTO vulnerabilities (scan_id, device_id, title, category, "
                "severity, details, evidence) VALUES (?,?,?,?,?,?,?)",
                (scan_id, v.device_id, v.title, v.category.value, v.severity.value,
                 v.details, v.evidence))
    return scan_id


def list_scans() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, subnets, risk_score, "
            "(SELECT COUNT(*) FROM devices d WHERE d.scan_id = s.id) AS device_count, "
            "(SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id) AS vuln_count "
            "FROM scans s ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def load_scan(scan_id: int) -> ScanResult:
    with connect() as conn:
        srow = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not srow:
            raise ValueError(f"סריקה {scan_id} לא נמצאה.")
        result = ScanResult(
            id=scan_id,
            started_at=datetime.fromisoformat(srow["started_at"]),
            finished_at=datetime.fromisoformat(srow["finished_at"]) if srow["finished_at"] else None,
            subnets=json.loads(srow["subnets"]))

        for d in conn.execute("SELECT * FROM devices WHERE scan_id = ?", (scan_id,)):
            data = json.loads(d["data_json"] or "{}")
            dev = Device(
                ip=d["ip"], mac=d["mac"], hostname=d["hostname"], vendor=d["vendor"],
                model=d["model"], os=d["os"],
                device_type=DeviceType(d["device_type"]), managed=bool(d["managed"]),
                netmiko_type=data.get("netmiko_type", ""),
                discovered_by=data.get("discovered_by", []),
                running_config=data.get("running_config", ""),
                alt_ips=data.get("alt_ips", []),
                access_base=data.get("access_base", ""),
                access_hops=data.get("access_hops", []),
                uid=data.get("uid", d["device_id"]),
                interfaces=[Interface(**i) for i in data.get("interfaces", [])],
                open_ports=[OpenPort(**p) for p in data.get("open_ports", [])])
            result.devices[dev.id] = dev

        for lk in conn.execute("SELECT * FROM links WHERE scan_id = ?", (scan_id,)):
            result.links.append(Link(lk["device_a"], lk["device_b"],
                                     lk["port_a"], lk["port_b"], lk["source"]))

        for v in conn.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)):
            result.vulnerabilities.append(Vulnerability(
                device_id=v["device_id"], title=v["title"],
                category=Category(v["category"]), severity=Severity(v["severity"]),
                details=v["details"], evidence=v["evidence"]))
    return result


def read_audit_log(limit: int = 200) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT ts, actor, action, target, details FROM audit_log "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
