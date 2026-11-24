"""מנוע Assessment מתזמר — מריץ את כל הבדיקות ומייצר רשימת חולשות.

לכל התקן רשת מנוהל ונגיש:
  - פותח סשן, קורא running-config ו-show interfaces status, סוגר.
  - מריץ ביקורת קונפיגורציה, חוזק סיסמאות, פורטים לא בשימוש.
לכל התקן (כולל קצה):
  - בודק פורטי שירות מסוכנים (מתוצאות nmap).
  - אם ההתחברות הצליחה עם סיסמת ברירת מחדל -> חולשה קריטית (החלטה 22).
"""

from __future__ import annotations

from collections.abc import Callable

from core import netutils
from core.assessment import ports as ports_check
from core.assessment.config_audit import audit_config, build_vulnerabilities
from core.models import (
    Category,
    Credential,
    Protocol,
    ScanResult,
    Severity,
    Vulnerability,
)
from core.pivot import pivot_teardown
from core.topology import read_identity, reach

ProgressFn = Callable[[str, float, str], None]


def _noop(stage: str, fraction: float, log: str) -> None:
    pass


def _cred_for(ip: str, managed_devices) -> Credential | None:
    for d in managed_devices or []:
        if d.ip == ip:
            return Credential(username=d.username, password=d.password,
                              enable_password=d.enable_password,
                              protocol=Protocol(d.protocol))
    return None


def assess(result: ScanResult, managed_devices=None, try_default_creds: bool = False,
           seed_cred: Credential | None = None,
           progress: ProgressFn = _noop) -> ScanResult:
    """מריץ את כל הבדיקות על תוצאות הסריקה ומעדכן את result.vulnerabilities."""
    result.vulnerabilities = []
    devices = list(result.devices.values())
    total = len(devices) or 1

    for idx, dev in enumerate(devices):
        frac = (idx + 1) / total
        progress("Assess", frac, f"בודק {dev.display_name} ({dev.ip})")

        # --- בדיקות פורטים לכל התקן ---
        result.vulnerabilities.extend(ports_check.check_open_ports(dev))

        # --- התקני רשת מנוהלים: קונפיגורציה + סיסמאות + פורטים לא בשימוש ---
        if dev.device_type.is_network_device or dev.managed:
            cred = _cred_for(dev.ip, managed_devices) or seed_cred or Credential()
            # גישה דרך נתיב הגישה השמור מהזחילה (ישיר או pivot), גם להתקנים מרוחקים
            access = (dev.access_base, dev.access_hops) if dev.access_hops else None
            session, _base, pivot_depth, note = reach(dev.ip, access, cred)
            if not session:
                progress("Assess", frac,
                         f"⚠ {dev.display_name}: לא ניתן לקרוא קונפיגורציה ({note})")
                continue

            try:
                # החלטה 22: התחברות שהצליחה עם סיסמת ברירת מחדל = חולשה קריטית
                if getattr(session.credential, "source", "") == "default" and try_default_creds:
                    result.vulnerabilities.append(Vulnerability(
                        device_id=dev.id,
                        title="ההתקן מקבל סיסמת ברירת מחדל",
                        category=Category.PASSWORD, severity=Severity.CRITICAL,
                        details="הצלחנו להתחבר עם פרטי ברירת מחדל מוכרים. יש להחליף מיידית.",
                        evidence=f"התחברות עם {session.credential.username or '(ריק)'}/default"))

                # פרטי ההתקן (MAC/דגם) — גם להתקנים מרוחקים
                ident = read_identity(session)
                if ident.get("model") and not dev.model:
                    dev.model = ident["model"]
                if ident.get("mac") and not dev.mac:
                    dev.mac = netutils.normalize_mac(ident["mac"])
                if ident.get("os") and not dev.os:
                    dev.os = ident["os"]

                config = session.get_running_config()
                if config:
                    dev.running_config = config
                    findings, creds = audit_config(config, dev.display_name)
                    result.vulnerabilities.extend(
                        build_vulnerabilities(dev.id, dev.display_name, findings, creds))

                # פורטים פיזיים לא בשימוש
                status_out = session.run_show("show interfaces status")
                interfaces = ports_check.parse_interface_status(status_out)
                if interfaces:
                    dev.interfaces = interfaces
                    result.vulnerabilities.extend(
                        ports_check.check_unused_switchports(dev, interfaces))
            finally:
                if pivot_depth:
                    pivot_teardown(session.handler, pivot_depth)
                session.close()

    progress("Done", 1.0,
             f"הבדיקה הסתיימה: {len(result.vulnerabilities)} חולשות, ציון רשת {result.risk_score}")
    return result
