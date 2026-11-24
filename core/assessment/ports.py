"""בדיקות מבוססות פורטים: שירותים מסוכנים + פורטים פיזיים לא בשימוש."""

from __future__ import annotations

import re

from core.models import Category, Device, Interface, Severity, Vulnerability

# פורטי שירות מסוכנים -> (תיאור, חומרה)
DANGEROUS_PORTS = {
    23:   ("Telnet — ניהול לא מוצפן", Severity.HIGH),
    21:   ("FTP — העברת קבצים לא מוצפנת", Severity.MEDIUM),
    69:   ("TFTP — ללא אימות", Severity.MEDIUM),
    80:   ("HTTP — ניהול לא מוצפן", Severity.LOW),
    512:  ("rexec", Severity.HIGH),
    513:  ("rlogin", Severity.HIGH),
    514:  ("rsh", Severity.HIGH),
    445:  ("SMB חשוף", Severity.MEDIUM),
    3389: ("RDP חשוף", Severity.MEDIUM),
    5900: ("VNC חשוף", Severity.MEDIUM),
    1900: ("UPnP", Severity.LOW),
}


def check_open_ports(device: Device) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    for port in device.open_ports:
        if port.port in DANGEROUS_PORTS:
            desc, sev = DANGEROUS_PORTS[port.port]
            svc = f" ({port.service} {port.product})".rstrip()
            vulns.append(Vulnerability(
                device_id=device.id,
                title=f"פורט פתוח {port.port}/{port.protocol} — {desc}",
                category=Category.PORTS, severity=sev,
                details="שירות זה חשוף לתקיפה. מומלץ לסגור אם אינו נדרש.",
                evidence=f"{port.port}/{port.protocol}{svc}"))
    return vulns


def check_unused_switchports(device: Device, interfaces: list[Interface]) -> list[Vulnerability]:
    """פורט פיזי במתג שאינו מחובר ואינו כבוי = חולשה (החלטת הפרויקט)."""
    unused: list[str] = []
    for intf in interfaces:
        status = intf.status.lower()
        if "notconnect" in status and "disabled" not in status and "shutdown" not in status:
            unused.append(intf.name)
    vulns: list[Vulnerability] = []
    if unused:
        sev = Severity.MEDIUM if len(unused) >= 3 else Severity.LOW
        vulns.append(Vulnerability(
            device_id=device.id,
            title=f"{len(unused)} פורטים פיזיים לא בשימוש ואינם כבויים",
            category=Category.PORTS, severity=sev,
            details="פורט פתוח שאינו בשימוש מאפשר חיבור לא מורשה. מומלץ shutdown.",
            evidence=", ".join(unused)))   # הרשימה המלאה — ה-Mitigation מסתמך עליה
    return vulns


def parse_interface_status(output: str) -> list[Interface]:
    """מנתח פלט של 'show interfaces status' (טקסט) לרשימת ממשקים."""
    interfaces: list[Interface] = []
    for line in output.splitlines():
        # Fa0/1   desc   notconnect   1   auto   auto  ...
        m = re.match(r"^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|monitoring)\s+(\S+)", line)
        if m:
            interfaces.append(Interface(
                name=m.group(1), description=m.group(2).strip(),
                status=m.group(3), vlan=m.group(4)))
    return interfaces
