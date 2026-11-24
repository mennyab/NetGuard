"""Session Manager — ניהול חיבורים למתגים ולנתבים.

עקרונות הבטיחות (לפי דרישות הפרויקט):
  1. לעולם לא מנתקים חיבורים קיימים שלא אנחנו פתחנו.
     אין הרצה של clear line / reload / no ip ssh וכו' (נאכף מול forbidden_commands).
  2. לפני חיבור חדש בודקים כמה קווי VTY פנויים (show users). אם נשארים
     פחות מ-vty_reserve_lines פנויים — לא מתחברים, כדי לא לחסום את המשתמש.
     בהתקן שהיצרן שלו לא מוכר (אין איך לספור סשנים) — מתחברים עם אזהרה.
  3. SSH מועדף. Telnet רק אם SSH לא זמין (ומסומן כחולשה בהמשך).
     חיבור SSH חדש נפתח *לצד* חיבור Telnet קיים, בלי לסגור אותו.
  4. בשלב ה-discovery רצות רק פקודות קריאה (show / display). אין כניסה ל-config.
  5. סדר ניסיונות הסיסמה: פרטי המשתמש -> 'cisco' -> ברירות מחדל לפי יצרן.
     עד max_per_device ניסיונות, עם השהיה וזיהוי נעילה. אם הכול נכשל — נשאל המשתמש.
  6. בסוף סוגרים רק את הסשנים שאנחנו פתחנו.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

from core.config_loader import default_credentials, settings
from core.models import Credential, Protocol

# ---------------------------------------------------------------------------
# זיהוי שירותים וסשנים פעילים
# ---------------------------------------------------------------------------

# פקודה לספירת סשנים פעילים + כמה קווי VTY יש בסך הכול, לפי יצרן.
# total=None פירושו "לא ידוע", ואז לא חוסמים לפי מכסה.
VTY_PROBE = {
    "cisco_ios":   {"cmd": "show users",           "total": 5},
    "cisco_xe":    {"cmd": "show users",           "total": 5},
    "cisco_nxos":  {"cmd": "show users",           "total": None},
    "hp_procurve": {"cmd": "show telnet",          "total": None},
    "hp_comware":  {"cmd": "display users",        "total": None},
    "aruba_os":    {"cmd": "show user-table",      "total": None},
    "juniper_junos": {"cmd": "show system users",  "total": None},
    "mikrotik_routeros": {"cmd": "/user active print", "total": None},
}

LOCKOUT_SIGNS = (
    "temporarily locked",
    "account locked",
    "maximum number of",
    "login blocked",
    "please try again later",
    "access denied",
)


@dataclass
class ConnectionAttempt:
    credential: Credential
    success: bool
    error: str = ""
    lockout_detected: bool = False
    connection_level: bool = False   # כשל ברמת החיבור (banner/kex/timeout), לא אימות

# סימנים לכשל חיבור ברמת הפרוטוקול (לא קשור לסיסמה) -> אין טעם לנסות סיסמאות נוספות
CONN_FAIL_SIGNS = ("banner", "kex", "key exchange", "eof", "connection closed",
                   "no matching", "incompatible", "protocol")


@dataclass
class DeviceSession:
    """סשן פתוח אחד להתקן. נשמר ב-pool ומשמש את כל הפקודות."""
    ip: str
    protocol: Protocol
    netmiko_type: str
    credential: Credential
    handler: object = None               # חיבור Netmiko הפעיל
    active_sessions_before: int = -1     # כמה סשנים היו פעילים לפני שהתחברנו
    opened_by_us: bool = True
    warnings: list[str] = field(default_factory=list)

    def run_show(self, command: str) -> str:
        """הרצת פקודת קריאה בלבד. פקודה אסורה -> חריגה."""
        _assert_not_forbidden(command)
        if not _is_read_command(command):
            raise ValueError(f"run_show מיועד לפקודות קריאה בלבד, לא ל: {command!r}")
        return self.handler.send_command(command, read_timeout=45)

    def run_show_structured(self, command: str) -> list[dict]:
        """פקודת קריאה עם ניתוח TextFSM (ntc-templates). מחזיר רשימת שורות כ-dict.
        אם אין תבנית מתאימה, Netmiko מחזיר טקסט גולמי ואנחנו מחזירים []."""
        _assert_not_forbidden(command)
        if not _is_read_command(command):
            raise ValueError(f"run_show_structured מיועד לפקודות קריאה בלבד: {command!r}")
        try:
            out = self.handler.send_command(command, use_textfsm=True, read_timeout=45)
            return out if isinstance(out, list) else []
        except Exception:
            return []

    def apply_config(self, commands: list[str]) -> str:
        """מריץ פקודות config (שינוי בפועל). משמש רק אחרי אישור המשתמש ב-Mitigation.
        כל פקודה נבדקת מול רשימת הפקודות האסורות."""
        for cmd in commands:
            _assert_not_forbidden(cmd)
        self.ensure_enable()
        return self.handler.send_config_set(commands, read_timeout=60)

    def save_running_backup(self, path: str) -> str:
        """שומר את ה-running-config לקובץ גיבוי לפני שינוי."""
        config = self.get_running_config()
        with open(path, "w", encoding="utf-8") as f:
            f.write(config)
        return path

    def ensure_enable(self) -> bool:
        """נכנס למצב enable אם צריך (לצורך קריאת running-config). לא משנה קונפיגורציה."""
        try:
            if not self.handler.check_enable_mode():
                self.handler.enable()
            return self.handler.check_enable_mode()
        except Exception:
            return False

    def get_running_config(self) -> str:
        """קריאת running-config (show בלבד). נכנס ל-enable במידת הצורך."""
        self.ensure_enable()
        try:
            return self.handler.send_command("show running-config", read_timeout=60)
        except Exception:
            return ""

    def close(self) -> None:
        """סוגר רק את הסשן שאנחנו פתחנו. לא נוגע בחיבורים אחרים."""
        if self.handler and self.opened_by_us:
            try:
                self.handler.disconnect()
            except Exception:
                pass
            self.handler = None


# ---------------------------------------------------------------------------
# אכיפת פקודות אסורות
# ---------------------------------------------------------------------------

def _assert_not_forbidden(command: str) -> None:
    low = command.lower().strip()
    for bad in settings()["connection"]["forbidden_commands"]:
        if low.startswith(bad):
            raise PermissionError(
                f"הפקודה {command!r} חסומה: היא עלולה לנתק חיבורים קיימים או לסכן את ההתקן."
            )


def _is_read_command(command: str) -> bool:
    low = command.lower().strip()
    return low.startswith(("show ", "display ", "/", "get ")) or low in ("show users",)


# ---------------------------------------------------------------------------
# זיהוי יצרן / סוג התקן
# ---------------------------------------------------------------------------

def detect_device_type(ip: str, credential: Credential) -> str | None:
    """זיהוי אוטומטי של סוג ההתקן ב-SSH (SSHDetect). מחזיר netmiko_type או None."""
    guess_params = {
        "device_type": "autodetect",
        "host": ip,
        "username": credential.username,
        "password": credential.password,
        "timeout": settings()["connection"]["timeout_seconds"],
    }
    try:
        detector = SSHDetect(**guess_params)
        best = detector.autodetect()
        return best            # למשל "cisco_ios"; None אם לא זוהה
    except Exception:
        return None


def _vendor_defaults(netmiko_type: str | None) -> list[Credential]:
    """בונה את רשימת ניסיונות ברירת המחדל: 'cisco' תחילה, ואז לפי יצרן."""
    creds_cfg = default_credentials()
    attempts: list[Credential] = []
    seen: set[tuple] = set()

    def add(username: str, password: str):
        key = (username, password)
        if key not in seen:
            seen.add(key)
            attempts.append(Credential(username=username, password=password, source="default"))

    # 1) תמיד מנסים את 'cisco' קודם (בקשת המשתמש)
    add("cisco", "cisco")
    add("", "cisco")

    # 2) ברירות מחדל לפי היצרן שזוהה
    vendor_key = _vendor_key_from_netmiko(netmiko_type)
    for entry in creds_cfg.get("vendors", {}).get(vendor_key, []):
        add(entry.get("username", ""), entry.get("password", ""))

    # 3) ברירות מחדל כלליות
    for entry in creds_cfg.get("generic", []):
        add(entry.get("username", ""), entry.get("password", ""))

    return attempts


def _vendor_key_from_netmiko(netmiko_type: str | None) -> str:
    if not netmiko_type:
        return ""
    if netmiko_type.startswith("cisco"):
        return "cisco"
    if netmiko_type.startswith(("hp", "aruba")):
        return "hp_aruba"
    if netmiko_type.startswith("juniper"):
        return "juniper"
    if netmiko_type.startswith("mikrotik"):
        return "mikrotik"
    return ""


# ---------------------------------------------------------------------------
# בדיקת סשנים פעילים (לא חוסם חיבורים קיימים)
# ---------------------------------------------------------------------------

def count_active_sessions(handler, netmiko_type: str) -> tuple[int, int | None]:
    """מחזיר (סשנים_פעילים, סך_הקווים). (-1, None) אם לא ניתן לדעת."""
    probe = VTY_PROBE.get(netmiko_type)
    if not probe:
        return -1, None
    try:
        output = handler.send_command(probe["cmd"], read_timeout=20)
    except Exception:
        return -1, None
    # ספירת שורות עם סשן פעיל. ב-Cisco כל שורה עם '*' או 'vty' היא קו בשימוש.
    active = 0
    for line in output.splitlines():
        low = line.lower()
        if "vty" in low or line.strip().startswith("*"):
            active += 1
    return active, probe["total"]


# ---------------------------------------------------------------------------
# פתיחת חיבור
# ---------------------------------------------------------------------------

def _port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _available_protocols(ip: str) -> list[Protocol]:
    """SSH מועדף. Telnet רק אם SSH לא פתוח."""
    conn = settings()["connection"]
    protocols = []
    if _port_open(ip, conn["ssh_port"]):
        protocols.append(Protocol.SSH)
    if _port_open(ip, conn["telnet_port"]):
        protocols.append(Protocol.TELNET)
    if conn["prefer_protocol"] == "ssh":
        protocols.sort(key=lambda p: 0 if p == Protocol.SSH else 1)
    return protocols


def _netmiko_device_type(base_type: str | None, protocol: Protocol) -> str:
    """מתאים את סוג ההתקן לפרוטוקול (ל-Telnet מוסיפים סיומת _telnet)."""
    base = base_type or "cisco_ios"
    if protocol == Protocol.TELNET and not base.endswith("_telnet"):
        if base.startswith("cisco"):
            return f"{base}_telnet"
        return "cisco_ios_telnet"
    return base


def _try_connect(ip: str, protocol: Protocol, netmiko_type: str,
                 cred: Credential) -> tuple[object | None, ConnectionAttempt]:
    """ניסיון חיבור יחיד. מחזיר (handler, תוצאת הניסיון)."""
    params = {
        "device_type": _netmiko_device_type(netmiko_type, protocol),
        "host": ip,
        "username": cred.username,
        "password": cred.password,
        "secret": cred.enable_password or cred.password,
        "timeout": settings()["connection"]["timeout_seconds"],
        "fast_cli": False,
    }
    try:
        handler = ConnectHandler(**params)
        return handler, ConnectionAttempt(cred, success=True)
    except NetmikoAuthenticationException as e:
        lock = any(sign in str(e).lower() for sign in LOCKOUT_SIGNS)
        return None, ConnectionAttempt(cred, success=False, error="אימות נכשל",
                                       lockout_detected=lock)
    except NetmikoTimeoutException:
        return None, ConnectionAttempt(cred, success=False, error="timeout",
                                       connection_level=True)
    except Exception as e:
        low = str(e).lower()
        lock = any(sign in low for sign in LOCKOUT_SIGNS)
        conn_fail = any(sign in low for sign in CONN_FAIL_SIGNS)
        return None, ConnectionAttempt(cred, success=False, error=str(e)[:200],
                                       lockout_detected=lock, connection_level=conn_fail)


# ---------------------------------------------------------------------------
# ה-API הראשי
# ---------------------------------------------------------------------------

@dataclass
class ConnectOutcome:
    session: DeviceSession | None = None
    attempts: list[ConnectionAttempt] = field(default_factory=list)
    needs_user_credentials: bool = False   # כל הניסיונות נכשלו -> לשאול את המשתמש
    skipped_reason: str = ""               # לא התחברנו (אין מכסה פנויה וכו')


def open_session(ip: str, user_cred: Credential | None = None,
                 netmiko_type: str | None = None) -> ConnectOutcome:
    """פותח סשן אחד להתקן, לפי כל עקרונות הבטיחות.

    user_cred   — פרטי הגישה שהמשתמש הזין (מנוסים ראשונים).
    netmiko_type — אם ידוע מראש. אחרת ננסה זיהוי אוטומטי ב-SSH.
    """
    cfg = settings()
    limits = cfg["login_attempts"]
    outcome = ConnectOutcome()

    protocols = _available_protocols(ip)
    if not protocols:
        outcome.skipped_reason = "אין פורט SSH או Telnet פתוח בהתקן."
        return outcome

    # זיהוי אוטומטי של סוג ההתקן ב-SSH, אם לא נמסר
    if netmiko_type is None and Protocol.SSH in protocols and user_cred:
        netmiko_type = detect_device_type(ip, user_cred)

    # בניית רשימת הניסיונות: קודם המשתמש, ואז ברירות מחדל
    attempts: list[Credential] = []
    if user_cred and (user_cred.username or user_cred.password):
        attempts.append(user_cred)
    attempts.extend(_vendor_defaults(netmiko_type))
    attempts = attempts[: limits["max_per_device"]]   # עד 5 ניסיונות

    for protocol in protocols:
        for cred in attempts:
            handler, result = _try_connect(ip, protocol, netmiko_type, cred)
            outcome.attempts.append(result)

            if result.lockout_detected and limits["stop_on_lockout_signs"]:
                outcome.skipped_reason = "זוהו סימני נעילת חשבון. הסריקה על ההתקן נעצרה."
                return outcome

            if handler is None:
                # כשל ברמת החיבור (למשל SSH עם אלגוריתמים ישנים) -> אין טעם לנסות
                # סיסמאות נוספות על הפרוטוקול הזה; עוברים ישר לפרוטוקול הבא (Telnet).
                if result.connection_level:
                    break
                time.sleep(limits["delay_seconds"])
                continue

            # --- התחברנו. עכשיו בודקים כמה סשנים כבר היו פעילים ---
            active, total = count_active_sessions(handler, netmiko_type or "")
            session = DeviceSession(
                ip=ip, protocol=protocol, netmiko_type=netmiko_type or "unknown",
                credential=cred, handler=handler, active_sessions_before=active,
            )
            if total is not None and active >= 0:
                free = total - active
                if free <= cfg["connection"]["vty_reserve_lines"]:
                    # כמעט לא נשארו קווים. לא רוצים לחסום את המשתמש -> מתנתקים.
                    handler.disconnect()
                    outcome.skipped_reason = (
                        f"נותרו {free} קווי VTY פנויים בלבד מתוך {total}. "
                        "המערכת לא מתחברת כדי לא לחסום אותך."
                    )
                    return outcome
            elif active == -1:
                session.warnings.append(
                    "לא ניתן לספור סשנים פעילים בהתקן זה (יצרן לא מוכר). "
                    "החיבור נפתח לצד החיבורים הקיימים ולא מנתק אותם."
                )

            if protocol == Protocol.TELNET:
                session.warnings.append("החיבור נעשה ב-Telnet (לא מוצפן) — ייבדק כחולשה.")

            outcome.session = session
            return outcome

    # כל הניסיונות נכשלו (בלי נעילה) -> נשאל את המשתמש
    if limits["ask_user_on_failure"]:
        outcome.needs_user_credentials = True
    return outcome
