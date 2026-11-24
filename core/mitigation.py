"""מנוע Mitigation — תכנון, ביצוע (רק באישור) ו-Rollback.

תכנון:  ממפה כל חולשה לפעולת תיקון עם פקודות מדויקות ופקודות ביטול (undo).
ביצוע:  רק פעולות שהמשתמש אישר, אחרי גיבוי, עם אימות ואפשרות שחזור.
        התקני קצה מקבלים המלצה ידנית בלבד (automatic=False).
"""

from __future__ import annotations

import re
import secrets
import string
from collections.abc import Callable
from datetime import datetime

from core.assessment.passwords import evaluate_password
from core.config_loader import project_path, settings
from core.models import (
    Category,
    Credential,
    MitigationAction,
    Protocol,
    ScanResult,
    Vulnerability,
)
from core.session_manager import open_session
from storage.db import audit

ProgressFn = Callable[[str, str], None]


def _noop(stage: str, log: str) -> None:
    pass


# ---------------------------------------------------------------------------
# יצירת סיסמה חזקה (כעזר — המשתמש יכול לערוך, והמערכת תמיד מאמתת מול המדיניות)
# ---------------------------------------------------------------------------

def suggest_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if evaluate_password(pw).meets_policy:
            return pw


# ---------------------------------------------------------------------------
# תכנון: חולשה -> פעולת תיקון
# ---------------------------------------------------------------------------

def _vty_lines(config: str) -> str:
    m = re.search(r"line vty (\d+ \d+)", config)
    return m.group(1) if m else "0 4"


def build_plan(result: ScanResult) -> list[MitigationAction]:
    actions: list[MitigationAction] = []
    counter = 0
    seen_signatures: set[tuple[str, str]] = set()   # (device_id, title) למניעת כפילויות

    def new_id() -> str:
        nonlocal counter
        counter += 1
        return f"act{counter:03d}"

    for v in result.vulnerabilities:
        dev = result.devices.get(v.device_id)
        if not dev:
            continue
        is_network = dev.device_type.is_network_device or dev.managed
        config = dev.running_config or ""
        action: MitigationAction | None = None

        # --- התקני קצה: המלצה ידנית בלבד ---
        if not is_network:
            if v.category == Category.PORTS:
                action = MitigationAction(
                    id=new_id(), device_id=dev.id, automatic=False,
                    title=f"[ידני] {v.title}",
                    commands=["— התקן קצה: סגור/חסום את השירות ידנית בהתקן עצמו —"],
                    impact="התקני קצה אינם משתנים אוטומטית. נדרשת פעולה ידנית.")
            if action:
                actions.append(action)
            continue

        title = v.title

        if "service password-encryption" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="הפעל service password-encryption",
                commands=["service password-encryption"],
                undo_commands=["no service password-encryption"],
                impact="סיסמאות עתידיות יישמרו מוצפנות (Type 7). השפעה נמוכה.")

        elif "Telnet מותר" in title or "transport input" in title:
            vty = _vty_lines(config)
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="אפשר SSH בלבד בקווי VTY",
                commands=[f"line vty {vty}", "transport input ssh"],
                undo_commands=[f"line vty {vty}", "transport input telnet ssh"],
                impact="⚠ לקוחות שמתחברים ב-Telnet יפסיקו להתחבר. ודא שיש גישת SSH תקינה.")

        elif "SNMP community" in title:
            m = re.search(r"community (\S+) (RO|RW)", v.evidence)
            if m:
                comm, access = m.group(1), m.group(2)
                action = MitigationAction(
                    id=new_id(), device_id=dev.id,
                    title=f"הסר SNMP community '{comm}'",
                    commands=[f"no snmp-server community {comm}"],
                    undo_commands=[f"snmp-server community {comm} {access}"],
                    impact="⚠ ניטור שמשתמש ב-community זה יפסיק לעבוד. הגדר community חזק/SNMPv3.")

        elif "HTTP" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="כבה שרת HTTP לא מוצפן",
                commands=["no ip http server"],
                undo_commands=["ip http server"],
                impact="ניהול דרך HTTP ייחסם. השתמש ב-HTTPS (ip http secure-server).")

        elif "exec-timeout 0" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="הגדר exec-timeout לקווים",
                commands=["line con 0", "exec-timeout 5 0",
                          f"line vty {_vty_lines(config)}", "exec-timeout 5 0"],
                undo_commands=["line con 0", "exec-timeout 0 0"],
                impact="סשן לא פעיל יתנתק אחרי 5 דקות.")

        elif "login block-for" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="הפעל הגנת login block-for",
                commands=["login block-for 120 attempts 5 within 60"],
                undo_commands=["no login block-for"],
                impact="אחרי 5 כשלונות ב-60 שניות, ההתחברות תיחסם ל-120 שניות.")

        elif "פורטים פיזיים לא בשימוש" in title:
            ports = [p.strip() for p in v.evidence.replace("...", "").split(",") if p.strip()]
            cmds = []
            for p in ports:
                cmds += [f"interface {p}", "shutdown",
                         "description UNUSED-DISABLED-BY-NETGUARD"]
            undo = []
            for p in ports:
                undo += [f"interface {p}", "no shutdown"]
            action = MitigationAction(
                id=new_id(), device_id=dev.id,
                title=f"כבה {len(ports)} פורטים לא בשימוש",
                commands=cmds, undo_commands=undo,
                impact="⚠ התקנים שיחוברו לפורטים אלו לא יקבלו רשת עד לביטול הכיבוי.")

        elif "סיסמה חלשה ב-enable" in title or "הצפנה חלשה (טקסט גלוי) ב-enable" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="החלף enable לסיסמה חזקה (Type 9)",
                commands=["enable algorithm-type scrypt secret {new_password}"],
                requires_input=["new_password"], input_target="enable",
                impact="סיסמת ה-enable תוחלף. שמור את הסיסמה החדשה במקום בטוח.")

        elif "ההתקן מקבל סיסמת ברירת מחדל" in title:
            action = MitigationAction(
                id=new_id(), device_id=dev.id, title="החלף סיסמת enable (ברירת מחדל)",
                commands=["enable algorithm-type scrypt secret {new_password}"],
                requires_input=["new_password"], input_target="enable",
                impact="⚠ קריטי: ההתקן מקבל סיסמת ברירת מחדל. החלף מיידית.")

        elif "סיסמה חלשה ב-username" in title or "הצפנה חלשה" in title and "username" in title:
            m = re.search(r"username (\S+)", title)
            if m:
                user = m.group(1)
                action = MitigationAction(
                    id=new_id(), device_id=dev.id,
                    title=f"החלף סיסמת המשתמש {user} (Type 9)",
                    commands=[f"username {user} algorithm-type scrypt secret {{new_password}}"],
                    requires_input=["new_password"], input_target=f"username {user}",
                    impact=f"סיסמת המשתמש {user} תוחלף.")

        if action:
            # חתימה לפי ההתקן + הפקודות עצמן: שתי חולשות שמתמפות לאותו תיקון מתאחדות
            signature = (action.device_id, tuple(action.commands))
            if signature in seen_signatures:
                # חולשה נוספת שמתמפה לאותו תיקון — מקשרים אותה לפעולה הקיימת
                for existing in actions:
                    if (existing.device_id, tuple(existing.commands)) == signature:
                        v.mitigation_id = existing.id
                        break
                continue
            seen_signatures.add(signature)
            v.mitigation_id = action.id
            actions.append(action)

    return actions


# ---------------------------------------------------------------------------
# ביצוע (רק פעולות מאושרות)
# ---------------------------------------------------------------------------

def _fill_inputs(commands: list[str], inputs: dict[str, str]) -> list[str]:
    out = []
    for c in commands:
        for key, val in inputs.items():
            c = c.replace("{" + key + "}", val)
        out.append(c)
    return out


def validate_action_inputs(action: MitigationAction, inputs: dict[str, str]) -> list[str]:
    """מאמת שהקלט (סיסמה) עומד במדיניות. מחזיר רשימת שגיאות."""
    errors: list[str] = []
    if "new_password" in action.requires_input:
        pw = inputs.get("new_password", "")
        is_admin = "enable" in action.input_target or "privilege" in action.title
        verdict = evaluate_password(pw, is_admin=is_admin)
        if not verdict.meets_policy:
            errors.extend(verdict.issues)
    return errors


def execute_action(action: MitigationAction, device, inputs: dict[str, str],
                   actor: str, managed_cred: Credential | None = None,
                   progress: ProgressFn = _noop) -> MitigationAction:
    """מבצע פעולה אחת: גיבוי -> ביצוע -> אימות. מעדכן את סטטוס הפעולה."""
    if not action.automatic:
        action.status = "manual"
        return action

    # אימות קלט לפני ביצוע
    errors = validate_action_inputs(action, inputs)
    if errors:
        action.status = "failed"
        action.output = "הסיסמה אינה עומדת במדיניות: " + "; ".join(errors)
        return action

    progress(action.id, f"מתחבר ל-{device.ip} ...")
    outcome = open_session(device.ip, user_cred=managed_cred,
                           netmiko_type=device.netmiko_type or None)
    if not outcome.session:
        action.status = "failed"
        action.output = outcome.skipped_reason or "לא ניתן להתחבר להתקן."
        return action

    session = outcome.session
    try:
        # 1) גיבוי (חובה)
        if settings()["mitigation"]["backup_before_change"]:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = project_path(f"{settings()['storage']['backups_dir']}/"
                                  f"{device.ip}_{ts}.cfg")
            action.backup_path = session.save_running_backup(str(backup))
            progress(action.id, f"גיבוי נשמר: {action.backup_path}")

        # 2) ביצוע
        cmds = _fill_inputs(action.commands, inputs)
        progress(action.id, "מריץ פקודות...")
        action.output = session.apply_config(cmds)
        action.status = "done"

        audit(actor, "mitigation_executed", device.ip,
              f"{action.title} | commands={len(cmds)}")
        progress(action.id, "✔ בוצע")
    except Exception as e:
        action.status = "failed"
        action.output = f"שגיאה: {e}"
        audit(actor, "mitigation_failed", device.ip, f"{action.title}: {e}")
    finally:
        session.close()
    return action


def rollback_action(action: MitigationAction, device, actor: str,
                    managed_cred: Credential | None = None,
                    progress: ProgressFn = _noop) -> MitigationAction:
    """מריץ את פקודות הביטול לשחזור המצב הקודם."""
    if not action.undo_commands:
        action.output = "לפעולה זו אין פקודות ביטול אוטומטיות. שחזר ידנית מהגיבוי: " + action.backup_path
        return action

    outcome = open_session(device.ip, user_cred=managed_cred,
                           netmiko_type=device.netmiko_type or None)
    if not outcome.session:
        action.output = "לא ניתן להתחבר לביצוע Rollback."
        return action
    session = outcome.session
    try:
        session.apply_config(action.undo_commands)
        action.status = "rolled_back"
        audit(actor, "mitigation_rolled_back", device.ip, action.title)
        progress(action.id, "↩ שוחזר")
    except Exception as e:
        action.output = f"שגיאת Rollback: {e}"
    finally:
        session.close()
    return action
