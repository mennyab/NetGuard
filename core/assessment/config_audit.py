"""ביקורת קונפיגורציה של התקן רשת (running-config).

מחלץ פרטי סיסמאות עם סוג ההצפנה, בודק הקשחת התחברות ושירותים מסוכנים,
ומחזיר רשימת חולשות + אוסף הסיסמאות הגלויות לבדיקת חוזק.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.assessment.passwords import evaluate_password
from core.assessment.type7 import decode_type7
from core.config_loader import password_policy
from core.models import Category, Severity, Vulnerability


@dataclass
class ConfigFinding:
    title: str
    category: Category
    severity: Severity
    details: str = ""
    evidence: str = ""


@dataclass
class CredentialInConfig:
    who: str                 # "enable" / "username bob" / "line vty 0 4"
    enc_type: int            # 0,5,7,8,9  (-1 = לא ידוע)
    plaintext: str | None    # אם ניתן לקרוא/לפענח
    is_admin: bool = False


SEVERITY_BY_ENC = {
    0: Severity.CRITICAL,   # טקסט גלוי
    7: Severity.HIGH,       # הפיך
    5: Severity.MEDIUM,     # MD5
    8: Severity.LOW,        # PBKDF2 — חזק, אבל נבדוק את הסיסמה עצמה אם אפשר
    9: Severity.LOW,        # scrypt
}


def _enc_name(enc: int) -> str:
    return password_policy()["encryption_types"].get(f"type{enc}", {}).get("name", f"Type {enc}")


# ---------------------------------------------------------------------------
# חילוץ סיסמאות מהקונפיגורציה
# ---------------------------------------------------------------------------

def extract_credentials(config: str) -> list[CredentialInConfig]:
    creds: list[CredentialInConfig] = []

    # enable secret / password
    for m in re.finditer(r"^enable (secret|password)(?:\s+(\d+))?\s+(\S+)", config, re.M):
        kind, enc, val = m.group(1), m.group(2), m.group(3)
        enc_type = int(enc) if enc else (5 if kind == "secret" else 0)
        creds.append(CredentialInConfig(
            who=f"enable {kind}", enc_type=enc_type,
            plaintext=_recover_plaintext(enc_type, val), is_admin=True))

    # username ... password/secret
    for m in re.finditer(r"^username (\S+).*?(password|secret)(?:\s+(\d+))?\s+(\S+)", config, re.M):
        user, kind, enc, val = m.group(1), m.group(2), m.group(3), m.group(4)
        enc_type = int(enc) if enc else (5 if kind == "secret" else 0)
        is_admin = bool(re.search(rf"^username {re.escape(user)}.*privilege 15", config, re.M))
        creds.append(CredentialInConfig(
            who=f"username {user}", enc_type=enc_type,
            plaintext=_recover_plaintext(enc_type, val), is_admin=is_admin))

    # line passwords (vty / console)
    for m in re.finditer(r"^line (\S+[\s\d]*)\n((?:\s+.*\n)*)", config, re.M):
        line_name, body = m.group(1).strip(), m.group(2)
        pm = re.search(r"password(?:\s+(\d+))?\s+(\S+)", body)
        if pm:
            enc_type = int(pm.group(1)) if pm.group(1) else 0
            creds.append(CredentialInConfig(
                who=f"line {line_name}", enc_type=enc_type,
                plaintext=_recover_plaintext(enc_type, pm.group(2))))
    return creds


def _recover_plaintext(enc_type: int, value: str) -> str | None:
    if enc_type == 0:
        return value
    if enc_type == 7:
        return decode_type7(value)       # פענוח לבדיקה בלבד
    return None                          # Type 5/8/9 — לא ניתן לשחזר


# ---------------------------------------------------------------------------
# בדיקות הקשחה ושירותים
# ---------------------------------------------------------------------------

def audit_config(config: str, device_name: str = "") -> tuple[list[ConfigFinding], list[CredentialInConfig]]:
    findings: list[ConfigFinding] = []
    cfg = config

    def add(title, category, severity, details="", evidence=""):
        findings.append(ConfigFinding(title, category, severity, details, evidence))

    # --- service password-encryption ---
    if not re.search(r"^service password-encryption", cfg, re.M):
        add("אין service password-encryption", Category.PASSWORD, Severity.HIGH,
            "סיסמאות עלולות להישמר בטקסט גלוי בקונפיגורציה.",
            "service password-encryption (חסר)")

    # --- Telnet על קווי VTY ---
    for m in re.finditer(r"^line vty .*\n((?:\s+.*\n)*)", cfg, re.M):
        body = m.group(1)
        if re.search(r"transport input .*telnet", body) or \
           (re.search(r"transport input all", body)):
            add("Telnet מותר בקווי VTY", Category.ACCESS, Severity.HIGH,
                "יש לאפשר SSH בלבד: transport input ssh.",
                "transport input telnet/all")
            break
        if "transport input" not in body and "password" in body:
            add("קווי VTY ללא הגבלת transport input", Category.ACCESS, Severity.MEDIUM,
                "מומלץ להגדיר transport input ssh במפורש.", "line vty")
            break

    # --- SNMP community חלש ---
    for m in re.finditer(r"^snmp-server community (\S+)\s*(RO|RW)?", cfg, re.M):
        comm, access = m.group(1), m.group(2) or "RO"
        if comm.lower() in ("public", "private"):
            sev = Severity.CRITICAL if access == "RW" else Severity.HIGH
            add(f"SNMP community ברירת מחדל '{comm}' ({access})", Category.ACCESS, sev,
                "יש להחליף ל-community ייחודי וחזק, ועדיף SNMPv3.",
                f"snmp-server community {comm} {access}")

    # --- HTTP server לניהול ---
    if re.search(r"^ip http server", cfg, re.M) and not re.search(r"^no ip http server", cfg, re.M):
        add("שרת HTTP (לא מוצפן) פעיל לניהול", Category.SERVICES, Severity.MEDIUM,
            "מומלץ: no ip http server, ולהשתמש ב-HTTPS בלבד.", "ip http server")

    # --- aux / console ללא סיסמה ---
    if re.search(r"^line aux 0\n((?:\s+.*\n)*)", cfg, re.M):
        aux_body = re.search(r"^line aux 0\n((?:\s+.*\n)*)", cfg, re.M).group(1)
        if "no exec" not in aux_body and "password" not in aux_body:
            add("קו AUX פעיל ללא הגנה", Category.ACCESS, Severity.MEDIUM,
                "מומלץ: no exec בקו ה-AUX.", "line aux 0")

    # --- exec-timeout 0 (אין ניתוק אוטומטי) ---
    if re.search(r"exec-timeout 0 0", cfg):
        add("exec-timeout 0 (אין ניתוק סשן לא פעיל)", Category.ACCESS, Severity.MEDIUM,
            "מומלץ exec-timeout 5 0 ומטה.", "exec-timeout 0 0")

    # --- login block-for (הגנה מפני ניחוש) ---
    if not re.search(r"^login block-for", cfg, re.M):
        add("אין הגנת login block-for מפני ניסיונות ניחוש", Category.ACCESS, Severity.LOW,
            "מומלץ: login block-for 120 attempts 5 within 60.", "login block-for (חסר)")

    creds = extract_credentials(cfg)
    return findings, creds


# ---------------------------------------------------------------------------
# המרת ממצאים לחולשות, כולל חוזק סיסמאות
# ---------------------------------------------------------------------------

def build_vulnerabilities(device_id: str, device_name: str,
                          findings: list[ConfigFinding],
                          creds: list[CredentialInConfig]) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    for f in findings:
        vulns.append(Vulnerability(
            device_id=device_id, title=f.title, category=f.category,
            severity=f.severity, details=f.details, evidence=f.evidence))

    # חולשות סיסמה לפי סוג הצפנה + חוזק
    for c in creds:
        sev = SEVERITY_BY_ENC.get(c.enc_type, Severity.MEDIUM)
        enc_label = _enc_name(c.enc_type)

        # סוג הצפנה חלש
        if c.enc_type in (0, 7, 5):
            vulns.append(Vulnerability(
                device_id=device_id,
                title=f"סיסמה בהצפנה חלשה ({enc_label}) ב-{c.who}",
                category=Category.PASSWORD, severity=sev,
                details=f"סוג ההצפנה {enc_label} אינו מספק. מומלץ Type 8/9.",
                evidence=f"{c.who}: {enc_label}"))

        # חוזק הסיסמה עצמה (אם ניתן לקרוא/לפענח)
        if c.plaintext is not None:
            verdict = evaluate_password(c.plaintext, is_admin=c.is_admin,
                                        context_words=[device_name])
            if not verdict.meets_policy:
                sev2 = Severity.CRITICAL if verdict.strength == "weak" else Severity.HIGH
                vulns.append(Vulnerability(
                    device_id=device_id,
                    title=f"סיסמה חלשה ב-{c.who} (חוזק: {verdict.strength})",
                    category=Category.PASSWORD, severity=sev2,
                    details="הסיסמה אינה עומדת במדיניות: " + "; ".join(verdict.issues),
                    evidence=f"{c.who} — {len(verdict.issues)} הפרות מדיניות"))
                # הערה: הסיסמה הגלויה עצמה לא נשמרת בחולשה
    return vulns
