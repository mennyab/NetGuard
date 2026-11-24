"""Pivoting — הגעה להתקן שאינו נגיש ישירות, דרך התקן נגיש (telnet מקונן).

כמו מהנדס רשת שמתחבר ל-R3, ומשם עושה telnet ל-R2, ומשם ל-sw3.
משמש את הזחילה כדי למפות התקנים מעבר לקטע רשת שהמחשב לא מנתב אליו.

הערה: pivot מיועד לקריאה בלבד (show). שינוי קונפיגורציה (Mitigation) דורש גישה ישירה.
"""

from __future__ import annotations

import re
import time

# תבניות שמופיעות אחרי "telnet <ip>"
_USERNAME_RE = re.compile(r"sername[: ]*$|ogin[: ]*$", re.I)
_PASSWORD_RE = re.compile(r"assword[: ]*$", re.I)
_PROMPT_RE = re.compile(r"[>#]\s*$")
_FAIL_RE = re.compile(r"(refused|unreachable|timed out|closed|%\s*Connection|denied)", re.I)


def pivot_hop(handler, target_ip: str, username: str = "cisco",
              passwords: list[str] | None = None, enable_password: str = "") -> bool:
    """מבצע telnet מההתקן הנוכחי ל-target_ip ומתחבר. מחזיר True אם הגענו ל-prompt.

    handler — חיבור Netmiko הפעיל, שנמצא כרגע ב-prompt של התקן נגיש.
    """
    passwords = passwords or ["cisco"]
    try:
        handler.write_channel(f"telnet {target_ip}\n")
    except Exception:
        return False

    deadline = time.time() + 25
    buffer = ""
    pw_index = 0
    sent_username = False

    while time.time() < deadline:
        time.sleep(1.0)
        try:
            buffer += handler.read_channel()
        except Exception:
            return False
        tail = buffer[-200:]

        if _FAIL_RE.search(tail):
            return False
        if _USERNAME_RE.search(tail) and not sent_username:
            handler.write_channel((username or "cisco") + "\n")
            sent_username = True
            buffer = ""
            continue
        if _PASSWORD_RE.search(tail):
            pw = passwords[pw_index] if pw_index < len(passwords) else passwords[-1]
            handler.write_channel(pw + "\n")
            pw_index += 1
            sent_username = False
            buffer = ""
            continue
        if _PROMPT_RE.search(tail):
            _maybe_enable(handler, enable_password or passwords[0])
            # ביטול עימוד (--More--) בהתקן המרוחק, אחרת פלט ארוך ייחתך
            try:
                handler.write_channel("terminal length 0\n")
                time.sleep(0.6)
                handler.read_channel()
            except Exception:
                pass
            try:
                handler.set_base_prompt()
            except Exception:
                pass
            return True
    return False


def _maybe_enable(handler, enable_pw: str) -> None:
    """נכנס ל-enable אם ההתקן במצב user (>)."""
    try:
        prompt = handler.read_channel()
        handler.write_channel("enable\n")
        time.sleep(1.0)
        out = handler.read_channel()
        if _PASSWORD_RE.search(out[-100:]):
            handler.write_channel(enable_pw + "\n")
            time.sleep(1.0)
            handler.read_channel()
    except Exception:
        pass


def pivot_teardown(handler, depth: int) -> None:
    """יוצא מכל ה-telnet-ים המקוננים וחוזר להתקן הבסיס (לא מנתק את חיבור הבסיס)."""
    for _ in range(depth):
        try:
            handler.write_channel("exit\n")
            time.sleep(1.0)
            handler.read_channel()
        except Exception:
            break
    try:
        handler.set_base_prompt()
    except Exception:
        pass
