"""בדיקת חוזק סיסמאות מול המדיניות (password_policy.yaml).

מעריך סיסמה שניתן לקרוא בטקסט גלוי (Type 0, Type 7 מפוענח, או סיסמה
שהמשתמש מקליד במערכת). מחזיר רשימת הפרות וציון חוזק.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.config_loader import common_passwords, password_policy

SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop",
             "asdfghjkl", "zxcvbnm"]


@dataclass
class PasswordVerdict:
    strength: str = "unknown"          # weak / medium / strong
    score: int = 0                     # 0-4 (zxcvbn)
    issues: list[str] = field(default_factory=list)
    meets_policy: bool = False


def _has_sequence(pw: str) -> bool:
    low = pw.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in low or seq[i:i + 4][::-1] in low:
                return True
    return False


def _has_repeats(pw: str, max_repeat: int) -> bool:
    return bool(re.search(r"(.)\1{" + str(max_repeat) + r",}", pw))


def evaluate_password(password: str, *, is_admin: bool = False,
                      context_words: list[str] | None = None) -> PasswordVerdict:
    """בודק סיסמה גלויה מול המדיניות."""
    policy = password_policy()
    verdict = PasswordVerdict()
    issues = verdict.issues
    context_words = (context_words or []) + policy.get("context_words", [])

    min_len = policy["min_length_admin"] if is_admin else policy["min_length"]
    if len(password) < min_len:
        issues.append(f"קצרה מהמינימום ({len(password)} < {min_len} תווים)")
    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        issues.append("חסרה אות גדולה")
    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        issues.append("חסרה אות קטנה")
    if policy["require_digit"] and not re.search(r"\d", password):
        issues.append("חסרה ספרה")
    if policy["require_special"]:
        specials = re.escape(policy["special_characters"])
        if not re.search(f"[{specials}]", password):
            issues.append("חסר תו מיוחד")

    if policy["forbid_common_passwords"] and password.lower() in common_passwords():
        issues.append("מופיעה ברשימת הסיסמאות הנפוצות")
    if policy["forbid_context_words"]:
        for word in context_words:
            if word and len(word) >= 3 and word.lower() in password.lower():
                issues.append(f"מכילה מידע הקשרי ({word})")
                break
    if _has_repeats(password, policy["max_repeated_chars"]):
        issues.append("מכילה תווים חוזרים ברצף")
    if policy["forbid_sequences"] and _has_sequence(password):
        issues.append("מכילה רצף צפוי (1234 / abcd / qwerty)")

    # ציון zxcvbn
    try:
        from zxcvbn import zxcvbn
        verdict.score = int(zxcvbn(password)["score"])
    except Exception:
        verdict.score = 0
    if verdict.score < policy["min_strength_score"]:
        issues.append(f"ציון חוזק נמוך ({verdict.score}/4)")

    verdict.meets_policy = len(issues) == 0
    verdict.strength = ("strong" if verdict.meets_policy and verdict.score >= 3
                        else "weak" if verdict.score <= 1 or len(password) < min_len
                        else "medium")
    return verdict
