"""שמירה וטעינה של פרופילי סריקה, כולל פרטי גישה מוצפנים.

הצפנה: Fernet (AES-128-CBC + HMAC) עם מפתח שנגזר מ"סיסמת מאסטר"
באמצעות PBKDF2-HMAC-SHA256. בלי סיסמת המאסטר אי אפשר לפענח את הקובץ.
הסיסמאות לעולם לא נכתבות לדיסק בטקסט גלוי.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import asdict, dataclass, field

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.config_loader import project_path

PROFILE_DIR = "storage/profiles"
PBKDF2_ITERATIONS = 390_000


@dataclass
class ManagedDevice:
    """התקן רשת מנוהל שהמשתמש הגדיר ידנית במסך Setup."""
    ip: str
    protocol: str = "ssh"            # ssh / telnet
    username: str = ""
    password: str = ""
    enable_password: str = ""


@dataclass
class ScanProfile:
    name: str = "default"
    subnets: list[str] = field(default_factory=list)
    managed_devices: list[ManagedDevice] = field(default_factory=list)
    snmp_community: str = ""
    snmp_version: str = "v2c"
    max_login_attempts: int = 5
    try_default_creds: bool = False
    authorized: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ScanProfile":
        devices = [ManagedDevice(**md) for md in d.pop("managed_devices", [])]
        return cls(managed_devices=devices, **d)


# ---------------------------------------------------------------------------
# הצפנה
# ---------------------------------------------------------------------------

def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def _profile_path(name: str):
    safe = "".join(c for c in name if c.isalnum() or c in ("-", "_")) or "profile"
    return project_path(f"{PROFILE_DIR}/{safe}.ngp")


def save_profile(profile: ScanProfile, master_password: str) -> str:
    """שומר פרופיל מוצפן. מחזיר את הנתיב."""
    salt = os.urandom(16)
    key = _derive_key(master_password, salt)
    payload = json.dumps(profile.to_dict(), ensure_ascii=False).encode("utf-8")
    token = Fernet(key).encrypt(payload)

    path = _profile_path(profile.name)
    with open(path, "wb") as f:
        f.write(b"NGP1" + salt + token)      # כותרת + salt + ciphertext
    return str(path)


def load_profile(name: str, master_password: str) -> ScanProfile:
    """טוען ומפענח פרופיל. סיסמת מאסטר שגויה -> ValueError."""
    path = _profile_path(name)
    with open(path, "rb") as f:
        blob = f.read()
    if blob[:4] != b"NGP1":
        raise ValueError("קובץ פרופיל לא תקין.")
    salt, token = blob[4:20], blob[20:]
    key = _derive_key(master_password, salt)
    try:
        payload = Fernet(key).decrypt(token)
    except InvalidToken:
        raise ValueError("סיסמת מאסטר שגויה או קובץ פגום.")
    return ScanProfile.from_dict(json.loads(payload.decode("utf-8")))


def list_profiles() -> list[str]:
    folder = project_path(f"{PROFILE_DIR}/_").parent
    return sorted(p.stem for p in folder.glob("*.ngp"))
