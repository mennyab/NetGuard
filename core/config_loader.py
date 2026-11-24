"""טעינת קבצי ההגדרות מתיקיית config/."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


def _load_yaml(name: str) -> dict:
    with open(CONFIG_DIR / name, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache
def settings() -> dict:
    return _load_yaml("settings.yaml")


@lru_cache
def password_policy() -> dict:
    return _load_yaml("password_policy.yaml")


@lru_cache
def default_credentials() -> dict:
    return _load_yaml("default_creds.yaml")


@lru_cache
def common_passwords() -> frozenset[str]:
    path = CONFIG_DIR / "common_passwords.txt"
    with open(path, encoding="utf-8") as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


def project_path(relative: str) -> Path:
    """נתיב מוחלט בתוך הפרויקט (ליצירת DB, גיבויים וכו')."""
    path = PROJECT_ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
