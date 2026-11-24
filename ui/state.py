"""ניהול המצב המשותף בין מסכי Streamlit (st.session_state)."""

from __future__ import annotations

import streamlit as st

from core.profile_store import ScanProfile


def get_profile() -> ScanProfile:
    if "profile" not in st.session_state:
        st.session_state.profile = ScanProfile()
    return st.session_state.profile


def set_profile(profile: ScanProfile) -> None:
    st.session_state.profile = profile


def get_scan_result():
    return st.session_state.get("scan_result")


def set_scan_result(result) -> None:
    st.session_state.scan_result = result


def selected_device_id() -> str | None:
    return st.session_state.get("selected_device_id")
