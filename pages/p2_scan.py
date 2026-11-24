"""מסך 2 — סריקה (Discovery) עם סרגל התקדמות ויומן חי."""

from __future__ import annotations

import streamlit as st

from core.discovery import discover
from core.models import DeviceType
from ui.state import get_profile, set_scan_result
from ui.theme import page_header

page_header("📡 סריקה", "גילוי ההתקנים ברשת, זיהוי יצרן, פורטים וסוג ההתקן")

profile = get_profile()

# סיכום ההגדרות
c1, c2, c3 = st.columns(3)
c1.metric("תת-רשתות", len(profile.subnets))
c2.metric("מתגים/נתבים מוגדרים", len(profile.managed_devices))
c3.metric("ניסיונות להתקן", profile.max_login_attempts)

if not profile.subnets:
    st.error("לא הוגדרו תת-רשתות. חזור למסך ההגדרות.")
    if st.button("⬅ חזרה להגדרות"):
        st.switch_page("pages/p1_setup.py")
    st.stop()

if not profile.authorized:
    st.error("לא סומן אישור הרשאה במסך ההגדרות.")
    st.stop()

st.caption("תת-רשתות לסריקה: " + ", ".join(profile.subnets))

start = st.button("▶ התחל סריקה", type="primary")

# הפעלה אוטומטית אם הגענו ממסך ההגדרות בלחיצת "סריקה אוטומטית"
auto_run = st.session_state.pop("auto_run_scan", False)
if auto_run:
    st.info("🚀 סריקה אוטומטית רצה...")

if start or auto_run:
    progress_bar = st.progress(0.0, text="מתכונן...")
    log_box = st.container(height=320)
    log_lines: list[str] = []

    def on_progress(stage: str, fraction: float, log: str) -> None:
        if fraction > 0:
            progress_bar.progress(min(fraction, 1.0), text=f"{stage}...")
        if log:
            log_lines.append(f"[{stage}] {log}")
            # מציג את 200 השורות האחרונות
            log_box.code("\n".join(log_lines[-200:]), language=None)

    with st.spinner("סורק..."):
        result = discover(
            subnets=profile.subnets,
            snmp_community=profile.snmp_community,
            snmp_version=profile.snmp_version,
            progress=on_progress,
        )
    progress_bar.progress(1.0, text="הסתיים")

    # בסריקה אוטומטית: ממשיכים ישר לבניית הטופולוגיה מה-Gateway שזוהה
    if auto_run and st.session_state.get("auto_seed_ip"):
        from core.models import Credential, Protocol
        from core.topology import crawl
        seed_ip = st.session_state.get("auto_seed_ip")
        st.info(f"🕸 בונה טופולוגיה אוטומטית מ-{seed_ip} ...")
        md = next((d for d in profile.managed_devices if d.ip == seed_ip), None)
        seed_cred = (Credential(username=md.username, password=md.password,
                                enable_password=md.enable_password,
                                protocol=Protocol(md.protocol)) if md
                     else Credential(protocol=Protocol.SSH))
        result, needs = crawl(seed_ip, seed_cred, progress=on_progress, existing=result)
        if needs:
            st.warning(f"{len(needs)} התקנים התגלו כשכנים אך לא היו נגישים.")

    set_scan_result(result)

    # שמירה אוטומטית להיסטוריה (החלטה 29)
    try:
        from storage.repository import save_scan
        sid = save_scan(result)
        st.caption(f"💾 הסריקה נשמרה להיסטוריה (#{sid})")
    except Exception as e:
        st.caption(f"⚠ שמירה להיסטוריה נכשלה: {e}")

    st.success(f"✔ הסריקה הסתיימה — נמצאו {len(result.devices)} התקנים")

    # בסריקה אוטומטית: עוברים לטופולוגיה, ושם ה-Assessment ירוץ אוטומטית
    if auto_run:
        st.session_state.auto_assess_pending = True
        st.switch_page("pages/p3_topology.py")

    type_counts: dict[str, int] = {}
    for dev in result.devices.values():
        label = f"{dev.device_type.icon} {dev.device_type.value}"
        type_counts[label] = type_counts.get(label, 0) + 1
    cols = st.columns(max(len(type_counts), 1))
    for col, (label, count) in zip(cols, sorted(type_counts.items())):
        col.metric(label, count)

    b1, b2 = st.columns(2)
    if b1.button("📋 צפה ברשימת ההתקנים", type="primary", use_container_width=True):
        st.switch_page("pages/p4_devices.py")
    if b2.button("🗺 צפה בטופולוגיה", use_container_width=True):
        st.switch_page("pages/p3_topology.py")

elif st.session_state.get("scan_result"):
    st.info("קיימת סריקה קודמת בזיכרון. אפשר להתחיל סריקה חדשה או לעבור למסכים הבאים.")
    if st.button("📋 רשימת ההתקנים מהסריקה האחרונה"):
        st.switch_page("pages/p4_devices.py")
