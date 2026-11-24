"""מסך 5 — פרטי התקן (Device Details)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from core.models import Severity
from ui.state import get_scan_result
from ui.theme import page_header

result = get_scan_result()
device_id = st.session_state.get("selected_device_id")

if not result or not device_id or device_id not in result.devices:
    page_header("🔎 פרטי התקן")
    st.info("לא נבחר התקן. חזור לרשימת ההתקנים ובחר אחד.")
    if st.button("📋 לרשימת ההתקנים"):
        st.switch_page("pages/p4_devices.py")
    st.stop()

dev = result.devices[device_id]
dev_vulns = [v for v in result.vulnerabilities if v.device_id == device_id]

# כותרת + ציון סיכון של ההתקן
page_header(f"{dev.device_type.icon} {dev.display_name}",
            f"{dev.ip} · {dev.vendor or 'יצרן לא ידוע'} · {dev.model or dev.device_type.value}")
risk = sum(v.severity.weight for v in dev_vulns)
m = st.columns(4)
m[0].metric("IP", dev.ip or "—")
m[1].metric("MAC", dev.mac or "—")
m[2].metric("פורטים פתוחים", len(dev.open_ports))
m[3].metric("חולשות", len(dev_vulns))

tabs = st.tabs(["כללי", "פורטים", "חולשות", "קונפיגורציה"])

# --- כללי ---
with tabs[0]:
    st.write({
        "סוג": dev.device_type.value,
        "Hostname": dev.hostname or "—",
        "יצרן": dev.vendor or "—",
        "דגם": dev.model or "—",
        "OS / תיאור": dev.os or "—",
        "מנוהל (SSH/Telnet)": "כן" if dev.managed else "לא",
        "התגלה על ידי": ", ".join(dev.discovered_by) or "—",
    })

# --- פורטים ---
with tabs[1]:
    st.markdown("**שירותים פתוחים (nmap)**")
    if dev.open_ports:
        st.dataframe(pd.DataFrame([
            {"פורט": p.port, "פרוטוקול": p.protocol, "שירות": p.service,
             "מוצר": p.product, "גרסה": p.version} for p in dev.open_ports]),
            use_container_width=True, hide_index=True)
    else:
        st.caption("לא נמצאו פורטים פתוחים.")

    if dev.interfaces:
        st.markdown("**ממשקים פיזיים**")
        st.dataframe(pd.DataFrame([
            {"ממשק": i.name, "סטטוס": i.status, "VLAN": i.vlan,
             "תיאור": i.description, "מחובר ל": i.connected_to} for i in dev.interfaces]),
            use_container_width=True, hide_index=True)

# --- חולשות ---
with tabs[2]:
    if dev_vulns:
        sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                    Severity.LOW: 3, Severity.INFO: 4}
        for v in sorted(dev_vulns, key=lambda x: sev_rank[x.severity]):
            with st.expander(f"{v.severity.icon} {v.title}"):
                st.write(f"**קטגוריה:** {v.category.value}")
                st.write(f"**פרטים:** {v.details}")
                if v.evidence:
                    st.code(v.evidence, language=None)
    else:
        st.success("לא נמצאו חולשות בהתקן זה (או שהבדיקה לא רצה).")

# --- קונפיגורציה ---
with tabs[3]:
    if dev.running_config:
        st.code(dev.running_config, language=None)
    else:
        st.caption("לא נקראה קונפיגורציה (ההתקן אינו מנוהל או לא נגיש).")

st.divider()
if st.button("📋 חזרה לרשימת ההתקנים"):
    st.switch_page("pages/p4_devices.py")
