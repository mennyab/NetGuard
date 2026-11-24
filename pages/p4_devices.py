"""מסך 4 — רשימת התקנים (Device Inventory)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from ui.state import get_scan_result
from ui.theme import page_header

page_header("📋 רשימת התקנים", "כל ההתקנים שזוהו בסריקה האחרונה")

result = get_scan_result()
if not result or not result.devices:
    st.info("עדיין לא בוצעה סריקה. עבור למסך הסריקה.")
    if st.button("📡 למסך הסריקה"):
        st.switch_page("pages/p2_scan.py")
    st.stop()

# בניית טבלה
rows = []
for dev in result.devices.values():
    rows.append({
        "סוג": f"{dev.device_type.icon} {dev.device_type.value}",
        "IP": dev.ip,
        "Hostname": dev.hostname or "—",
        "MAC": dev.mac or "—",
        "יצרן": dev.vendor or "—",
        "OS / תיאור": (dev.os[:40] + "…") if len(dev.os) > 40 else (dev.os or "—"),
        "פורטים": len(dev.open_ports),
        "מקורות": ", ".join(dev.discovered_by),
        "_id": dev.id,
    })
df = pd.DataFrame(rows)

# סינון
f1, f2, f3 = st.columns([2, 2, 3])
types = ["הכל"] + sorted({r["סוג"] for r in rows})
sel_type = f1.selectbox("סוג התקן", types)
search = f3.text_input("🔍 חיפוש (IP / שם / יצרן)")

view = df.copy()
if sel_type != "הכל":
    view = view[view["סוג"] == sel_type]
if search:
    s = search.lower()
    mask = view.apply(lambda r: s in str(r["IP"]).lower()
                      or s in str(r["Hostname"]).lower()
                      or s in str(r["יצרן"]).lower(), axis=1)
    view = view[mask]

f2.metric("מוצגים", len(view))

st.dataframe(
    view.drop(columns=["_id"]),
    use_container_width=True,
    hide_index=True,
)

# בחירת התקן למעבר לפרטים
st.divider()
ids = {f'{r["IP"]} — {r["Hostname"]}': r["_id"] for _, r in view.iterrows()}
if ids:
    chosen = st.selectbox("בחר התקן לצפייה בפרטים", list(ids.keys()))
    if st.button("🔎 פתח פרטי התקן"):
        st.session_state.selected_device_id = ids[chosen]
        st.switch_page("pages/p5_device_details.py")

# ייצוא CSV
st.download_button("📥 ייצוא ל-CSV", df.drop(columns=["_id"]).to_csv(index=False),
                   file_name="netguard_devices.csv", mime="text/csv")
