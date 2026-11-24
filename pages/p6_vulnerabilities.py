"""מסך 6 — דוח חולשות (Vulnerability Dashboard)."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from core.assessment.engine import assess
from core.models import Severity
from ui.state import get_profile, get_scan_result, set_scan_result
from ui.theme import page_header

page_header("⚠️ דוח חולשות", "סיכום החולשות ברשת ובכל התקן")

result = get_scan_result()
profile = get_profile()

if not result or not result.devices:
    st.info("עדיין לא בוצעה סריקה.")
    if st.button("📡 למסך הסריקה"):
        st.switch_page("pages/p2_scan.py")
    st.stop()

# הרצת בדיקה — רק בלחיצה מפורשת (הבדיקה מתחברת להתקנים)
st.caption("הבדיקה מתחברת למתגים ולנתבים כדי לקרוא קונפיגורציה (קריאה בלבד).")
if st.button("🔍 הרץ/רענן בדיקת חולשות", type="primary"):
    progress_bar = st.progress(0.0, text="בודק...")
    log_box = st.container(height=200)
    logs: list[str] = []

    def on_progress(stage, fraction, log):
        if fraction > 0:
            progress_bar.progress(min(fraction, 1.0), text=stage)
        if log:
            logs.append(f"[{stage}] {log}")
            log_box.code("\n".join(logs[-120:]), language=None)

    with st.spinner("מריץ בדיקות אבטחה..."):
        result = assess(result, managed_devices=profile.managed_devices,
                        try_default_creds=profile.try_default_creds,
                        progress=on_progress)
    set_scan_result(result)
    st.session_state._assessed_once = True

vulns = result.vulnerabilities
if not vulns:
    st.success("🎉 לא נמצאו חולשות (או שהבדיקה עדיין לא רצה).")
    st.stop()

# ---------------------------------------------------------------------------
# כרטיסי סיכום
# ---------------------------------------------------------------------------
counts = {s: sum(1 for v in vulns if v.severity == s) for s in Severity}
c = st.columns(5)
c[0].metric("🔴 קריטי", counts[Severity.CRITICAL])
c[1].metric("🟠 גבוה", counts[Severity.HIGH])
c[2].metric("🟡 בינוני", counts[Severity.MEDIUM])
c[3].metric("🟢 נמוך", counts[Severity.LOW])
c[4].metric("ציון רשת", f"{result.risk_score}/100")
st.progress(result.risk_score / 100)

# ---------------------------------------------------------------------------
# גרפים
# ---------------------------------------------------------------------------
g1, g2 = st.columns(2)
by_cat = pd.DataFrame(
    [{"קטגוריה": v.category.value, "חומרה": v.severity.value} for v in vulns])
with g1:
    st.markdown("**חולשות לפי קטגוריה**")
    fig = px.histogram(by_cat, x="קטגוריה", color="חומרה",
                       color_discrete_map={"critical": "#e74c3c", "high": "#e67e22",
                                           "medium": "#f1c40f", "low": "#2ecc71"})
    st.plotly_chart(fig, use_container_width=True)
with g2:
    st.markdown("**ציון בטיחות לכל התקן** (ירוק=גבוה, צהוב=בינוני, אדום=נמוך)")
    from core.models import score_color
    dev_scores = []
    for dev in result.devices.values():
        s = result.device_score(dev.id)
        dev_scores.append({"התקן": dev.display_name, "ציון": s, "color": score_color(s)})
    dev_scores.sort(key=lambda r: r["ציון"])
    by_dev = pd.DataFrame(dev_scores)
    fig2 = px.bar(by_dev, x="התקן", y="ציון", range_y=[0, 100])
    fig2.update_traces(marker_color=by_dev["color"])
    fig2.update_layout(showlegend=False)
    st.plotly_chart(fig2, use_container_width=True)

# ---------------------------------------------------------------------------
# טבלת חולשות
# ---------------------------------------------------------------------------
st.subheader("רשימת החולשות")

# --- מסננים: לפי התקן ולפי חומרה ---
dev_names = {}
for v in vulns:
    d = result.devices.get(v.device_id)
    dev_names[v.device_id] = d.display_name if d else v.device_id
f1, f2 = st.columns(2)
device_filter = f1.selectbox("סנן לפי התקן",
                             ["כל ההתקנים"] + sorted(set(dev_names.values())))
sev_filter = f2.selectbox("סנן לפי חומרה",
                          ["הכל", "critical", "high", "medium", "low"])

sev_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4}
rows = []
for v in sorted(vulns, key=lambda x: sev_rank[x.severity]):
    dev = result.devices.get(v.device_id)
    name = dev.display_name if dev else v.device_id
    if device_filter != "כל ההתקנים" and name != device_filter:
        continue
    if sev_filter != "הכל" and v.severity.value != sev_filter:
        continue
    rows.append({
        "חומרה": f"{v.severity.icon} {v.severity.value}",
        "התקן": name,
        "חולשה": v.title,
        "קטגוריה": v.category.value,
        "פרטים": v.details,
    })
st.caption(f"מוצגות {len(rows)} חולשות")
st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.divider()
if st.button("🛠 המשך לתוכנית תיקון (Mitigation)", type="primary"):
    st.switch_page("pages/p7_mitigation.py")
