"""מסך 3 — מפת טופולוגיה (זחילה מ-seed + רינדור pyvis)."""

from __future__ import annotations

import streamlit as st
import streamlit.components.v1 as components

from core import netutils
from core.models import Credential, Protocol
from core.topo_render import build_html
from core.topology import crawl
from ui.state import get_profile, get_scan_result, set_scan_result
from ui.theme import page_header

page_header("🗺️ מפת טופולוגיה",
            "זחילה ברשת החל ממתג/נתב התחלתי, לפי שכנים (CDP/LLDP) ושכנויות ניתוב (OSPF)")

profile = get_profile()
result = get_scan_result()

seed_ip = None
seed_cred = None
start_crawl = False

# ---------------------------------------------------------------------------
# גילוי אוטומטי — זיהוי ה-seed (Gateway) לבד
# ---------------------------------------------------------------------------
st.subheader("🔍 גילוי אוטומטי")
gateways = netutils.default_gateways()
# מעדיפים Gateway בטווח פרטי (רשת המעבדה) על פני ברירת המחדל של ה-Wi-Fi
def _is_private(ip: str) -> bool:
    return ip.startswith(("192.168.", "10.")) or ip.startswith("172.")

auto_candidates = [g for g in gateways if _is_private(g.gateway)]
auto_candidates.sort(key=lambda g: 0 if g.gateway.startswith("192.168.") else 1)

if auto_candidates:
    labels = {f"{g.gateway}  (דרך {g.interface or g.src_ip})": g for g in auto_candidates}
    chosen_label = st.selectbox("ה-seed שזוהה אוטומטית (ה-Gateway של הרשת)",
                                list(labels.keys()))
    auto_gw = labels[chosen_label]
    st.caption(f"המערכת תתחיל לזחול מ-{auto_gw.gateway} ותגלה לבד את שאר ההתקנים "
               "דרך CDP/LLDP/OSPF. אם הוגדרו פרטי גישה במסך ההגדרות — ישמשו; "
               "אחרת ינוסו ברירות המחדל (כולל cisco/cisco).")
    if st.button("🔍 גלה טופולוגיה אוטומטית", type="primary", use_container_width=True):
        seed_ip = auto_gw.gateway
        # פרטי גישה: מהפרופיל אם קיים להתקן זה, אחרת ריק (ברירות מחדל)
        md = next((d for d in profile.managed_devices if d.ip == seed_ip), None)
        if md:
            seed_cred = Credential(username=md.username, password=md.password,
                                   enable_password=md.enable_password,
                                   protocol=Protocol(md.protocol))
        else:
            seed_cred = Credential(protocol=Protocol.SSH)
        start_crawl = True
else:
    st.info("לא זוהה Gateway אוטומטית. השתמש בהגדרה הידנית למטה.")

# ---------------------------------------------------------------------------
# הגדרה ידנית (מתקדם) — seed מותאם אישית
# ---------------------------------------------------------------------------
with st.expander("⚙️ הגדרה ידנית של seed ופרטי גישה (מתקדם)",
                 expanded=not auto_candidates):
    m_seed = st.text_input("כתובת IP של המתג/נתב ההתחלתי", key="seed_ip",
                           placeholder="192.168.1.1")
    c1, c2, c3 = st.columns(3)
    m_user = c1.text_input("שם משתמש (אופציונלי)", key="seed_user")
    m_pass = c2.text_input("סיסמה (אופציונלי)", type="password", key="seed_pass")
    m_enable = c3.text_input("Enable (אופציונלי)", type="password", key="seed_enable")
    st.caption("אותם פרטים ינוסו בכל קפיצה לשכן.")
    if st.button("🕸 התחל זחילה ידנית", key="manual_crawl"):
        if netutils.is_valid_ip(m_seed):
            seed_ip = m_seed
            seed_cred = Credential(username=m_user, password=m_pass,
                                   enable_password=m_enable, protocol=Protocol.SSH)
            start_crawl = True
        else:
            st.error("כתובת IP של ה-seed אינה תקינה.")

if start_crawl and seed_ip:
    progress_bar = st.progress(0.0, text="מתחיל...")
    log_box = st.container(height=260)
    logs: list[str] = []

    def on_progress(stage, fraction, log):
        if fraction > 0:
            progress_bar.progress(min(fraction, 1.0), text=stage)
        if log:
            logs.append(f"[{stage}] {log}")
            log_box.code("\n".join(logs[-150:]), language=None)

    with st.spinner("זוחל ברשת..."):
        result, needs_access = crawl(seed_ip, seed_cred, progress=on_progress,
                                     existing=result)
    progress_bar.progress(1.0, text="הסתיים")
    set_scan_result(result)
    try:
        from storage.repository import save_scan
        save_scan(result)
    except Exception:
        pass

    st.success(f"✔ נבנתה טופולוגיה: {len(result.devices)} התקנים, {len(result.links)} קשרים")
    if needs_access:
        st.warning("ההתקנים הבאים התגלו כשכנים אך לא ניתן היה להתחבר אליהם "
                   "(הזחילה לא המשיכה דרכם):")
        for item in needs_access:
            st.write(f"• `{item['ip']}` — {item['reason']}")

# ---------------------------------------------------------------------------
# הצגת המפה
# ---------------------------------------------------------------------------
result = get_scan_result()
if result and result.devices:
    st.divider()
    lcol, rcol = st.columns([4, 1])
    with rcol:
        st.markdown("**מקרא**")
        st.markdown("לכל התקן אייקון לפי סוגו (נתב / מתג / מחשב / שרת / מדפסת ועוד).")
        st.markdown("**טבעת הצבע = רמת סיכון:**")
        st.markdown("🔴 חולשה קריטית\n\n🟠 גבוהה\n\n🟡 בינונית\n\n🔵 תקין")
    with lcol:
        if result.links:
            html = build_html(result)
            components.html(html, height=620, scrolling=True)
        else:
            st.info("אין עדיין קשרים. הגדר seed והתחל זחילה כדי לבנות את הטופולוגיה.")

    # --- הרצת Assessment אוטומטית אחרי סריקה אוטומטית ---
    if st.session_state.pop("auto_assess_pending", False) and not result.vulnerabilities:
        from core.assessment.engine import assess
        from storage.repository import save_scan
        st.divider()
        st.info("🔍 מריץ בדיקת חולשות אוטומטית על ההתקנים...")
        with st.spinner("בודק חולשות (מתחבר להתקנים, כולל מרוחקים דרך pivot)..."):
            result = assess(result, managed_devices=profile.managed_devices,
                            try_default_creds=profile.try_default_creds)
            set_scan_result(result)
            try:
                save_scan(result)
            except Exception:
                pass
        st.rerun()   # רענון כדי לצבוע את המפה לפי הסיכון ולהציג את הכפתור
    elif result.vulnerabilities:
        st.success(f"ℹ️ קיימת בדיקת חולשות: {len(result.vulnerabilities)} חולשות, "
                   f"ציון רשת {result.risk_score}/100. המפה צבועה לפי רמת הסיכון.")
        if st.button("⚠️ לדוח החולשות"):
            st.switch_page("pages/p6_vulnerabilities.py")
else:
    st.info("עדיין אין נתונים. אפשר להתחיל מהסריקה (מסך 📡) או מזחילה מ-seed כאן.")
