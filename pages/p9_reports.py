"""מסך 9 — דוחות והיסטוריה (Reports & History)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from reports.generator import (
    executive_html,
    html_to_pdf,
    technical_html,
)
from storage.repository import list_scans, load_scan, read_audit_log, save_scan
from ui.state import get_scan_result, set_scan_result
from ui.theme import page_header

page_header("📄 דוחות והיסטוריה", "דוחות, השוואה בין סריקות ויומן ביקורת")

result = get_scan_result()

tab_current, tab_history, tab_audit = st.tabs(["דוח נוכחי", "היסטוריה והשוואה", "יומן ביקורת"])

# ---------------------------------------------------------------------------
# דוח נוכחי
# ---------------------------------------------------------------------------
with tab_current:
    if not result or not result.devices:
        st.info("אין סריקה פעילה. הרץ סריקה או טען מההיסטוריה.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("התקנים", len(result.devices))
        c2.metric("חולשות", len(result.vulnerabilities))
        c3.metric("ציון רשת", f"{result.risk_score}/100")

        if st.button("💾 שמור סריקה זו להיסטוריה"):
            sid = save_scan(result)
            st.success(f"נשמר כסריקה #{sid}")

        st.divider()
        st.markdown("**הורדת דוחות**")
        d1, d2 = st.columns(2)
        exec_html = executive_html(result)
        tech_html = technical_html(result)
        with d1:
            st.download_button("📄 דוח מנהלים (PDF)", html_to_pdf(exec_html),
                               file_name="netguard_executive.pdf", mime="application/pdf")
            st.download_button("📄 דוח מנהלים (HTML)", exec_html,
                               file_name="netguard_executive.html", mime="text/html")
        with d2:
            st.download_button("📄 דוח טכני מלא (PDF)", html_to_pdf(tech_html),
                               file_name="netguard_technical.pdf", mime="application/pdf")
            st.download_button("📄 דוח טכני מלא (HTML)", tech_html,
                               file_name="netguard_technical.html", mime="text/html")

# ---------------------------------------------------------------------------
# היסטוריה והשוואה
# ---------------------------------------------------------------------------
with tab_history:
    scans = list_scans()
    if not scans:
        st.info("אין סריקות שמורות עדיין. שמור סריקה מהטאב 'דוח נוכחי'.")
    else:
        df = pd.DataFrame(scans)
        df = df.rename(columns={"id": "מס'", "started_at": "התחלה",
                                "device_count": "התקנים", "vuln_count": "חולשות",
                                "risk_score": "ציון"})
        st.dataframe(df[["מס'", "התחלה", "התקנים", "חולשות", "ציון"]],
                     use_container_width=True, hide_index=True)

        ids = [s["id"] for s in scans]
        lc, rc = st.columns(2)
        load_id = lc.selectbox("טען סריקה למסכים", ids)
        if lc.button("📂 טען סריקה זו"):
            set_scan_result(load_scan(load_id))
            st.success(f"סריקה #{load_id} נטענה. עבור למסכים לצפייה.")

        if len(ids) >= 2:
            st.markdown("**⚖ השוואה בין שתי סריקות**")
            cc1, cc2 = st.columns(2)
            a = cc1.selectbox("סריקה א'", ids, index=1, key="cmp_a")
            b = cc2.selectbox("סריקה ב'", ids, index=0, key="cmp_b")
            if st.button("השווה"):
                ra, rb = load_scan(a), load_scan(b)
                m1, m2, m3 = st.columns(3)
                m1.metric(f"חולשות #{a}", len(ra.vulnerabilities))
                m2.metric(f"חולשות #{b}", len(rb.vulnerabilities),
                          delta=len(rb.vulnerabilities) - len(ra.vulnerabilities))
                m3.metric("שינוי בציון", f"{rb.risk_score}",
                          delta=rb.risk_score - ra.risk_score)

                titles_a = {(v.device_id, v.title) for v in ra.vulnerabilities}
                titles_b = {(v.device_id, v.title) for v in rb.vulnerabilities}
                fixed = titles_a - titles_b
                new = titles_b - titles_a
                st.write(f"✅ **תוקנו {len(fixed)} חולשות**")
                for did, t in list(fixed)[:30]:
                    st.caption(f"• {t}")
                if new:
                    st.write(f"🆕 **{len(new)} חולשות חדשות**")
                    for did, t in list(new)[:30]:
                        st.caption(f"• {t}")

# ---------------------------------------------------------------------------
# יומן ביקורת
# ---------------------------------------------------------------------------
with tab_audit:
    st.markdown("**יומן ביקורת — כל פעולות השינוי שבוצעו**")
    logs = read_audit_log()
    if logs:
        st.dataframe(pd.DataFrame(logs), use_container_width=True, hide_index=True)
    else:
        st.caption("אין רשומות ביומן הביקורת עדיין.")
