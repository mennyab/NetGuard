"""מסך 8 — ביצוע ותוצאות (Execution & Rollback)."""

from __future__ import annotations

import streamlit as st

from core.assessment.engine import assess
from core.mitigation import execute_action, rollback_action
from core.models import Credential, Protocol
from ui.state import get_profile, get_scan_result, set_scan_result
from ui.theme import page_header

page_header("✅ ביצוע ותוצאות", "ביצוע הפעולות שאושרו, אימות ו-Rollback")

result = get_scan_result()
profile = get_profile()
approved_ids = st.session_state.get("approved_actions", [])
plan = st.session_state.get("plan", [])
actor = st.session_state.get("approver", "unknown")

if not approved_ids or not plan:
    st.info("לא אושרו פעולות. חזור למסך תוכנית התיקון.")
    if st.button("🛠 לתוכנית התיקון"):
        st.switch_page("pages/p7_mitigation.py")
    st.stop()


def _cred_for(ip: str) -> Credential | None:
    for d in profile.managed_devices:
        if d.ip == ip:
            return Credential(username=d.username, password=d.password,
                              enable_password=d.enable_password,
                              protocol=Protocol(d.protocol))
    return None


actions_to_run = [a for a in plan if a.id in approved_ids]
score_before = result.risk_score
vulns_before = len(result.vulnerabilities)

# ---------------------------------------------------------------------------
# ביצוע
# ---------------------------------------------------------------------------
if not st.session_state.get("_executed"):
    st.warning(f"מבצע {len(actions_to_run)} פעולות שאושרו על ידי {actor}.")
    if st.button("▶ בצע כעת", type="primary"):
        log_box = st.container(height=240)
        logs: list[str] = []

        def on_progress(aid, msg):
            logs.append(f"[{aid}] {msg}")
            log_box.code("\n".join(logs[-120:]), language=None)

        for a in actions_to_run:
            dev = result.devices.get(a.device_id)
            if not dev:
                continue
            with st.spinner(f"מבצע: {a.title}"):
                execute_action(a, dev, st.session_state.action_inputs.get(a.id, {}),
                               actor=actor, managed_cred=_cred_for(dev.ip),
                               progress=on_progress)
        st.session_state._executed = True
        st.rerun()

# ---------------------------------------------------------------------------
# תוצאות
# ---------------------------------------------------------------------------
if st.session_state.get("_executed"):
    st.subheader("תוצאות הביצוע")
    for a in actions_to_run:
        dev = result.devices.get(a.device_id)
        icon = {"done": "✔", "failed": "✖", "rolled_back": "↩",
                "manual": "✋", "pending": "…"}.get(a.status, "•")
        with st.container(border=True):
            st.markdown(f"{icon} **{a.title}** · `{dev.display_name if dev else a.device_id}` "
                        f"— סטטוס: `{a.status}`")
            if a.backup_path:
                st.caption(f"גיבוי: {a.backup_path}")
            if a.output:
                with st.expander("פלט"):
                    st.code(a.output, language=None)
            if a.status == "done" and a.undo_commands:
                if st.button(f"↩ Rollback", key=f"rb_{a.id}"):
                    with st.spinner("משחזר..."):
                        rollback_action(a, dev, actor=actor,
                                        managed_cred=_cred_for(dev.ip))
                    st.rerun()

    st.divider()
    st.subheader("סריקת אימות (לפני / אחרי)")
    st.caption("הרצה חוזרת של בדיקת החולשות כדי למדוד את השיפור.")
    if st.button("🔄 הרץ סריקת אימות"):
        with st.spinner("בודק מחדש..."):
            result = assess(result, managed_devices=profile.managed_devices,
                            try_default_creds=profile.try_default_creds)
        set_scan_result(result)
        c1, c2, c3 = st.columns(3)
        c1.metric("חולשות לפני", vulns_before)
        c2.metric("חולשות אחרי", len(result.vulnerabilities),
                  delta=len(result.vulnerabilities) - vulns_before)
        c3.metric("ציון רשת", f"{result.risk_score}/100",
                  delta=result.risk_score - score_before)

    if st.button("🏁 סיום — חזרה לדוחות"):
        for k in ("_executed", "approved_actions", "approve_word"):
            st.session_state.pop(k, None)
        st.switch_page("pages/p9_reports.py")
