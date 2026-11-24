"""מסך 7 — תוכנית תיקון (Mitigation Plan) ואישור בלעדי של המשתמש."""

from __future__ import annotations

import streamlit as st

from core.assessment.passwords import evaluate_password
from core.config_loader import settings
from core.mitigation import build_plan, suggest_strong_password, validate_action_inputs
from ui.state import get_scan_result
from ui.theme import page_header

page_header("🛠️ תוכנית תיקון",
            "המערכת מציעה — התיקון מתבצע אך ורק באישור מפורש שלך")

result = get_scan_result()
if not result or not result.vulnerabilities:
    st.info("אין חולשות לתיקון. הרץ קודם בדיקת חולשות.")
    if st.button("⚠️ לדוח החולשות"):
        st.switch_page("pages/p6_vulnerabilities.py")
    st.stop()

# בניית התוכנית (פעם אחת, נשמרת ב-session)
if st.button("🔧 בנה/רענן תוכנית תיקון") or "plan" not in st.session_state:
    st.session_state.plan = build_plan(result)
    st.session_state.selected_actions = set()
    st.session_state.action_inputs = {}

plan = st.session_state.plan
auto_actions = [a for a in plan if a.automatic]
manual_actions = [a for a in plan if not a.automatic]

st.caption(f"נמצאו {len(auto_actions)} פעולות אוטומטיות (מתגים/נתבים) "
           f"ו-{len(manual_actions)} המלצות ידניות (התקני קצה).")

# ---------------------------------------------------------------------------
# פעולות אוטומטיות — בחירה ידנית, ברירת מחדל לא מסומן
# ---------------------------------------------------------------------------
st.subheader("פעולות על מתגים ונתבים")
inputs_state = st.session_state.action_inputs

for a in auto_actions:
    dev = result.devices.get(a.device_id)
    dev_name = dev.display_name if dev else a.device_id
    with st.container(border=True):
        cols = st.columns([0.08, 0.92])
        checked = cols[0].checkbox("בחר", key=f"sel_{a.id}", label_visibility="collapsed")
        with cols[1]:
            st.markdown(f"**{a.title}**  ·  `{dev_name}`")
            if a.impact:
                st.caption(a.impact)

            # קלט סיסמה (החלטה 25: המשתמש מגדיר, המערכת מאמתת)
            if "new_password" in a.requires_input:
                pc1, pc2 = st.columns([3, 1])
                pw = pc1.text_input(f"סיסמה חדשה ל-{a.input_target}", type="password",
                                    key=f"pw_{a.id}")
                if pc2.button("🎲 הצע", key=f"gen_{a.id}"):
                    st.session_state[f"pw_plain_{a.id}"] = suggest_strong_password()
                    st.info(f"הצעה (העתק ושמור): `{st.session_state[f'pw_plain_{a.id}']}`")
                inputs_state[a.id] = {"new_password": pw}
                if pw:
                    verdict = evaluate_password(pw, is_admin="enable" in a.input_target)
                    if verdict.meets_policy:
                        st.success(f"✔ הסיסמה עומדת במדיניות (חוזק: {verdict.strength})")
                    else:
                        st.error("✖ לא עומדת במדיניות: " + "; ".join(verdict.issues))

            with st.expander("הצג פקודות"):
                preview = a.commands
                if a.id in inputs_state:
                    preview = [c.replace("{new_password}", "********") for c in a.commands]
                st.code("\n".join(preview), language=None)
                if a.undo_commands:
                    st.caption("פקודות ביטול (Rollback):")
                    st.code("\n".join(a.undo_commands), language=None)

        if checked:
            st.session_state.selected_actions.add(a.id)
        else:
            st.session_state.selected_actions.discard(a.id)

# ---------------------------------------------------------------------------
# המלצות ידניות
# ---------------------------------------------------------------------------
if manual_actions:
    with st.expander(f"ℹ️ {len(manual_actions)} המלצות ידניות (התקני קצה)"):
        for a in manual_actions:
            dev = result.devices.get(a.device_id)
            st.write(f"• `{dev.display_name if dev else a.device_id}` — {a.title}")

st.divider()

# ---------------------------------------------------------------------------
# אישור סופי בלעדי (הקלדת APPROVE)
# ---------------------------------------------------------------------------
selected = [a for a in auto_actions if a.id in st.session_state.selected_actions]
st.subheader(f"אישור וביצוע — {len(selected)} פעולות נבחרו")

if selected:
    # בדיקת תקינות קלט לכל הפעולות שנבחרו
    blocking = []
    for a in selected:
        errs = validate_action_inputs(a, inputs_state.get(a.id, {}))
        if errs:
            blocking.append((a, errs))

    st.checkbox("☑ גבה קונפיגורציה לפני כל שינוי (חובה)", value=True, disabled=True)

    if blocking:
        st.error("יש פעולות עם סיסמה שאינה עומדת במדיניות. תקן לפני ביצוע:")
        for a, errs in blocking:
            st.write(f"• {a.title}: " + "; ".join(errs))
    else:
        word = settings()["mitigation"]["approval_word"]
        typed = st.text_input(f'להפעלה, הקלד/י את המילה "{word}"', key="approve_word")
        actor = st.text_input("שם המאשר (לרישום ביומן הביקורת)", key="approver_name")
        c1, c2 = st.columns(2)
        if c1.button("✅ אשר ובצע", type="primary",
                     disabled=(typed != word or not actor)):
            st.session_state.approved_actions = [a.id for a in selected]
            st.session_state.approver = actor
            st.switch_page("pages/p8_execution.py")
        c2.caption("אין ביצוע אוטומטי. כל פעולה מבוצעת רק לאחר אישור מפורש זה.")
else:
    st.info("סמן פעולות לביצוע כדי להמשיך.")
