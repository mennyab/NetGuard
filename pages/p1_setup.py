"""מסך 1 — הגדרות וגישה לציוד."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from core import netutils
from core.config_loader import settings
from core.models import Credential, Protocol
from core.profile_store import (
    ManagedDevice,
    ScanProfile,
    list_profiles,
    load_profile,
    save_profile,
)
from core.session_manager import open_session
from ui.state import get_profile, set_profile
from ui.theme import page_header

page_header("⚙️ הגדרות וגישה לציוד",
            "הגדרת תת-הרשתות, פרטי הגישה למתגים ולנתבים ואפשרויות הבטיחות")

profile: ScanProfile = get_profile()

# ---------------------------------------------------------------------------
# סריקה אוטומטית בלחיצה אחת
# ---------------------------------------------------------------------------
st.subheader("🚀 סריקה אוטומטית")
_gateways = netutils.default_gateways()
_auto_gw = next((g for g in _gateways if g.gateway.startswith("192.168.")),
                next((g for g in _gateways if g.gateway.startswith(("10.", "172."))), None))
_ifaces = netutils.list_local_interfaces()
_auto_subnet = ""
if _auto_gw:
    _match = next((i for i in _ifaces if i.ip == _auto_gw.src_ip), None)
    if _match:
        _auto_subnet = _match.cidr

if _auto_subnet:
    st.info(f"זוהתה רשת פעילה: **{_auto_subnet}** (כרטיס {_auto_gw.interface or _auto_gw.src_ip}), "
            f"Gateway: **{_auto_gw.gateway}**. "
            "הסריקה האוטומטית תגלה את ההתקנים ותבנה את הטופולוגיה לבד.")
    auto_ok = st.checkbox("☑ אני מאשר/ת שיש לי הרשאה חוקית לסרוק רשת זו", key="auto_auth")
    if st.button("🚀 התחל סריקה אוטומטית מלאה", type="primary", disabled=not auto_ok,
                 use_container_width=True):
        if _auto_subnet not in profile.subnets:
            profile.subnets.append(_auto_subnet)
        profile.authorized = True
        set_profile(profile)
        st.session_state.auto_seed_ip = _auto_gw.gateway
        st.session_state.auto_run_scan = True          # ה-scan ירוץ לבד
        st.switch_page("pages/p2_scan.py")
    st.caption("הסריקה כוללת: גילוי התקנים (ARP+nmap) ואחריו בניית טופולוגיה מה-Gateway. "
               "לאחר מכן אפשר להריץ בדיקת חולשות. תיקון תמיד דורש את אישורך.")
else:
    st.caption("לא זוהתה רשת אוטומטית. השתמש בהגדרה הידנית למטה.")

st.divider()

# ---------------------------------------------------------------------------
# כרטיסי רשת מקומיים
# ---------------------------------------------------------------------------
st.subheader("🖧 כרטיס רשת (הגדרה ידנית)")
interfaces = netutils.list_local_interfaces()
if interfaces:
    options = {f"{i.name} — {i.ip} ({i.cidr})": i for i in interfaces}
    chosen_label = st.selectbox("כרטיס הרשת שממנו נסרוק", list(options.keys()))
    chosen_iface = options[chosen_label]
    if st.button("➕ הוסף את תת-הרשת של כרטיס זה"):
        if chosen_iface.cidr not in profile.subnets:
            profile.subnets.append(chosen_iface.cidr)
else:
    st.warning("לא זוהו כרטיסי רשת פעילים.")

# ---------------------------------------------------------------------------
# תת-רשתות לסריקה
# ---------------------------------------------------------------------------
st.subheader("🌐 תת-רשתות לסריקה")
col1, col2 = st.columns([3, 1])
with col1:
    new_subnet = st.text_input("הוסף תת-רשת (CIDR, למשל 192.168.1.0/24)",
                               key="new_subnet", label_visibility="collapsed",
                               placeholder="192.168.1.0/24")
with col2:
    if st.button("➕ הוסף תת-רשת", use_container_width=True):
        if netutils.is_valid_cidr(new_subnet):
            if new_subnet not in profile.subnets:
                profile.subnets.append(new_subnet)
        else:
            st.error("CIDR לא תקין.")

if profile.subnets:
    for sn in list(profile.subnets):
        c1, c2 = st.columns([5, 1])
        c1.code(sn, language=None)
        if c2.button("🗑 הסר", key=f"del_sn_{sn}"):
            profile.subnets.remove(sn)
            st.rerun()
else:
    st.info("עדיין לא הוגדרו תת-רשתות.")

st.divider()

# ---------------------------------------------------------------------------
# התקני רשת מנוהלים (מתגים ונתבים)
# ---------------------------------------------------------------------------
st.subheader("🔀 התקני רשת מנוהלים (מתגים ונתבים)")
st.caption("מחשבי קצה אינם נדרשים כאן — הם ייסרקו אוטומטית מבחוץ. "
           "כאן מזינים רק מתגים ונתבים שרוצים להתחבר אליהם.")

device_rows = [
    {"IP": d.ip, "פרוטוקול": d.protocol, "משתמש": d.username,
     "סיסמה": d.password, "Enable": d.enable_password}
    for d in profile.managed_devices
]
if not device_rows:
    device_rows = [{"IP": "", "פרוטוקול": "ssh", "משתמש": "",
                    "סיסמה": "", "Enable": ""}]

edited = st.data_editor(
    pd.DataFrame(device_rows),
    num_rows="dynamic",
    use_container_width=True,
    column_config={
        "IP": st.column_config.TextColumn("IP", required=True),
        "פרוטוקול": st.column_config.SelectboxColumn("פרוטוקול", options=["ssh", "telnet"]),
        "סיסמה": st.column_config.TextColumn("סיסמה"),
        "Enable": st.column_config.TextColumn("Enable"),
    },
    key="device_editor",
)

# עדכון הפרופיל מהטבלה
managed: list[ManagedDevice] = []
for _, row in edited.iterrows():
    ip = str(row.get("IP", "")).strip()
    if ip and netutils.is_valid_ip(ip):
        managed.append(ManagedDevice(
            ip=ip,
            protocol=str(row.get("פרוטוקול", "ssh") or "ssh"),
            username=str(row.get("משתמש", "") or ""),
            password=str(row.get("סיסמה", "") or ""),
            enable_password=str(row.get("Enable", "") or ""),
        ))
profile.managed_devices = managed

# --- בדיקת חיבור (קריאה בלבד: show users) ---
if st.button("🔌 בדוק חיבור לכל ההתקנים (לא מנתק סשנים קיימים)"):
    if not managed:
        st.warning("לא הוגדרו התקנים לבדיקה.")
    for d in managed:
        with st.status(f"בודק {d.ip} ...", expanded=True) as status:
            cred = Credential(
                username=d.username, password=d.password,
                enable_password=d.enable_password,
                protocol=Protocol(d.protocol),
            )
            outcome = open_session(d.ip, user_cred=cred)
            if outcome.session:
                sess = outcome.session
                active = sess.active_sessions_before
                active_txt = f"{active} סשנים פעילים" if active >= 0 else "מספר סשנים לא ידוע"
                msg = f"✔ מחובר ({sess.protocol.value.upper()}, {active_txt})"
                for w in sess.warnings:
                    msg += f"\n⚠ {w}"
                sess.close()
                status.update(label=f"{d.ip}: {msg}", state="complete")
                st.success(msg)
            elif outcome.needs_user_credentials:
                status.update(label=f"{d.ip}: כל הניסיונות נכשלו", state="error")
                st.error("לא הצלחתי להתחבר עם הפרטים שהוזנו ולא עם סיסמאות ברירת המחדל. "
                         "בדוק את פרטי הגישה.")
            else:
                status.update(label=f"{d.ip}: לא התחבר", state="error")
                st.warning(outcome.skipped_reason or "החיבור נכשל.")

st.divider()

# ---------------------------------------------------------------------------
# אפשרויות בטיחות
# ---------------------------------------------------------------------------
st.subheader("🛡 אפשרויות בטיחות")
cfg = settings()
colA, colB = st.columns(2)
with colA:
    profile.max_login_attempts = st.number_input(
        "מקסימום ניסיונות סיסמה להתקן", min_value=1, max_value=10,
        value=profile.max_login_attempts or cfg["login_attempts"]["max_per_device"])
    profile.snmp_version = st.selectbox("גרסת SNMP", ["v1", "v2c", "v3"],
                                        index=["v1", "v2c", "v3"].index(profile.snmp_version))
with colB:
    profile.snmp_community = st.text_input("SNMP Community", value=profile.snmp_community,
                                           type="password")
    profile.try_default_creds = st.checkbox(
        "נסה סיסמאות ברירת מחדל כשההתחברות נכשלת (דורש אישור מפורש)",
        value=profile.try_default_creds)

profile.authorized = st.checkbox(
    "☑ אני מאשר/ת שיש לי הרשאה חוקית לסרוק את הרשתות וההתקנים שהוגדרו",
    value=profile.authorized)

st.divider()

# ---------------------------------------------------------------------------
# פרופילים (שמירה/טעינה מוצפנת) + מעבר לסריקה
# ---------------------------------------------------------------------------
st.subheader("💾 פרופילים")
pcol1, pcol2, pcol3 = st.columns(3)

with pcol1:
    st.markdown("**שמירה מוצפנת**")
    profile.name = st.text_input("שם הפרופיל", value=profile.name)
    master_save = st.text_input("סיסמת מאסטר (להצפנת הפרופיל)", type="password",
                                key="master_save")
    if st.button("💾 שמור פרופיל"):
        if not master_save:
            st.error("יש להזין סיסמת מאסטר כדי להצפין את פרטי הגישה.")
        else:
            path = save_profile(profile, master_save)
            st.success(f"הפרופיל נשמר מוצפן: {path}")

with pcol2:
    st.markdown("**טעינה**")
    existing = list_profiles()
    if existing:
        to_load = st.selectbox("בחר פרופיל", existing)
        master_load = st.text_input("סיסמת מאסטר", type="password", key="master_load")
        if st.button("📂 טען פרופיל"):
            try:
                loaded = load_profile(to_load, master_load)
                set_profile(loaded)
                st.success("הפרופיל נטען.")
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    else:
        st.caption("אין פרופילים שמורים עדיין.")

with pcol3:
    st.markdown("**התחל סריקה**")
    ready = bool(profile.subnets) and profile.authorized
    if not profile.subnets:
        st.caption("❌ חסרות תת-רשתות")
    if not profile.authorized:
        st.caption("❌ חסר אישור הרשאה")
    set_profile(profile)
    if st.button("▶ המשך למסך הסריקה", type="primary", disabled=not ready,
                 use_container_width=True):
        st.switch_page("pages/p2_scan.py")
