"""NetGuard - נקודת הכניסה.

הרצה:
    streamlit run app.py
(מומלץ להריץ את הטרמינל כמנהל - נדרש עבור סריקת ARP ו-nmap)
"""

import sys

import streamlit as st

# בדיקה שהקובץ רץ דרך "streamlit run" ולא "python app.py"
try:
    from streamlit.runtime.scriptrunner import get_script_run_ctx
    if get_script_run_ctx() is None:
        print("\n" + "=" * 62)
        print("  ⚠  יש להריץ את המערכת כך:   streamlit run app.py")
        print("     ולא:                     python app.py")
        print("=" * 62 + "\n")
        sys.exit(1)
except ImportError:
    pass

from storage.db import init_db
from ui.theme import apply_theme

st.set_page_config(page_title="NetGuard", page_icon="🛡️", layout="wide")
apply_theme()
init_db()

PAGES = [
    st.Page("pages/p1_setup.py",           title="הגדרות וגישה",      icon="⚙️", default=True),
    st.Page("pages/p2_scan.py",            title="סריקה",             icon="📡"),
    st.Page("pages/p3_topology.py",        title="מפת טופולוגיה",      icon="🗺️"),
    st.Page("pages/p4_devices.py",         title="רשימת התקנים",      icon="📋"),
    st.Page("pages/p5_device_details.py",  title="פרטי התקן",         icon="🔎"),
    st.Page("pages/p6_vulnerabilities.py", title="דוח חולשות",        icon="⚠️"),
    st.Page("pages/p7_mitigation.py",      title="תוכנית תיקון",      icon="🛠️"),
    st.Page("pages/p8_execution.py",       title="ביצוע ותוצאות",     icon="✅"),
    st.Page("pages/p9_reports.py",         title="דוחות והיסטוריה",   icon="📄"),
]

st.sidebar.markdown("## 🛡️ NetGuard")
st.navigation(PAGES).run()
