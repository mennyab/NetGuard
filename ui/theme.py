"""עיצוב גלובלי: מראה נקי ובהיר + עימוד לעברית (RTL), עם טקסט טכני LTR."""

import streamlit as st

LIGHT_CSS = """
<style>
  :root {
    --ng-bg: #f7f9fc;
    --ng-panel: #ffffff;
    --ng-border: #e3e8f0;
    --ng-accent: #2f6df6;
    --ng-accent2: #00b3a4;
    --ng-text: #1a2233;
    --ng-dim: #5b6677;
  }

  .stApp {
    background:
      radial-gradient(900px 400px at 100% 0%, rgba(47,109,246,0.06), transparent 60%),
      radial-gradient(700px 350px at 0% 100%, rgba(0,179,164,0.05), transparent 55%),
      var(--ng-bg);
    color: var(--ng-text);
  }

  /* השפה עברית — יישור כללי לימין */
  .stApp, .main, .block-container { direction: rtl; }
  .stMarkdown, .stMarkdown p, .stMarkdown li, .stCaption,
  label, h1, h2, h3, h4, [data-testid="stMetric"], .stAlert {
    direction: rtl;
    text-align: right;
  }

  /* תוכן טכני (קוד, פקודות, IP, טבלאות נתונים, שדות קלט) — LTR */
  code, pre, .stCode, input, textarea,
  [data-testid="stDataFrame"], [data-testid="stTable"] {
    direction: ltr !important;
    text-align: left !important;
    unicode-bidi: plaintext;
  }

  /* כותרות — קו הדגשה נקי */
  h1 { color: var(--ng-text); font-weight: 700; letter-spacing: .2px; }
  h1::after {
    content: ""; display: block; width: 60px; height: 3px; margin: 8px 0 0 auto;
    background: linear-gradient(90deg, var(--ng-accent2), var(--ng-accent));
    border-radius: 2px;
  }
  h2, h3 { color: #2a3448; }

  /* כרטיסי מדדים — כרטיסים נקיים עם צל רך */
  [data-testid="stMetric"] {
    background: var(--ng-panel);
    border: 1px solid var(--ng-border);
    border-radius: 14px;
    padding: 14px 16px;
    box-shadow: 0 6px 18px rgba(26,34,51,0.06);
  }
  [data-testid="stMetricValue"] { color: var(--ng-accent); font-weight: 700; }

  /* כפתורים */
  .stButton > button {
    border: 1px solid var(--ng-border);
    border-radius: 10px;
    background: #fff;
    color: var(--ng-text);
    transition: all .15s ease;
  }
  .stButton > button:hover {
    border-color: var(--ng-accent);
    box-shadow: 0 4px 14px rgba(47,109,246,0.18);
    color: var(--ng-accent);
  }
  .stButton > button[kind="primary"] {
    background: linear-gradient(180deg, #3b82f6, var(--ng-accent));
    border-color: transparent; color: #fff; font-weight: 600;
  }

  /* פאנלים */
  [data-testid="stExpander"], .stAlert {
    border: 1px solid var(--ng-border) !important;
    border-radius: 12px !important;
    background: var(--ng-panel) !important;
  }
  section[data-testid="stSidebar"] {
    background: #ffffff; border-left: 1px solid var(--ng-border);
  }
  code, pre {
    background: #f1f5fb !important; border: 1px solid var(--ng-border);
    border-radius: 8px; color: #0b5bd3 !important;
  }
  hr { border-color: var(--ng-border); }
</style>
"""


def apply_theme() -> None:
    st.markdown(LIGHT_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "") -> None:
    st.title(title)
    if subtitle:
        st.caption(subtitle)


def under_construction(step: str) -> None:
    st.info(f"🚧 מסך זה ייבנה בשלב: {step}")
