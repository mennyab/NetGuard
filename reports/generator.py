"""מחולל דוחות — דוח מנהלים ודוח טכני מלא (HTML, וייצוא ל-PDF)."""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from io import BytesIO
from pathlib import Path

from core.config_loader import project_path
from core.models import ScanResult, Severity

# גופנים תומכי-עברית במערכת. הגופן שנמצא מועתק לתוך הפרויקט כדי ש-xhtml2pdf
# יוכל לקרוא אותו (הוא קורא רק מתוך תיקיית הפרויקט).
_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\tahoma.ttf",
    r"C:\Windows\Fonts\ARIALUNI.TTF",
]


def _ensure_local_font() -> Path | None:
    """מעתיק גופן עברי לתוך הפרויקט (פעם אחת) ומחזיר את הנתיב המקומי."""
    local = project_path("storage/fonts/hebrew.ttf")
    if local.exists():
        return local
    for src in _FONT_CANDIDATES:
        if Path(src).exists():
            try:
                shutil.copy(src, local)
                return local
            except Exception:
                continue
    return None


def _hebrew_font_face() -> str:
    local = _ensure_local_font()
    if local:
        return (f"@font-face {{ font-family: 'HebrewFont'; "
                f"src: url('{local.as_uri()}'); }}")
    return ""


def _get_bidi_display():
    """מחזיר את פונקציית get_display, תומך בשתי גרסאות python-bidi."""
    try:
        from bidi import get_display            # python-bidi >= 0.5
        return get_display
    except Exception:
        try:
            from bidi.algorithm import get_display   # גרסאות ישנות
            return get_display
        except Exception:
            return None


def _apply_bidi(html: str) -> str:
    """מחיל את אלגוריתם ה-bidi על טקסט בין תגיות (ל-PDF בלבד, שאינו תומך RTL)."""
    get_display = _get_bidi_display()
    if get_display is None:
        return html

    def repl(m: re.Match) -> str:
        text = m.group(1)
        if any("\u0590" <= c <= "\u05ff" for c in text):   # יש עברית
            return ">" + get_display(text) + "<"
        return m.group(0)

    return re.sub(r">([^<>]+)<", repl, html)

SEV_HE = {"critical": "קריטי", "high": "גבוה", "medium": "בינוני",
          "low": "נמוך", "info": "מידע"}
SEV_COLOR = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f",
             "low": "#2ecc71", "info": "#95a5a6"}

_BASE_CSS = """
<style>
  __FONT_FACE__
  body { font-family: 'HebrewFont', Arial, sans-serif; direction: rtl; color: #222; }
  * { font-family: 'HebrewFont', Arial, sans-serif; }
  h1 { color: #1a5276; } h2 { color: #1a5276; border-bottom: 2px solid #ddd; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th, td { border: 1px solid #ccc; padding: 6px; text-align: right; font-size: 12px; }
  th { background: #1a5276; color: #fff; }
  .score { font-size: 42px; font-weight: bold; }
  .badge { color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
  .meta { color: #666; font-size: 12px; }
</style>
"""


def _base_css() -> str:
    return _BASE_CSS.replace("__FONT_FACE__", _hebrew_font_face())


def _sev_counts(result: ScanResult) -> dict[str, int]:
    return {s.value: sum(1 for v in result.vulnerabilities if v.severity == s)
            for s in Severity}


def _badge(sev: str) -> str:
    return f'<span class="badge" style="background:{SEV_COLOR[sev]}">{SEV_HE[sev]}</span>'


def _score_bars(result: ScanResult) -> str:
    """פסי ציון אופקיים לכל התקן (היסטוגרמה שעובדת ב-PDF)."""
    from core.models import score_color as _score_color
    rows = []
    for dev in sorted(result.devices.values(), key=lambda d: result.device_score(d.id)):
        s = result.device_score(dev.id)
        width_pt = max(4, round(s * 1.7))     # רוחב הפס ביחס לציון (0-170pt)
        color = _score_color(s)
        bar = (f'<div style="background-color:{color};width:{width_pt}pt;'
               f'height:12px;"></div>')
        rows.append(
            f'<tr><td style="width:110px">{dev.display_name}</td>'
            f'<td>{bar}</td>'
            f'<td style="width:45px;color:{color};font-weight:bold">{s}</td></tr>')
    return "".join(rows)


def executive_html(result: ScanResult) -> str:
    from core.models import score_color as _score_color

    counts = _sev_counts(result)
    score = result.risk_score
    sc_color = _score_color(score)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    sev_rows = "".join(
        f'<tr><td>{_badge(s)}</td><td>{counts[s]}</td></tr>'
        for s in ["critical", "high", "medium", "low"])

    # טבלת התקנים עם ציון בטיחות לכל אחד (תוכן מהסריקה)
    dev_rows = []
    for dev in sorted(result.devices.values(), key=lambda d: result.device_score(d.id)):
        ds = result.device_score(dev.id)
        nv = sum(1 for v in result.vulnerabilities if v.device_id == dev.id)
        dev_rows.append(
            f"<tr><td>{dev.display_name}</td><td>{dev.ip}</td>"
            f"<td>{dev.model or dev.vendor or '—'}</td><td>{nv}</td>"
            f'<td style="color:{_score_color(ds)};font-weight:bold">{ds}</td></tr>')

    # חולשות חמורות מובילות (עד 10)
    top = sorted(result.vulnerabilities, key=lambda v: sev_rank[v.severity.value])[:10]
    top_rows = []
    for v in top:
        dev = result.devices.get(v.device_id)
        top_rows.append(
            f"<tr><td>{_badge(v.severity.value)}</td>"
            f"<td>{dev.display_name if dev else v.device_id}</td><td>{v.title}</td></tr>")

    return f"""{_base_css()}
    <h1>NetGuard — דוח מנהלים</h1>
    <p class="meta">נוצר: {datetime.now():%Y-%m-%d %H:%M} · תת-רשתות: {', '.join(result.subnets) or '—'}</p>

    <h2>ציון אבטחת הרשת</h2>
    <p class="score" style="color:{sc_color}">{score}<span style="font-size:18px">/100</span></p>
    <p>סה"כ התקנים: <b>{len(result.devices)}</b> · סה"כ חולשות: <b>{len(result.vulnerabilities)}</b>
       · קשרים בטופולוגיה: <b>{len(result.links)}</b></p>

    <h2>סיכום חולשות לפי חומרה</h2>
    <table><tr><th>חומרה</th><th>כמות</th></tr>{sev_rows}</table>

    <h2>ציון בטיחות לפי התקן</h2>
    <table><tr><th>התקן</th><th>IP</th><th>דגם</th><th>חולשות</th><th>ציון</th></tr>
    {''.join(dev_rows)}</table>

    <h2>היסטוגרמת ציונים</h2>
    <table>{_score_bars(result)}</table>

    <h2>חולשות מובילות לטיפול</h2>
    <table><tr><th>חומרה</th><th>התקן</th><th>חולשה</th></tr>
    {''.join(top_rows) or '<tr><td colspan=3>לא נמצאו חולשות</td></tr>'}</table>
    """


def technical_html(result: ScanResult) -> str:
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    parts = [_base_css(), "<h1>NetGuard — דוח טכני מלא</h1>",
             f'<p class="meta">נוצר: {datetime.now():%Y-%m-%d %H:%M}</p>']

    # טבלת התקנים
    parts.append("<h2>התקנים</h2><table><tr><th>סוג</th><th>IP</th><th>Hostname</th>"
                 "<th>יצרן</th><th>פורטים</th><th>חולשות</th></tr>")
    for dev in result.devices.values():
        nv = sum(1 for v in result.vulnerabilities if v.device_id == dev.id)
        parts.append(f"<tr><td>{dev.device_type.value}</td><td>{dev.ip}</td>"
                     f"<td>{dev.hostname or '—'}</td><td>{dev.vendor or '—'}</td>"
                     f"<td>{len(dev.open_ports)}</td><td>{nv}</td></tr>")
    parts.append("</table>")

    # חולשות מפורטות
    parts.append("<h2>חולשות</h2><table><tr><th>חומרה</th><th>התקן</th><th>חולשה</th>"
                 "<th>קטגוריה</th><th>ראיה</th></tr>")
    for v in sorted(result.vulnerabilities, key=lambda x: sev_rank[x.severity.value]):
        dev = result.devices.get(v.device_id)
        name = dev.display_name if dev else v.device_id
        parts.append(f"<tr><td>{_badge(v.severity.value)}</td><td>{name}</td>"
                     f"<td>{v.title}</td><td>{v.category.value}</td>"
                     f"<td><code>{v.evidence}</code></td></tr>")
    parts.append("</table>")
    return "".join(parts)


def html_to_pdf(html: str) -> bytes:
    """ממיר HTML ל-PDF (xhtml2pdf). xhtml2pdf מטפל ב-RTL בסדר לוגי — בלי bidi ידני."""
    from xhtml2pdf import pisa
    buf = BytesIO()
    pisa.CreatePDF(src=html, dest=buf, encoding="utf-8")
    return buf.getvalue()
