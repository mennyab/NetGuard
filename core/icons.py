"""אייקוני SVG להתקני רשת (data URI) — לשימוש במפת הטופולוגיה (pyvis)."""

from __future__ import annotations

import base64

from core.models import DeviceType

# כל אייקון: SVG 64x64, גליף כהה על רקע לבן מעוגל. סגנון אחיד ונקי.
_W = "#1a2233"   # קו כהה
_A = "#2f6df6"   # כחול
_G = "#00b3a4"   # טורקיז

_SVGS: dict[DeviceType, str] = {
    DeviceType.ROUTER: f"""
      <circle cx='32' cy='32' r='30' fill='#eaf1ff' stroke='{_A}' stroke-width='2'/>
      <rect x='16' y='34' width='32' height='14' rx='3' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <circle cx='22' cy='41' r='1.8' fill='{_A}'/><circle cx='28' cy='41' r='1.8' fill='{_G}'/>
      <circle cx='34' cy='41' r='1.8' fill='{_A}'/>
      <path d='M24 30 l0 -10 l-4 0 l6 -7 l6 7 l-4 0 l0 10' fill='{_A}'/>
      <path d='M40 14 l0 10 l4 0 l-6 7 l-6 -7 l4 0 l0 -10' fill='{_G}'/>
    """,
    DeviceType.SWITCH: f"""
      <circle cx='32' cy='32' r='30' fill='#e9fbf8' stroke='{_G}' stroke-width='2'/>
      <rect x='13' y='26' width='38' height='16' rx='3' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='18' y='37' width='4' height='3' fill='{_G}'/><rect x='25' y='37' width='4' height='3' fill='{_G}'/>
      <rect x='32' y='37' width='4' height='3' fill='{_G}'/><rect x='39' y='37' width='4' height='3' fill='{_G}'/>
      <path d='M20 32 h18 m-4 -3 l4 3 l-4 3' stroke='{_A}' stroke-width='2' fill='none'/>
    """,
    DeviceType.PC: f"""
      <circle cx='32' cy='32' r='30' fill='#eef1f6' stroke='{_A}' stroke-width='2'/>
      <rect x='16' y='18' width='32' height='22' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='20' y='22' width='24' height='14' fill='#dce9ff'/>
      <rect x='26' y='42' width='12' height='3' fill='{_W}'/>
      <rect x='22' y='45' width='20' height='3' rx='1' fill='{_W}'/>
    """,
    DeviceType.SERVER: f"""
      <circle cx='32' cy='32' r='30' fill='#eef1f6' stroke='{_A}' stroke-width='2'/>
      <rect x='20' y='16' width='24' height='13' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='20' y='32' width='24' height='13' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <circle cx='25' cy='22' r='1.8' fill='{_G}'/><circle cx='25' cy='38' r='1.8' fill='{_G}'/>
      <rect x='30' y='21' width='10' height='2' fill='{_W}'/><rect x='30' y='37' width='10' height='2' fill='{_W}'/>
    """,
    DeviceType.PRINTER: f"""
      <circle cx='32' cy='32' r='30' fill='#f0eefb' stroke='{_A}' stroke-width='2'/>
      <rect x='20' y='16' width='24' height='12' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='15' y='28' width='34' height='16' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='22' y='38' width='20' height='10' fill='#dce9ff' stroke='{_W}' stroke-width='1.5'/>
      <circle cx='44' cy='34' r='2' fill='{_G}'/>
    """,
    DeviceType.CAMERA: f"""
      <circle cx='32' cy='32' r='30' fill='#f0eefb' stroke='{_A}' stroke-width='2'/>
      <rect x='16' y='24' width='22' height='16' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <circle cx='27' cy='32' r='5' fill='#dce9ff' stroke='{_W}' stroke-width='1.5'/>
      <path d='M38 28 l8 -4 l0 16 l-8 -4 z' fill='{_A}'/>
    """,
    DeviceType.FIREWALL: f"""
      <circle cx='32' cy='32' r='30' fill='#fdeceb' stroke='#e74c3c' stroke-width='2'/>
      <rect x='17' y='20' width='30' height='24' rx='2' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <path d='M17 28 h30 M17 36 h30 M27 20 v8 M37 28 v8 M27 36 v8' stroke='#e74c3c' stroke-width='2'/>
    """,
    DeviceType.ACCESS_POINT: f"""
      <circle cx='32' cy='32' r='30' fill='#e9fbf8' stroke='{_G}' stroke-width='2'/>
      <path d='M22 34 a14 14 0 0 1 20 0' fill='none' stroke='{_A}' stroke-width='2.5'/>
      <path d='M26 38 a8 8 0 0 1 12 0' fill='none' stroke='{_G}' stroke-width='2.5'/>
      <circle cx='32' cy='42' r='3' fill='{_A}'/>
    """,
    DeviceType.PHONE: f"""
      <circle cx='32' cy='32' r='30' fill='#eef1f6' stroke='{_A}' stroke-width='2'/>
      <rect x='24' y='16' width='16' height='32' rx='3' fill='#fff' stroke='{_W}' stroke-width='2'/>
      <rect x='27' y='20' width='10' height='18' fill='#dce9ff'/>
      <circle cx='32' cy='43' r='1.8' fill='{_W}'/>
    """,
    DeviceType.UNKNOWN: f"""
      <circle cx='32' cy='32' r='30' fill='#eef1f6' stroke='#8b949e' stroke-width='2'/>
      <text x='32' y='44' font-size='34' text-anchor='middle' fill='#8b949e'
            font-family='Arial' font-weight='bold'>?</text>
    """,
}
# אליאסים
_SVGS[DeviceType.L3_SWITCH] = _SVGS[DeviceType.SWITCH]
_SVGS[DeviceType.IOT] = _SVGS[DeviceType.UNKNOWN]


def device_icon_uri(device_type: DeviceType) -> str:
    """מחזיר data URI של אייקון ה-SVG להתקן."""
    body = _SVGS.get(device_type, _SVGS[DeviceType.UNKNOWN])
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64' "
           f"width='64' height='64'>{body}</svg>")
    b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"
