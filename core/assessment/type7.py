"""פענוח Cisco Type 7 (אלגוריתם Vigenere, הפיך וידוע).

משמש אך ורק לניתוח חוזק הסיסמה. הסיסמה המפוענחת לא מוצגת בטקסט גלוי בדוח —
מדווחים רק את סוג ההצפנה ואת רמת החוזק.
"""

from __future__ import annotations

_XLAT = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
    0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
    0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
    0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
    0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37,
]


def decode_type7(encrypted: str) -> str | None:
    """מפענח מחרוזת Type 7. מחזיר None אם הפורמט לא תקין."""
    s = encrypted.strip()
    if len(s) < 2 or not s[:2].isdigit():
        return None
    try:
        seed = int(s[:2])
        out = []
        hex_part = s[2:]
        for i in range(0, len(hex_part), 2):
            byte = int(hex_part[i:i + 2], 16)
            key = _XLAT[(seed + i // 2) % len(_XLAT)]
            out.append(chr(byte ^ key))
        return "".join(out)
    except (ValueError, IndexError):
        return None
