"""סיווג סוג ההתקן לפי שילוב רמזים (החלטה 16).

כל רמז מוסיף נקודות לסוגי התקנים אפשריים, והסוג עם הניקוד הגבוה מנצח.
הרמזים: SNMP sysServices, sysDescr, יצרן לפי MAC, פורטים פתוחים,
והאם ההתקן נגיש כציוד רשת מנוהל (SSH/Telnet + CLI של נתב/מתג).
"""

from __future__ import annotations

from collections import defaultdict

from core.models import Device, DeviceType

# פורט -> סוגי התקן שהוא מרמז עליהם (נקודות)
PORT_HINTS: dict[int, list[tuple[DeviceType, int]]] = {
    23:   [(DeviceType.SWITCH, 2), (DeviceType.ROUTER, 2)],   # telnet — נפוץ בציוד רשת
    80:   [(DeviceType.UNKNOWN, 0)],
    161:  [(DeviceType.SWITCH, 2), (DeviceType.ROUTER, 2)],   # SNMP
    443:  [(DeviceType.UNKNOWN, 0)],
    515:  [(DeviceType.PRINTER, 5)],                          # LPD
    631:  [(DeviceType.PRINTER, 5)],                          # IPP
    9100: [(DeviceType.PRINTER, 6)],                          # JetDirect
    554:  [(DeviceType.CAMERA, 5)],                           # RTSP
    3389: [(DeviceType.SERVER, 3), (DeviceType.PC, 2)],       # RDP
    445:  [(DeviceType.PC, 2), (DeviceType.SERVER, 2)],       # SMB
    139:  [(DeviceType.PC, 2), (DeviceType.SERVER, 2)],
    22:   [(DeviceType.SERVER, 1)],                           # SSH לבדו חלש כרמז
    5060: [(DeviceType.PHONE, 4)],                            # SIP
}

# מילות מפתח ב-sysDescr / שם שירות -> סוג
KEYWORD_HINTS: list[tuple[str, DeviceType, int]] = [
    ("router", DeviceType.ROUTER, 6),
    ("switch", DeviceType.SWITCH, 6),
    ("catalyst", DeviceType.SWITCH, 6),
    ("cisco ios", DeviceType.SWITCH, 3),
    ("firewall", DeviceType.FIREWALL, 7),
    ("asa", DeviceType.FIREWALL, 6),
    ("access point", DeviceType.ACCESS_POINT, 6),
    ("aironet", DeviceType.ACCESS_POINT, 6),
    ("printer", DeviceType.PRINTER, 6),
    ("jetdirect", DeviceType.PRINTER, 6),
    ("laserjet", DeviceType.PRINTER, 6),
    ("camera", DeviceType.CAMERA, 6),
    ("ip cam", DeviceType.CAMERA, 6),
    ("windows", DeviceType.PC, 4),
    ("ubuntu", DeviceType.SERVER, 3),
    ("linux", DeviceType.SERVER, 2),
    ("server", DeviceType.SERVER, 3),
    ("voip", DeviceType.PHONE, 5),
    ("phone", DeviceType.PHONE, 5),
]

# יצרני ציוד רשת מובהקים (לפי MAC vendor)
NETWORK_VENDORS = ("cisco", "juniper", "aruba", "hewlett packard enterprise",
                   "mikrotik", "ubiquiti", "d-link", "tp-link", "netgear", "huawei")
PRINTER_VENDORS = ("hewlett-packard", "hp inc", "canon", "epson", "brother",
                   "lexmark", "xerox", "kyocera", "ricoh")
PC_VENDORS = ("dell", "lenovo", "asus", "gigabyte", "micro-star", "intel", "apple")
CAMERA_VENDORS = ("hikvision", "dahua", "axis", "hanwha", "vivotek")


def classify(device: Device, snmp_services: int | None = None,
             is_managed_network_device: bool = False) -> DeviceType:
    scores: dict[DeviceType, int] = defaultdict(int)

    # 1) פורטים פתוחים
    for port in device.open_ports:
        for dtype, pts in PORT_HINTS.get(port.port, []):
            scores[dtype] += pts
        # טקסט השירות עצמו
        service_text = f"{port.service} {port.product}".lower()
        for kw, dtype, pts in KEYWORD_HINTS:
            if kw in service_text:
                scores[dtype] += pts

    # 2) sysDescr / OS
    descr = f"{device.os} {device.model}".lower()
    for kw, dtype, pts in KEYWORD_HINTS:
        if kw in descr:
            scores[dtype] += pts

    # 3) יצרן לפי MAC
    vendor = device.vendor.lower()
    if any(v in vendor for v in PRINTER_VENDORS):
        scores[DeviceType.PRINTER] += 4
    if any(v in vendor for v in CAMERA_VENDORS):
        scores[DeviceType.CAMERA] += 5
    if any(v in vendor for v in PC_VENDORS):
        scores[DeviceType.PC] += 3
    if any(v in vendor for v in NETWORK_VENDORS):
        scores[DeviceType.SWITCH] += 2
        scores[DeviceType.ROUTER] += 1

    # 4) SNMP sysServices: ביט 2 (ערך 2) = L2, ביט 3 (ערך 4) = L3/routing
    if snmp_services is not None:
        if snmp_services & 0x04:          # routing
            scores[DeviceType.ROUTER] += 5
        if snmp_services & 0x02:          # L2 switching
            scores[DeviceType.SWITCH] += 4

    # 5) הצלחנו להתחבר אליו כציוד רשת מנוהל — רמז חזק
    if is_managed_network_device:
        nt = device.netmiko_type
        if "router" in nt or device.open_ports and any(p.port == 179 for p in device.open_ports):
            scores[DeviceType.ROUTER] += 4
        else:
            scores[DeviceType.SWITCH] += 4

    if not scores or max(scores.values()) == 0:
        return DeviceType.UNKNOWN
    return max(scores, key=scores.get)
