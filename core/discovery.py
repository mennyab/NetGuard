"""מנוע Discovery — גילוי ההתקנים ברשת.

שכבות:
  1. ARP sweep (scapy)        -> אילו התקנים חיים + MAC
  2. MAC vendor lookup        -> יצרן
  3. nmap (top-100 ports)     -> פורטים, שירותים, גרסאות
  4. SNMP sysDescr/sysName    -> שם ותיאור ההתקן
  5. classifier               -> סוג ההתקן

כל שלב מדווח התקדמות דרך callback כדי שמסך הסריקה יציג יומן חי (החלטה 18).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime

from core import netutils
from core.classifier import classify
from core.config_loader import settings
from core.models import Device, DeviceType, OpenPort, ScanResult

# ייבוא "עצל" של ספריות כבדות, כדי שהמסך ייטען מהר
ProgressFn = Callable[[str, float, str], None]   # (stage, fraction, log_line)


def _noop(stage: str, fraction: float, log: str) -> None:
    pass


# ---------------------------------------------------------------------------
# שכבה 1: ARP sweep
# ---------------------------------------------------------------------------

def _iface_for_subnet(subnet: str):
    """מחזיר את שם כרטיס הרשת ב-scapy שמוביל לתת-הרשת (כדי לשלוח ARP בכרטיס הנכון)."""
    try:
        import ipaddress

        from scapy.all import conf
        # כתובת יעד לדוגמה בתוך תת-הרשת
        net = ipaddress.ip_network(subnet, strict=False)
        target = str(next(net.hosts(), net.network_address))
        iface, _outip, _gw = conf.route.route(target)
        return iface
    except Exception:
        return None


def arp_sweep(subnet: str, progress: ProgressFn = _noop) -> dict[str, str]:
    """מחזיר {ip: mac} לכל התקן חי בתת-הרשת."""
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    timeout = settings()["discovery"]["ping_timeout_seconds"]
    found: dict[str, str] = {}
    iface = _iface_for_subnet(subnet)      # שולחים בכרטיס שמחובר לרשת היעד
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=max(timeout, 2), verbose=False,
                          iface=iface, retry=1)
        for _, rcv in answered:
            found[rcv.psrc] = netutils.normalize_mac(rcv.hwsrc)
            progress("ARP", 0.0, f"{rcv.psrc}  ←  {rcv.hwsrc}")
        if not found:
            progress("ARP", 0.0,
                     f"⚠ לא נמצאו התקנים ב-{subnet} (כרטיס: {iface}). "
                     "ודא שהמערכת רצה כמנהל ושהכרטיס מחובר לרשת הנכונה.")
    except PermissionError:
        progress("ARP", 0.0, "⚠ אין הרשאות ל-ARP. הרץ כמנהל (Administrator).")
    except Exception as e:
        progress("ARP", 0.0, f"⚠ שגיאת ARP: {e}")
    return found


# ---------------------------------------------------------------------------
# שכבה 2: יצרן לפי MAC
# ---------------------------------------------------------------------------

def _vendor_lookup():
    from mac_vendor_lookup import MacLookup
    try:
        return MacLookup()
    except Exception:
        return None


def lookup_vendor(mac_lookup, mac: str) -> str:
    if not mac_lookup or not mac:
        return ""
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# שכבה 3: nmap
# ---------------------------------------------------------------------------

def nmap_scan(ip: str, progress: ProgressFn = _noop) -> tuple[list[OpenPort], str]:
    """סורק פורטים נפוצים. מחזיר (רשימת פורטים פתוחים, ניחוש OS)."""
    import nmap

    args = settings()["discovery"]["nmap_arguments"]
    scanner = nmap.PortScanner()
    ports: list[OpenPort] = []
    os_guess = ""
    try:
        scanner.scan(ip, arguments=args)
        if ip not in scanner.all_hosts():
            return ports, os_guess
        host = scanner[ip]
        for proto in host.all_protocols():
            for port in sorted(host[proto].keys()):
                info = host[proto][port]
                if info.get("state") == "open":
                    ports.append(OpenPort(
                        port=port, protocol=proto,
                        service=info.get("name", ""),
                        product=info.get("product", ""),
                        version=info.get("version", ""),
                    ))
        progress("nmap", 0.0, f"{ip}: {len(ports)} פורטים פתוחים")
    except Exception as e:
        progress("nmap", 0.0, f"⚠ nmap נכשל על {ip}: {e}")
    return ports, os_guess


# ---------------------------------------------------------------------------
# שכבה 4: SNMP
# ---------------------------------------------------------------------------

def snmp_query(ip: str, community: str, version: str, progress: ProgressFn = _noop
               ) -> dict[str, str | int]:
    """שולף sysName, sysDescr, sysServices. מחזיר {} אם אין SNMP."""
    if not community:
        return {}
    try:
        from pysnmp.hlapi.v1arch import (
            CommunityData, ObjectIdentity, ObjectType, UdpTransportTarget,
            get_cmd,
        )
    except Exception:
        return {}

    oids = settings()["discovery"]["snmp_oids"]
    timeout = settings()["discovery"]["snmp_timeout_seconds"]
    result: dict[str, str | int] = {}
    mp_model = 0 if version == "v1" else 1    # v1=0, v2c=1

    for name, oid in oids.items():
        try:
            iterator = get_cmd(
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                ObjectType(ObjectIdentity(oid)),
            )
            err_ind, err_stat, _, var_binds = next(iterator)
            if err_ind or err_stat:
                continue
            for _, val in var_binds:
                result[name] = val.prettyPrint() if name != "sysServices" else int(val)
        except Exception:
            continue
    if result:
        progress("SNMP", 0.0, f"{ip}: SNMP {result.get('sysName', '')}")
    return result


# ---------------------------------------------------------------------------
# תזמור מלא
# ---------------------------------------------------------------------------

def discover(subnets: list[str], snmp_community: str = "", snmp_version: str = "v2c",
             progress: ProgressFn = _noop) -> ScanResult:
    result = ScanResult(started_at=datetime.now(), subnets=list(subnets))
    mac_lookup = _vendor_lookup()

    # --- שלב 1: ARP על כל תת-הרשתות ---
    progress("Discovery", 0.05, "מתחיל סריקת ARP...")
    alive: dict[str, str] = {}
    for i, subnet in enumerate(subnets):
        progress("Discovery", 0.05 + 0.15 * (i / max(len(subnets), 1)),
                 f"ARP על {subnet}")
        alive.update(arp_sweep(subnet, progress))
    progress("Discovery", 0.20, f"נמצאו {len(alive)} התקנים חיים")

    # יצירת רשומות התקן
    for ip, mac in alive.items():
        dev = Device(ip=ip, mac=mac, discovered_by=["arp"])
        dev.vendor = lookup_vendor(mac_lookup, mac)
        result.devices[dev.id] = dev

    # --- שלב 2-4: לכל התקן: nmap + SNMP ---
    total = len(result.devices) or 1
    for idx, dev in enumerate(list(result.devices.values())):
        base = 0.20 + 0.75 * (idx / total)
        progress("Scan", base, f"סורק {dev.ip} ({dev.vendor or 'יצרן לא ידוע'})")

        # nmap
        ports, os_guess = nmap_scan(dev.ip, progress)
        dev.open_ports = ports
        if os_guess:
            dev.os = os_guess
        if ports:
            dev.discovered_by.append("nmap")

        # SNMP
        snmp = snmp_query(dev.ip, snmp_community, snmp_version, progress)
        snmp_services = None
        if snmp:
            dev.discovered_by.append("snmp")
            if snmp.get("sysName"):
                dev.hostname = str(snmp["sysName"])
            if snmp.get("sysDescr"):
                dev.os = str(snmp["sysDescr"])[:200]
            snmp_services = snmp.get("sysServices")

        # סיווג
        dev.device_type = classify(dev, snmp_services=snmp_services)

    progress("Done", 1.0, f"הסריקה הסתיימה: {len(result.devices)} התקנים")
    result.finished_at = datetime.now()
    return result


def expand_subnet(subnet: str) -> list[str]:
    """רשימת כתובות ה-host בתת-הרשת (לשימוש עתידי בסריקה סדרתית)."""
    net = ipaddress.ip_network(subnet, strict=False)
    return [str(h) for h in net.hosts()]
