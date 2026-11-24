"""עזרי רשת: זיהוי כרטיסי הרשת ותת-הרשת המקומית."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

import psutil  # מגיע כתלות של scapy; אם לא קיים יש fallback


@dataclass
class LocalInterface:
    name: str
    ip: str
    netmask: str

    @property
    def cidr(self) -> str:
        try:
            net = ipaddress.ip_network(f"{self.ip}/{self.netmask}", strict=False)
            return str(net)
        except ValueError:
            return f"{self.ip}/24"


def list_local_interfaces() -> list[LocalInterface]:
    """כרטיסי רשת פעילים עם כתובת IPv4 (לא loopback)."""
    result: list[LocalInterface] = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            if name in stats and not stats[name].isup:
                continue
            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    result.append(LocalInterface(name, addr.address, addr.netmask or "255.255.255.0"))
    except Exception:
        # fallback: הכתובת המקומית הראשית בלבד
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            result.append(LocalInterface("primary", ip, "255.255.255.0"))
        except Exception:
            pass
    return result


@dataclass
class GatewayInfo:
    gateway: str
    src_ip: str
    interface: str = ""      # שם ידידותי (יושלם לפי src_ip)


def default_gateways() -> list[GatewayInfo]:
    """מזהה את שערי ברירת המחדל (seed מועמד לטופולוגיה) מטבלת הניתוב."""
    result: list[GatewayInfo] = []
    try:
        from scapy.all import conf
        seen: set[str] = set()
        for net, msk, gw, iface, outip, metric in conf.route.routes:
            if net == 0 and gw not in ("0.0.0.0", "::", "") and gw not in seen:
                seen.add(gw)
                result.append(GatewayInfo(gateway=gw, src_ip=str(outip)))
    except Exception:
        return result

    # השלמת שם ידידותי של הכרטיס לפי כתובת ה-src
    ifaces = {i.ip: i.name for i in list_local_interfaces()}
    for g in result:
        g.interface = ifaces.get(g.src_ip, "")
    return result


def is_valid_cidr(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def normalize_mac(mac: str) -> str:
    """מנרמל כתובת MAC לפורמט אחיד aa:bb:cc:dd:ee:ff.
    מטפל ב-Cisco (0013.1a7d.3340), מקפים, ו-ARP (00:13:1a:7d:33:40)."""
    hexchars = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(hexchars) != 12:
        return mac.strip().lower()
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2))
