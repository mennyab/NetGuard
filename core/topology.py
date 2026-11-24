"""מנוע טופולוגיה — זחילה ברשת החל ממתג/נתב התחלתי (seed).

המודל (לפי החלטה 19):
  1. מתחברים ל-seed שהמשתמש מספק (IP + אופציונלית משתמש/סיסמה).
  2. קוראים שכנים: CDP ו-LLDP (`show cdp neighbors detail` / `show lldp ...`).
  3. קוראים שכנויות ניתוב: OSPF (`show ip ospf neighbor`).
  4. קוראים טבלת MAC כדי לחבר התקני קצה לפורטים.
  5. לכל שכן שהוא ציוד רשת וידועה כתובת הניהול שלו — מתחברים גם אליו (רקורסיה),
     בהנחה ש-telnet/ssh מופעלים. אותם פרטי גישה מנוסים בכל קפיצה.
  6. בונים גרף קשרים (networkx) שמוצג ב-pyvis.

כל הקריאות הן show בלבד. אין כניסה ל-config. Session Manager אוכף זאת.
"""

from __future__ import annotations

from collections.abc import Callable

from core import netutils
from core.classifier import classify
from core.models import Credential, Device, DeviceType, Interface, Link, ScanResult
from core.pivot import pivot_hop, pivot_teardown
from core.session_manager import open_session

ProgressFn = Callable[[str, float, str], None]


def _noop(stage: str, fraction: float, log: str) -> None:
    pass


# ---------------------------------------------------------------------------
# חילוץ שדות מתבניות TextFSM (שמות השדות משתנים מעט בין תבניות/גרסאות)
# ---------------------------------------------------------------------------

def _first(row: dict, *keys: str) -> str:
    for k in keys:
        if k in row and row[k]:
            v = row[k]
            return v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else str(v))
    return ""


# ---------------------------------------------------------------------------
# קריאת שכנים מהתקן מחובר
# ---------------------------------------------------------------------------

def read_cdp_neighbors(session) -> list[dict]:
    """מחזיר [{neighbor_ip, neighbor_name, local_port, remote_port, platform}]."""
    rows = session.run_show_structured("show cdp neighbors detail")
    result = []
    for r in rows:
        result.append({
            "neighbor_ip": _first(r, "management_ip", "mgmt_address", "management_address", "ip_address"),
            "neighbor_name": _first(r, "destination_host", "dest_host", "neighbor_name", "device_id"),
            "local_port": _first(r, "local_port", "local_interface"),
            "remote_port": _first(r, "remote_port", "port_id", "neighbor_interface"),
            "platform": _first(r, "platform"),
            "source": "cdp",
        })
    return result


def read_lldp_neighbors(session) -> list[dict]:
    rows = session.run_show_structured("show lldp neighbors detail")
    result = []
    for r in rows:
        result.append({
            "neighbor_ip": _first(r, "management_ip", "mgmt_address", "management_address"),
            "neighbor_name": _first(r, "neighbor", "system_name", "neighbor_name", "chassis_id"),
            "local_port": _first(r, "local_interface", "local_port"),
            "remote_port": _first(r, "neighbor_interface", "port_id", "remote_port"),
            "platform": _first(r, "system_description", "platform"),
            "source": "lldp",
        })
    return result


def read_ospf_neighbors(session) -> list[dict]:
    """שכנויות OSPF — חושף נתבים שלא בהכרח מופיעים ב-CDP."""
    rows = session.run_show_structured("show ip ospf neighbor")
    result = []
    for r in rows:
        addr = _first(r, "address", "neighbor_address", "ip_address")
        nid = _first(r, "neighbor_id", "router_id")
        if addr or nid:
            result.append({
                "neighbor_ip": addr or nid,
                "neighbor_name": nid,
                "local_port": _first(r, "interface"),
                "remote_port": "",
                "platform": "",
                "source": "ospf",
            })
    return result


def read_arp_table(session) -> list[dict]:
    """טבלת ARP — ממפה IP<->MAC של כל התקני הקצה שההתקן מכיר (כולל ברשתות מרוחקות)."""
    rows = session.run_show_structured("show ip arp")
    result = []
    for r in rows:
        ip = _first(r, "address", "ip_address", "ip")
        mac = _first(r, "mac", "mac_address", "hardware_addr")
        if ip and mac and netutils.is_valid_ip(ip):
            result.append({"ip": ip, "mac": netutils.normalize_mac(mac)})
    return result


def read_mac_table(session) -> list[dict]:
    """טבלת MAC — מחברת התקני קצה לפורט במתג."""
    rows = session.run_show_structured("show mac address-table")
    result = []
    for r in rows:
        mac = _first(r, "destination_address", "mac_address", "mac")
        port = _first(r, "destination_port", "ports", "port", "interface")
        vlan = _first(r, "vlan", "vlan_id")
        if mac and port and port.lower() not in ("cpu", "all"):
            result.append({"mac": netutils.normalize_mac(mac), "port": port, "vlan": vlan})
    return result


def read_identity(session) -> dict:
    """שם ההתקן, גרסה, דגם ו-MAC (מ-show version, עם fallback ל-show interfaces)."""
    info = {"hostname": "", "os": "", "model": "", "mac": ""}
    try:
        ver = session.run_show_structured("show version")
        if ver:
            info["hostname"] = _first(ver[0], "hostname", "host_name")
            info["os"] = _first(ver[0], "version", "os_version", "software_image")
            info["model"] = _first(ver[0], "hardware", "platform", "model")
            info["mac"] = _first(ver[0], "mac_address", "mac", "base_mac")
    except Exception:
        pass
    # fallback ל-MAC: הכתובת הצרובה של הממשק הראשון
    if not info["mac"]:
        try:
            import re
            out = session.run_show("show interfaces")
            m = re.search(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}", out)
            if m:
                info["mac"] = m.group(0)
        except Exception:
            pass
    return info


def reach(ip: str, pivot_access: tuple | None, seed_cred: Credential,
          pivot_user: str = "cisco", pivot_pw: list[str] | None = None,
          pivot_enable: str = ""):
    """מגיע להתקן: קודם ישירות, ואז דרך pivot (telnet מקונן).
    מחזיר (session, base_ip, pivot_depth, note). בסשן pivot צריך pivot_teardown לפני close.
    """
    pivot_pw = pivot_pw or [p for p in [seed_cred.password, "cisco"] if p] or ["cisco"]
    outcome = open_session(ip, user_cred=seed_cred)
    if outcome.session:
        return outcome.session, ip, 0, ""
    if pivot_access:
        base_ip, hops = pivot_access
        base_outcome = open_session(base_ip, user_cred=seed_cred)
        if base_outcome.session:
            sess = base_outcome.session
            for i, hop in enumerate(hops):
                if not pivot_hop(sess.handler, hop, username=pivot_user,
                                 passwords=pivot_pw, enable_password=pivot_enable):
                    pivot_teardown(sess.handler, i)
                    sess.close()
                    return None, base_ip, 0, f"pivot נכשל ב-{hop}"
            return sess, base_ip, len(hops), "pivot"
    reason = outcome.skipped_reason or (
        "נדרשים פרטי גישה" if outcome.needs_user_credentials else "לא נגיש")
    return None, ip, 0, reason


# ---------------------------------------------------------------------------
# הזחילה הרקורסיבית
# ---------------------------------------------------------------------------

def crawl(seed_ip: str, seed_cred: Credential, progress: ProgressFn = _noop,
          max_devices: int = 60, existing: ScanResult | None = None
          ) -> tuple[ScanResult, list[dict]]:
    """זוחל ברשת מה-seed. מחזיר (ScanResult עם links, רשימת התקנים שדורשים גישה).

    existing — אם קיימת סריקת Discovery, מעשירים אותה; אחרת בונים חדשה.
    """
    result = existing or ScanResult(subnets=[])
    needs_access: list[dict] = []          # התקנים שלא הצלחנו להתחבר אליהם
    # קביעת זהות יציבה (uid) לכל התקן קיים, וקידוד מחדש של המילון לפי uid
    _ensure_uids(result)
    mac_to_device = {d.mac: d for d in result.devices.values() if d.mac}

    visited: set[str] = set()
    # כל פריט: (ip, pivot_access) כאשר pivot_access = (base_ip, hops) או None.
    # hops = רשימת IP לביצוע telnet מקונן מ-base_ip עד ליעד (הפריט האחרון = היעד).
    queue: list[tuple[str, tuple | None]] = [(seed_ip, None)]
    queued_ips: set[str] = {seed_ip}
    ip_to_id: dict[str, str] = {d.ip: d.id for d in result.devices.values() if d.ip}

    # סיסמאות ל-pivot (telnet מקונן): פרטי המשתמש אם ניתנו, ואז 'cisco'
    pivot_pw = [p for p in [seed_cred.password, "cisco"] if p]
    pivot_user = seed_cred.username or "cisco"
    pivot_enable = seed_cred.enable_password or ""

    # זיהוי יצרן לפי MAC (לסיווג התקני קצה)
    from core.discovery import _vendor_lookup, lookup_vendor
    mac_lookup = _vendor_lookup()

    def ensure_device(ip: str, name: str = "", mac: str = "") -> Device:
        """מחזיר/יוצר התקן לפי IP (או MAC). לכל התקן uid יציב שלא משתנה."""
        if ip and ip in ip_to_id:
            return result.devices[ip_to_id[ip]]
        if mac and mac in mac_to_device:
            return mac_to_device[mac]
        dev = Device(ip=ip, mac=mac, hostname=name)
        dev.uid = mac or ip or f"dev{len(result.devices)}"   # זהות יציבה
        result.devices[dev.uid] = dev
        if ip:
            ip_to_id[ip] = dev.uid
        if mac:
            mac_to_device[mac] = dev
        return dev

    while queue and len(visited) < max_devices:
        ip, pivot_access = queue.pop(0)
        if not ip or ip in visited or not netutils.is_valid_ip(ip):
            continue
        visited.add(ip)

        progress("Crawl", 0.1 + 0.8 * (len(visited) / max_devices),
                 f"מתחבר ל-{ip} ...")
        session, base_ip, pivot_depth, note = reach(
            ip, pivot_access, seed_cred, pivot_user, pivot_pw, pivot_enable)

        if not session:
            needs_access.append({"ip": ip, "reason": note})
            progress("Crawl", 0.0, f"⚠ {ip}: {note}")
            ensure_device(ip)
            continue

        via = " (דרך pivot)" if pivot_depth else ""
        # ה-access הנוכחי: base_ip + hops שמובילים ל-ip. לשכנים נוסיף hop נוסף.
        current_hops = list(pivot_access[1]) if (pivot_access and pivot_depth) else []

        current = ensure_device(ip)
        current.managed = True
        # שמירת נתיב הגישה כדי שה-Assessment יוכל להתחבר שוב (ישיר או pivot)
        current.access_base = base_ip
        current.access_hops = current_hops
        try:
            current.netmiko_type = session.handler.device_type or session.netmiko_type
        except Exception:
            current.netmiko_type = session.netmiko_type
        current.device_type = DeviceType.SWITCH
        if pivot_depth or session.protocol.value == "telnet":
            current.discovered_by.append("telnet")

        try:
            ident = read_identity(session)
            if ident["hostname"]:
                current.hostname = ident["hostname"]
            if ident["os"]:
                current.os = ident["os"]
            if ident["model"] and not current.model:
                current.model = ident["model"]
            if ident["mac"] and not current.mac:
                current.mac = netutils.normalize_mac(ident["mac"])

            # --- שכנים: CDP + LLDP + OSPF ---
            ospf_neighbors = read_ospf_neighbors(session)
            if ospf_neighbors:
                current.device_type = DeviceType.ROUTER   # מריץ OSPF => נתב
            neighbors = read_cdp_neighbors(session) + read_lldp_neighbors(session) \
                + ospf_neighbors
            for nb in neighbors:
                nb_ip = nb["neighbor_ip"].strip()
                nb_dev = ensure_device(nb_ip, name=nb["neighbor_name"])
                if nb.get("platform") and not nb_dev.model:
                    nb_dev.model = nb["platform"][:60]
                # סיווג שכן שלא התחברנו אליו, לפי פלטפורמת ה-CDP
                if nb_dev.device_type == DeviceType.UNKNOWN and not nb_dev.managed:
                    nb_dev.device_type = _classify_by_platform(nb.get("platform", ""))
                result.links.append(Link(
                    device_a=current.id, device_b=nb_dev.id,
                    port_a=nb["local_port"], port_b=nb["remote_port"],
                    source=nb["source"],
                ))
                # רקורסיה: ננסה להגיע לשכן — ישירות, או דרך pivot מההתקן הנוכחי
                if nb_ip and nb_ip not in visited and nb_ip not in queued_ips:
                    nb_access = (base_ip, current_hops + [nb_ip])
                    queue.append((nb_ip, nb_access))
                    queued_ips.add(nb_ip)

            # --- טבלת ARP: גילוי התקני קצה בכל מרחב הכתובות (כולל רשתות מרוחקות) ---
            new_hosts = 0
            for arp in read_arp_table(session):
                host = ensure_device(arp["ip"], mac=arp["mac"])
                if not host.ip:
                    host.ip = arp["ip"]
                if not host.mac:
                    host.mac = arp["mac"]
                # סיווג התקן קצה חדש לפי יצרן ה-MAC
                if not host.managed and host.device_type == DeviceType.UNKNOWN:
                    host.vendor = host.vendor or lookup_vendor(mac_lookup, host.mac)
                    host.device_type = classify(host)
                    host.discovered_by.append("arp")
                    new_hosts += 1

            # --- טבלת MAC: חיבור התקני קצה לפורטים פיזיים ---
            for entry in read_mac_table(session):
                end = mac_to_device.get(entry["mac"])
                if end and end.id != current.id:
                    result.links.append(Link(
                        device_a=current.id, device_b=end.id,
                        port_a=entry["port"], port_b="",
                        source="mac_table",
                    ))
                    current.interfaces.append(Interface(
                        name=entry["port"], status="connected",
                        vlan=entry["vlan"], connected_to=end.id))
            progress("Crawl", 0.0,
                     f"✔ {current.display_name}: {len(neighbors)} שכנים, "
                     f"{new_hosts} התקני קצה{via}")
        finally:
            if pivot_depth:
                pivot_teardown(session.handler, pivot_depth)  # יציאה מה-telnet המקונן
            session.close()        # סוגר רק את חיבור הבסיס שלנו

    # מיזוג התקנים שהם אותו רכיב פיזי (כמה כתובות IP לאותו נתב) לפי hostname
    _merge_by_hostname(result)
    # ניקוי קשרים כפולים
    result.links = _dedupe_links(result.links)
    progress("Done", 1.0,
             f"הטופולוגיה נבנתה: {len(result.devices)} התקנים, {len(result.links)} קשרים")
    return result, needs_access


def _ensure_uids(result: ScanResult) -> None:
    """מבטיח uid יציב לכל התקן, ומקודד מחדש את המילון לפי uid."""
    rekeyed: dict[str, Device] = {}
    for key, dev in list(result.devices.items()):
        if not dev.uid:
            dev.uid = dev.mac or dev.ip or key
        rekeyed[dev.uid] = dev
    result.devices.clear()
    result.devices.update(rekeyed)


def _merge_into(keep: Device, dup: Device, result: ScanResult) -> None:
    """ממזג את dup לתוך keep ומפנה קשרים."""
    if not keep.managed and dup.managed:
        keep.managed = True
    keep.netmiko_type = keep.netmiko_type or dup.netmiko_type
    if dup.device_type == DeviceType.ROUTER:
        keep.device_type = DeviceType.ROUTER
    keep.interfaces.extend(dup.interfaces)
    keep.open_ports = keep.open_ports or dup.open_ports
    keep.model = keep.model or dup.model
    keep.mac = keep.mac or dup.mac
    keep.hostname = keep.hostname or dup.hostname
    keep.access_base = keep.access_base or dup.access_base
    if not keep.access_hops:
        keep.access_hops = dup.access_hops
    for extra in [dup.ip, *dup.alt_ips]:
        if extra and extra != keep.ip and extra not in keep.alt_ips:
            keep.alt_ips.append(extra)
    for lk in result.links:
        if lk.device_a == dup.id:
            lk.device_a = keep.id
        if lk.device_b == dup.id:
            lk.device_b = keep.id
    result.devices.pop(dup.uid, None)


def _merge_by_hostname(result: ScanResult) -> None:
    """ממזג התקנים שהם אותו רכיב פיזי — לפי hostname או לפי אותו MAC."""
    by_name: dict[str, Device] = {}
    by_mac: dict[str, Device] = {}
    for dev in list(result.devices.values()):
        if dev.uid not in result.devices:
            continue   # כבר מוזג
        host = dev.hostname.strip().lower()
        mac = dev.mac.strip().lower()
        keep = (by_name.get(host) if host else None) or (by_mac.get(mac) if mac else None)
        if keep is not None and keep.uid != dev.uid:
            _merge_into(keep, dev, result)
            dev = keep
        if host:
            by_name.setdefault(host, dev)
        if mac:
            by_mac.setdefault(mac, dev)
    # הסרת קשרים עצמיים שנוצרו מהמיזוג (התקן לעצמו)
    result.links = [lk for lk in result.links if lk.device_a != lk.device_b]


def _classify_by_platform(platform: str) -> DeviceType:
    """מסווג התקן לפי מחרוזת הפלטפורמה של CDP (כשלא התחברנו אליו)."""
    p = platform.lower()
    if any(k in p for k in ("isr", "router", "asr", "c89", "c81")):
        return DeviceType.ROUTER
    if any(k in p for k in ("ws-c", "catalyst", "switch", "c29", "c35", "c93", "c38")):
        return DeviceType.SWITCH
    return DeviceType.UNKNOWN


# סדר עדיפות למקור קשר (מי "מנצח" כשיש כמה קשרים לאותו זוג התקנים)
_SOURCE_RANK = {"cdp": 0, "lldp": 1, "mac_table": 2, "routing": 3, "ospf": 4}


def _dedupe_links(links: list[Link]) -> list[Link]:
    """מאחד קשרים בין אותו זוג התקנים לקשר אחד, מעדיף CDP/LLDP (עם שני הפורטים)."""
    best: dict[frozenset, Link] = {}
    for lk in links:
        key = frozenset([lk.device_a, lk.device_b])
        cur = best.get(key)
        if cur is None or _SOURCE_RANK.get(lk.source, 9) < _SOURCE_RANK.get(cur.source, 9):
            best[key] = lk
    return list(best.values())
