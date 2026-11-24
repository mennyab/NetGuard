"""מודלי הנתונים המשותפים לכל רכיבי המערכת."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class DeviceType(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    L3_SWITCH = "l3_switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    PC = "pc"
    SERVER = "server"
    PRINTER = "printer"
    CAMERA = "camera"
    PHONE = "phone"
    IOT = "iot"
    UNKNOWN = "unknown"

    @property
    def is_network_device(self) -> bool:
        """התקן רשת מנוהל - ניתן להתחבר אליו ולבצע עליו Mitigation."""
        return self in (DeviceType.ROUTER, DeviceType.SWITCH,
                        DeviceType.L3_SWITCH, DeviceType.FIREWALL)

    @property
    def icon(self) -> str:
        return {
            "router": "🌐", "switch": "🔀", "l3_switch": "🔀", "firewall": "🧱",
            "access_point": "📶", "pc": "💻", "server": "🖥", "printer": "🖨",
            "camera": "📷", "phone": "📞", "iot": "📟", "unknown": "❔",
        }[self.value]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}[self.value]

    @property
    def icon(self) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🟢", "info": "⚪"}[self.value]


class Protocol(str, Enum):
    SSH = "ssh"
    TELNET = "telnet"


class Category(str, Enum):
    PASSWORD = "password"
    ACCESS = "access"
    PORTS = "ports"
    SERVICES = "services"
    CONFIG = "config"


@dataclass
class Credential:
    """פרטי גישה להתקן. לעולם לא נשמרים ב-DB בטקסט גלוי."""
    username: str = ""
    password: str = ""
    enable_password: str = ""
    protocol: Protocol = Protocol.SSH
    source: str = "user"          # user / default / asked

    def __repr__(self) -> str:    # שלא יודפסו סיסמאות בלוגים
        return f"Credential(user={self.username!r}, protocol={self.protocol.value}, source={self.source})"


@dataclass
class Interface:
    name: str
    status: str = ""              # connected / notconnect / disabled / err-disabled
    vlan: str = ""
    mode: str = ""                # access / trunk / routed
    port_security: bool | None = None
    description: str = ""
    ip_address: str = ""
    connected_to: str = ""        # device_id של ההתקן בצד השני


@dataclass
class OpenPort:
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    model: str = ""
    os: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    netmiko_type: str = ""        # למשל cisco_ios / hp_procurve / juniper_junos
    managed: bool = False         # האם הצלחנו להתחבר ולקרוא קונפיגורציה
    interfaces: list[Interface] = field(default_factory=list)
    open_ports: list[OpenPort] = field(default_factory=list)
    running_config: str = ""
    discovered_by: list[str] = field(default_factory=list)   # arp / snmp / cdp / lldp / nmap
    alt_ips: list[str] = field(default_factory=list)         # כתובות IP נוספות (ממשקים אחרים)
    access_base: str = ""                                     # IP להתחברות (ישיר=עצמו, pivot=הבסיס)
    access_hops: list[str] = field(default_factory=list)     # hops של telnet מקונן (pivot)
    uid: str = ""                                            # זהות יציבה שלא משתנה אחרי יצירה

    @property
    def id(self) -> str:
        return self.uid or self.mac or self.ip

    @property
    def display_name(self) -> str:
        return self.hostname or self.ip


@dataclass
class Link:
    """קשר בין שני התקנים בטופולוגיה."""
    device_a: str
    device_b: str
    port_a: str = ""
    port_b: str = ""
    source: str = ""              # cdp / lldp / mac_table / routing


@dataclass
class Vulnerability:
    device_id: str
    title: str
    category: Category
    severity: Severity
    details: str = ""
    evidence: str = ""            # שורת קונפיגורציה / פלט שמראה את הבעיה
    mitigation_id: str = ""


@dataclass
class MitigationAction:
    id: str
    device_id: str
    title: str
    commands: list[str]
    undo_commands: list[str] = field(default_factory=list)   # לשחזור (Rollback)
    impact: str = ""
    requires_input: list[str] = field(default_factory=list)  # למשל "new_password"
    input_target: str = ""        # למשל "enable" / "username admin" (למילוי הסיסמה)
    automatic: bool = True        # False = המלצה ידנית בלבד (התקני קצה)
    approved: bool = False
    approved_by: str = ""
    approved_at: datetime | None = None
    status: str = "pending"       # pending / done / failed / rolled_back
    output: str = ""
    backup_path: str = ""


@dataclass
class ScanResult:
    id: int | None = None
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    subnets: list[str] = field(default_factory=list)
    devices: dict[str, Device] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    def device_score(self, device_id: str) -> int:
        """ציון בטיחות 0-100 להתקן בודד (100 = בטוח)."""
        sevs = [v.severity for v in self.vulnerabilities if v.device_id == device_id]
        return score_from_severities(sevs)

    @property
    def risk_score(self) -> int:
        """ציון רשת 0-100 = ממוצע ציוני ההתקנים (100 = הכי בטוח)."""
        if not self.devices:
            return 100 if not self.vulnerabilities else 0
        scores = [self.device_score(dev_id) for dev_id in self.devices]
        return round(sum(scores) / len(scores))


def score_from_severities(sevs: list[Severity]) -> int:
    """ציון 0-100 לפי החולשות: החומרה הגרועה ביותר קובעת את הבסיס, וכמות מורידה.
    נותן טווח משמעותי במקום להתאפס תמיד."""
    if not sevs:
        return 100
    worst = max(sevs, key=lambda s: s.weight)
    base = {"critical": 35, "high": 60, "medium": 78, "low": 90, "info": 98}[worst.value]
    base -= min(25, (len(sevs) - 1) * 2)   # כל חולשה נוספת מורידה מעט
    return max(5, base)


def score_band(score: int) -> str:
    """רמת הציון: low / medium / high (לצביעה)."""
    return "high" if score >= 75 else "medium" if score >= 45 else "low"


def score_color(score: int) -> str:
    return {"high": "#2ecc71", "medium": "#f1c40f", "low": "#e74c3c"}[score_band(score)]
