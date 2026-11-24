"""רינדור הטופולוגיה כגרף pyvis אינטראקטיבי (HTML)."""

from __future__ import annotations

from core.models import DeviceType, ScanResult

# צבע לפי רמת סיכון של ההתקן
RISK_COLOR = {"critical": "#e74c3c", "high": "#e67e22",
              "medium": "#f1c40f", "low": "#2ecc71", "none": "#3498db"}

SHAPE = {
    DeviceType.ROUTER: "diamond",
    DeviceType.SWITCH: "square",
    DeviceType.L3_SWITCH: "square",
    DeviceType.FIREWALL: "triangle",
    DeviceType.ACCESS_POINT: "triangleDown",
    DeviceType.PC: "dot",
    DeviceType.SERVER: "box",
    DeviceType.PRINTER: "dot",
    DeviceType.CAMERA: "dot",
    DeviceType.UNKNOWN: "dot",
}


def _device_risk(result: ScanResult, device_id: str) -> str:
    """רמת הסיכון החמורה ביותר של התקן, לצביעת הצומת."""
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    worst = "none"
    for v in result.vulnerabilities:
        if v.device_id == device_id:
            if worst == "none" or sev_rank[v.severity.value] < sev_rank[worst]:
                worst = v.severity.value
    return worst


def _layout_positions(result: ScanResult) -> dict[str, tuple[float, float]]:
    """פריסה התחלתית יציבה עם networkx (physics מכובה -> הרכיבים נשארים במקומם)."""
    import networkx as nx

    g = nx.Graph()
    g.add_nodes_from(result.devices.keys())
    for lk in result.links:
        if lk.device_a in result.devices and lk.device_b in result.devices:
            g.add_edge(lk.device_a, lk.device_b)
    try:
        pos = nx.spring_layout(g, k=1.2, iterations=100, seed=42)
    except Exception:
        pos = {n: (0.0, 0.0) for n in g.nodes}
    scale = 450
    return {n: (float(p[0]) * scale, float(p[1]) * scale) for n, p in pos.items()}


def build_html(result: ScanResult, height: str = "600px") -> str:
    from pyvis.network import Network

    net = Network(height=height, width="100%", bgcolor="#ffffff",
                  font_color="#222", directed=False, notebook=False, cdn_resources="in_line")

    positions = _layout_positions(result)

    from core.icons import device_icon_uri

    for dev in result.devices.values():
        risk = _device_risk(result, dev.id)
        label = dev.display_name
        title = (f"{dev.device_type.value}\nIP: {dev.ip or '—'}\n"
                 f"MAC: {dev.mac or '—'}\nדגם: {dev.model or dev.vendor or '—'}\n"
                 f"פורטים פתוחים: {len(dev.open_ports)}")
        size = 30 if dev.device_type.is_network_device else 22
        x, y = positions.get(dev.id, (0.0, 0.0))
        # אייקון אמיתי (SVG) + טבעת צבע לפי רמת הסיכון
        net.add_node(dev.id, label=label, title=title,
                     shape="circularImage", image=device_icon_uri(dev.device_type),
                     color={"border": RISK_COLOR[risk], "background": "#ffffff"},
                     borderWidth=4, borderWidthSelected=5,
                     size=size, x=x, y=y, physics=False,
                     font={"size": 15, "color": "#1a2233", "face": "arial",
                           "strokeWidth": 4, "strokeColor": "#ffffff"})

    for lk in result.links:
        if lk.device_a in result.devices and lk.device_b in result.devices:
            edge_label = ""
            if lk.port_a or lk.port_b:
                edge_label = f"{lk.port_a} ↔ {lk.port_b}".strip(" ↔")
            net.add_edge(lk.device_a, lk.device_b, title=f"{lk.source}: {edge_label}",
                         label=edge_label if lk.source in ("cdp", "lldp") else "",
                         color="#888")

    # physics מכובה לגמרי: גרירה ממקמת והרכיב נשאר; interaction מאפשר גרירה וזום
    net.set_options('''{
      "physics": { "enabled": false },
      "interaction": { "dragNodes": true, "dragView": true, "zoomView": true },
      "edges": { "smooth": false, "font": { "size": 10, "align": "top" } }
    }''')
    return net.generate_html(notebook=False)
