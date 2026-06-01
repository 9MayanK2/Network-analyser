import time
from rich.live        import Live
from rich.table       import Table
from rich.panel       import Panel
from rich.columns     import Columns
from rich.text        import Text
from rich.console     import Group
from rich             import box
import db


def _protocol_color(proto: str) -> str:
    """Return a rich color name for each protocol — consistent across tables."""
    return {
        "TCP"  : "green",
        "UDP"  : "yellow",
        "ICMP" : "cyan",
        "ARP"  : "blue",
        "IPv6" : "magenta",
    }.get(proto, "white")


def build_header(total: int, alerts: int, iface: str) -> Panel:
    content = (
        f"[bold cyan]⚡ Network Traffic Analyser[/]  "
        f"[dim]|[/]  Total: [bold green]{total}[/]  "
        f"[dim]|[/]  Alerts: [bold red]{alerts}[/]  "
        f"[dim]|[/]  Interface: [yellow]{iface}[/]  "
        f"[dim]| refreshing every 1.5s[/]"
    )
    return Panel(content, style="dim")


def build_proto_table(by_proto) -> Table:
    t = Table(
        title="Protocol Breakdown",
        box=box.SIMPLE_HEAVY,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    t.add_column("Protocol", min_width=10)
    t.add_column("Packets",  justify="right", min_width=8)

    for row in by_proto:
        proto = row["protocol"] or "UNKNOWN"
        color = _protocol_color(proto)
        t.add_row(
            f"[{color}]{proto}[/]",
            f"[{color}]{row['cnt']}[/]",
        )
    return t


def build_ip_table(top_ips) -> Table:
    t = Table(
        title="Top Source IPs",
        box=box.SIMPLE_HEAVY,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
    )
    t.add_column("IP Address", min_width=18)
    t.add_column("Packets",   justify="right", min_width=8)

    for row in top_ips:
        t.add_row(
            f"[green]{row['src_ip']}[/]",
            str(row["cnt"]),
        )
    return t


def build_recent_table(recent) -> Table:
    t = Table(
        title="Recent Packets",
        box=box.SIMPLE_HEAVY,
        title_style="bold cyan",
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    t.add_column("Time",     no_wrap=True,   min_width=10, style="dim")
    t.add_column("Proto",    min_width=6)
    t.add_column("Src IP",   min_width=16)
    t.add_column("Dst IP",   min_width=16,   style="dim")
    t.add_column("DPort",    justify="right",min_width=6)
    t.add_column("Len",      justify="right",min_width=5, style="dim")
    t.add_column("Alert",    justify="center",min_width=6)

    for row in recent:
        proto    = row["protocol"] or "?"
        color    = _protocol_color(proto)
        is_alert = row["is_alert"]

        # Show [!] in red for alert packets, dim dot for normal
        alert_cell = Text("[!]", style="bold red") if is_alert else Text("·", style="dim")

        # Highlight entire row red if it's an alert
        row_style = "on dark_red" if is_alert else ""

        # Timestamp — only show HH:MM:SS not full ISO string
        ts = str(row["timestamp"])[11:19]

        t.add_row(
            ts,
            f"[{color}]{proto}[/]",
            f"[{'red' if is_alert else 'green'}]{row['src_ip'] or '—'}[/]",
            row["dst_ip"] or "—",
            f"[{'red' if is_alert else 'white'}]{row['dst_port']}[/]",
            str(row["length"]),
            alert_cell,
            style=row_style,
        )
    return t


def run_dashboard(iface: str = "eth0"):
    """
    Start the live dashboard. Blocks until Ctrl+C.
    Pulls fresh stats from SQLite every 1.5 seconds.
    """
    with Live(refresh_per_second=1, screen=False) as live:
        while True:
            stats = db.get_stats()

            header  = build_header(stats["total"], stats["alerts"], iface)
            tables  = Columns([
                build_proto_table(stats["by_proto"]),
                build_ip_table(stats["top_ips"]),
            ], expand=True)
            recent  = build_recent_table(stats["recent"])

            # Group combines multiple renderables into one
            # Live.update() only accepts a single renderable — Group is the solution
            live.update(Group(header, tables, recent))
            time.sleep(1.5)



