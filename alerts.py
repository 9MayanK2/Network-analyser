import logging
from pathlib import Path

# Create logs/ folder and set up file logging
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    filename="logs/alerts.log",
    level=logging.WARNING,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Ports that should never appear in normal traffic
# Key = port number, Value = why it's suspicious
SUSPICIOUS_PORTS = {
    21   : "FTP — plaintext file transfer",
    23   : "Telnet — plaintext credentials",
    445  : "SMB — common ransomware vector",
    1433 : "MSSQL — database exposed",
    3306 : "MySQL — database exposed",
    3389 : "RDP — brute force target",
    5432 : "PostgreSQL — database exposed",
    6379 : "Redis — no auth by default",
    9200 : "Elasticsearch — no auth by default",
    27017: "MongoDB — no auth by default",
    4444 : "Metasploit default listener",
}


def check_packet(packet: dict) -> tuple:
    """
    Check one packet for suspicious indicators.
    Returns (is_alert: bool, reason: str).
    Called for EVERY packet — must be fast.
    """
    src_port = packet.get("src_port", 0)
    dst_port = packet.get("dst_port", 0)
    proto    = packet.get("protocol", "")
    flags    = packet.get("flags", "")

    # Check 1: traffic TO a suspicious port (someone connecting to it)
    if dst_port in SUSPICIOUS_PORTS:
        reason = f"Connection TO suspicious port {dst_port} — {SUSPICIOUS_PORTS[dst_port]}"
        _log(packet, reason)
        return True, reason

    # Check 2: traffic FROM a suspicious port (service responding — it's running)
    if src_port in SUSPICIOUS_PORTS:
        reason = f"Response FROM suspicious port {src_port} — {SUSPICIOUS_PORTS[src_port]}"
        _log(packet, reason)
        return True, reason

    # Check 3: TCP NULL scan — all flags are 0
    # Normal TCP always has at least one flag set.
    # Zero flags = evasion technique used by port scanners (nmap -sN)
    if proto == "TCP" and flags == "":
        reason = "TCP NULL scan — no flags set (possible nmap -sN)"
        _log(packet, reason)
        return True, reason

    # Check 4: TCP XMAS scan — FIN + PSH + URG all set simultaneously
    # Another evasion technique — named XMAS because flags "light up like a tree"
    if proto == "TCP" and all(f in flags for f in ("FIN", "PSH", "URG")):
        reason = "TCP XMAS scan — FIN+PSH+URG set (possible nmap -sX)"
        _log(packet, reason)
        return True, reason

    return False, ""


def _log(packet: dict, reason: str):
    """Write alert to log file."""
    msg = (
        f"{reason} | "
        f"{packet.get('src_ip')}:{packet.get('src_port')} → "
        f"{packet.get('dst_ip')}:{packet.get('dst_port')}"
    )
    logging.warning(msg)
