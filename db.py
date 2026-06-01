import sqlite3
import threading
from pathlib import Path

DB_PATH = Path("data/traffic.db")

# CRITICAL: SQLite connections are NOT thread-safe when shared.
# The sniffer runs in a background thread. The dashboard runs in main thread.
# threading.local() gives EACH thread its own separate connection object.
# Without this you will get "database is locked" errors randomly.

_local = threading.local()

def get_conn():
    """Return this thread's own SQLite coonection. Create it if first time."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(exist_ok=True)
        _local.conn = sqlite3.connect(str(DB_PATH))
        _local.conn.row_factory = sqlite3.Row

    return _local.conn

def init_db():
    """Create the packets table if it doesn't exist. Safe to call multiple times."""
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            src_mac   TEXT,
            dst_mac   TEXT,
            protocol  TEXT,
            src_ip    TEXT,
            dst_ip    TEXT,
            src_port  INTEGER,
            dst_port  INTEGER,
            length    INTEGER,
            flags     TEXT,
            ttl       INTEGER,
            is_alert  INTEGER DEFAULT 0
        )
    """)
    # Indexes make queries fast — without them every SELECT scans every row
    conn.execute("CREATE INDEX IF NOT EXISTS idx_proto ON packets(protocol)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON packets(timestamp)")
    conn.commit()


def insert_packet(packet: dict, is_alert: bool = False):
    """Insert one parsed packet dict into the database."""
    conn = get_conn()
    conn.execute("""
        INSERT INTO packets
            (timestamp, src_mac, dst_mac, protocol,
             src_ip, dst_ip, src_port, dst_port,
             length, flags, ttl, is_alert)
        VALUES
            (:timestamp, :src_mac, :dst_mac, :protocol,
             :src_ip, :dst_ip, :src_port, :dst_port,
             :length, :flags, :ttl, :is_alert)
    """, {**packet, "is_alert": int(is_alert)})
    conn.commit()


def get_stats():
    """
    Called by dashboard every 1.5 seconds.
    Returns everything needed to render the live dashboard.
    """
    conn = get_conn()

    total  = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    alerts = conn.execute("SELECT COUNT(*) FROM packets WHERE is_alert=1").fetchone()[0]

    by_proto = conn.execute("""
        SELECT protocol, COUNT(*) as cnt
        FROM packets
        GROUP BY protocol
        ORDER BY cnt DESC
        LIMIT 8
    """).fetchall()

    top_ips = conn.execute("""
        SELECT src_ip, COUNT(*) as cnt
        FROM packets
        WHERE src_ip != ''
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 8
    """).fetchall()

    recent = conn.execute("""
        SELECT timestamp, protocol, src_ip, dst_ip,
               src_port, dst_port, length, flags, is_alert
        FROM packets
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    return {
        "total"    : total,
        "alerts"   : alerts,
        "by_proto" : by_proto,
        "top_ips"  : top_ips,
        "recent"   : recent,
    }
