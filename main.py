import argparse
import signal
import sys

from sniffer   import Sniffer
from parser    import parse_ethernet
import db
import alerts
from dashboard import run_dashboard


def build_on_packet(sniffer_ref):
    """
    Returns the callback function that the sniffer calls for every frame.
    We wrap it in a closure so it can reference the sniffer if needed later.

    Why a closure instead of a plain function?
    Because later if you want to add stats like "packets per second"
    you can store state in the closure without using global variables.
    """
    def on_packet(raw_data):
        # Step 1: parse raw bytes → clean dict
        packet = parse_ethernet(raw_data)
        if packet is None:
            return   # too short / malformed — skip silently

        # Step 2: check if this packet is suspicious
        is_alert, reason = alerts.check_packet(packet)

        # Step 3: store in SQLite — always, alert or not
        db.insert_packet(packet, is_alert=is_alert)

        # Step 4: if alert, print immediately to terminal
        # (dashboard also shows it, but this gives instant feedback)
        if is_alert:
            print(f"\n  [!] ALERT: {reason}")
            print(f"      {packet['src_ip']}:{packet['src_port']}"
                  f" → {packet['dst_ip']}:{packet['dst_port']}\n")

    return on_packet


def main():
    # ── CLI arguments ──────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Home Lab Network Traffic Analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py --iface eth0
  sudo python main.py --iface eth0 --no-dash
        """
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Network interface to sniff on (default: eth0). "
             "Find yours with: ip link show"
    )
    parser.add_argument(
        "--no-dash",
        action="store_true",
        help="Disable live dashboard — log-only mode. "
             "Useful for long captures or running headless."
    )
    args = parser.parse_args()

    # ── Startup ────────────────────────────────────────────────
    print(f"[*] Initialising database...")
    db.init_db()

    print(f"[*] Starting sniffer on interface: {args.iface}")
    sniffer = Sniffer(
        interface=args.iface,
        on_packet=build_on_packet(None),
    )
    thread = sniffer.start()
    print(f"[*] Sniffer running. Capturing traffic...\n")

    # ── Clean shutdown on Ctrl+C ───────────────────────────────
    # Why signal handler instead of try/except KeyboardInterrupt?
    # signal.SIGINT fires even when the main thread is blocked inside
    # rich's Live context manager. KeyboardInterrupt alone sometimes
    # gets swallowed by rich and the socket stays open.
    def handle_exit(sig, frame):
        print("\n\n[*] Stopping sniffer...")
        sniffer.stop()

        # Print final summary before exit
        stats = db.get_stats()
        print(f"[*] Session summary:")
        print(f"    Total packets : {stats['total']}")
        print(f"    Total alerts  : {stats['alerts']}")
        print(f"    Log file      : logs/alerts.log")
        print(f"    Database      : data/traffic.db")
        print(f"\n[*] Run this to query your capture:")
        print(f"    sqlite3 data/traffic.db "
              f"\"SELECT protocol, COUNT(*) FROM packets GROUP BY protocol;\"")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    # ── Run ────────────────────────────────────────────────────
    if args.no_dash:
        # Log-only mode — just keep the sniffer thread alive
        print("[*] Dashboard disabled. Press Ctrl+C to stop.")
        thread.join()
    else:
        # Dashboard mode — blocks here until Ctrl+C
        run_dashboard(iface=args.iface)


if __name__ == "__main__":
    main()
