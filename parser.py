import struct
import socket
from datetime import datetime

ETH_P_IPV4 =0x0800
ETH_P_ARP =0x0806
ETH_P_IPV6 =0x86DD

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

def format_mac(raw_bytes):
    """Convert 6 raw bytes -> aa:bb:cc:dd:ee:ff string"""
    return ":".join(f"{b:02x}" for b in raw_bytes)

def parse_ethernet(raw_data):
    """
    Entry point. Called with every raw frame from sniffer.
    Ethernet II header = 14 bytes:
      | Dst MAC (6) | Src MAC (6) | EtherType (2) |
    Returns a dict. All other modules read from this dict only.
    """

    if len(raw_data) < 14:
        return None

    dst_mac, src_mac,ethertype = struct.unpack("!6s6sH", raw_data[:14])
    payload = raw_data[14:]

    packet = {
        "timestamp" : datetime.now().isoformat(timespec="seconds"),
        "src_mac"   : format_mac(src_mac),
        "dst_mac"   : format_mac(dst_mac),  
        "ethertype" : hex(ethertype),
        "protocol"  : "OTHER",
        "src_ip"    : "",
        "dst_ip"    : "",
        "src_port"  : 0,
        "dst_port"  : 0,
        "ttl"       : 0,
        "flags"     : "",
        "length"    : len(raw_data),
    }


    if ethertype == ETH_P_IPV4:
        parse_ipv4(payload, packet)
    elif ethertype == ETH_P_ARP:
        packet["protocol"] = "ARP"
    elif ethertype == ETH_P_IPV6:
        packet["protocol"] = "IPv6"

    return packet

def parse_ipv4(data, packet):
    """
    IPv4 header — minimum 20 bytes:
      byte 0    : version (top 4 bits) + IHL (bottom 4 bits)
      byte 1    : DSCP/ECN
      bytes 2-3 : total length
      bytes 4-5 : identification
      bytes 6-7 : flags + fragment offset
      byte 8    : TTL
      byte 9    : protocol (TCP=6, UDP=17, ICMP=1)
      bytes 10-11: header checksum
      bytes 12-15: source IP
      bytes 16-19: destination IP
    """
    if len(data) < 20:
          return 

    # IHL = bottom 4 bits of first byte × 4 = header length in bytes
    # CRITICAL: IP header is NOT always 20 bytes — options can extend it

    ihl = (data[0] & 0x0F) * 4

    ttl      = data[8]
    protocol = data[9]
    src_raw  = data[12:16]
    dst_raw  = data[16:20]

    packet["src_ip"] = socket.inet_ntoa(src_raw)
    packet["dst_ip"] = socket.inet_ntoa(dst_raw)
    packet["ttl"]    = ttl

    ip_payload = data[ihl:]

    if protocol == IP_PROTO_TCP:
        parse_tcp(ip_payload, packet)
    elif protocol == IP_PROTO_UDP:
        parse_udp(ip_payload, packet)
    elif protocol == IP_PROTO_ICMP:
        packet["protocol"] = "ICMP"

def parse_tcp(data, packet):
    """
    TCP header — minimum 20 bytes:
      bytes 0-1 : source port
      bytes 2-3 : destination port
      bytes 4-7 : sequence number
      bytes 8-11: acknowledgment number
      byte 12   : data offset (top 4 bits) — header length in 32-bit words
      byte 13   : flags (URG ACK PSH RST SYN FIN packed into 6 bits)
      bytes 14-15: window size
      bytes 16-17: checksum
      bytes 18-19: urgent pointer
    """
    if len(data) < 20:
        return

    src_port = struct.unpack("!H", data[0:2])[0]
    dst_port = struct.unpack("!H", data[2:4])[0]
    flags_byte = data[13]

    # Each bit in flags_byte is one TCP flag — check with bitmask AND
    flags = []
    if flags_byte & 0x01: flags.append("FIN")
    if flags_byte & 0x02: flags.append("SYN")
    if flags_byte & 0x04: flags.append("RST")
    if flags_byte & 0x08: flags.append("PSH")
    if flags_byte & 0x10: flags.append("ACK")
    if flags_byte & 0x20: flags.append("URG")

    packet["protocol"] = "TCP"
    packet["src_port"] = src_port
    packet["dst_port"] = dst_port
    packet["flags"]    = "|".join(flags)


def parse_udp(data, packet):
    """
    UDP header - always exactly 8 bytes (much simpler than TCP):
     bytes 0-1 : source port
     bytes 2-3 : destination port
     bytes 4-5 : length
     bytes 6-7 : checksum
    NO flags, no sequence numbers, no connection state
    """

    if len(data) < 8:
        return

    src_port = struct.unpack("!H", data[0:2])[0]
    src_port = struct.unpack("!H", data[2:4])[0]

    packet["protocol"] = "UDP"
    packet["src_port"] = src_port
    packet["dst_port"] = dst_port





