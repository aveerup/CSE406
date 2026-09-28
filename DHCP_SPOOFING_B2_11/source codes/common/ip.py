import socket
import struct

from .checksum import checksum

IP_HEADER_LEN = 20
PROTO_UDP = 17


def build_ip_header(src_ip: str, dst_ip: str, payload_len: int, ident: int = 0,
                     ttl: int = 64, proto: int = PROTO_UDP) -> bytes:
    version_ihl = (4 << 4) | 5  # IPv4, 5 * 4 = 20-byte header, no options
    tos = 0
    total_length = IP_HEADER_LEN + payload_len
    flags_frag = 0  # no fragmentation
    header_no_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        ident, flags_frag,
        ttl, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    csum = checksum(header_no_checksum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length,
        ident, flags_frag,
        ttl, proto, csum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )


def parse_ip_header(data: bytes) -> dict:
    if len(data) < IP_HEADER_LEN:
        return None
    (version_ihl, tos, total_length, ident, flags_frag, ttl, proto, csum,
     src_ip, dst_ip) = struct.unpack("!BBHHHBBH4s4s", data[:IP_HEADER_LEN])
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_len = ihl * 4
    if version != 4 or ihl < 5 or len(data) < header_len:
        return None
    if total_length < header_len or total_length > len(data):
        return None
    if checksum(data[:header_len]) != 0:
        return None
    # DHCP packets in this lab should not be fragmented. A later fragment does
    # not contain a complete UDP header, so reject fragmented packets.
    if flags_frag & 0x3FFF:
        return None
    return {
        "version": version,
        "header_len": header_len,
        "total_length": total_length,
        "ttl": ttl,
        "protocol": proto,
        "src_ip": socket.inet_ntoa(src_ip),
        "dst_ip": socket.inet_ntoa(dst_ip),
        "payload": data[header_len:total_length] if total_length else data[header_len:],
    }
