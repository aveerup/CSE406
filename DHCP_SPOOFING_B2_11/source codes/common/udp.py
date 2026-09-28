import socket
import struct

from .checksum import checksum
from .ip import PROTO_UDP

UDP_HEADER_LEN = 8


def build_udp_header(src_port: int, dst_port: int, payload: bytes,
                      src_ip: str, dst_ip: str) -> bytes:
    length = UDP_HEADER_LEN + len(payload)
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, PROTO_UDP, length,
    )
    header_no_checksum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    csum = checksum(pseudo_header + header_no_checksum + payload)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum)


def parse_udp_header(data: bytes) -> dict:
    if len(data) < UDP_HEADER_LEN:
        return None
    src_port, dst_port, length, csum = struct.unpack("!HHHH", data[:UDP_HEADER_LEN])
    if length < UDP_HEADER_LEN or length > len(data):
        return None
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "payload": data[UDP_HEADER_LEN:length] if length else data[UDP_HEADER_LEN:],
    }
