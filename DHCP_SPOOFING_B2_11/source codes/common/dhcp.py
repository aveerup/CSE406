import socket
import struct

from .eth import mac_to_bytes, mac_to_str

SERVER_PORT = 67
CLIENT_PORT = 68
MAGIC_COOKIE = 0x63825363

BOOTREQUEST = 1
BOOTREPLY = 2

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)

MSG_TYPE_NAMES = {
    DISCOVER: "DISCOVER", OFFER: "OFFER", REQUEST: "REQUEST", DECLINE: "DECLINE",
    ACK: "ACK", NAK: "NAK", RELEASE: "RELEASE", INFORM: "INFORM",
}

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_END = 255

_FIXED_FMT = "!BBBBIHH4s4s4s4s16s64s128s"
_FIXED_LEN = struct.calcsize(_FIXED_FMT)  


def opt_byte(code: int, value: int) -> bytes:
    return struct.pack("!BBB", code, 1, value)


def opt_ip(code: int, ip: str) -> bytes:
    raw = socket.inet_aton(ip)
    return struct.pack("!BB", code, len(raw)) + raw


def opt_u32(code: int, value: int) -> bytes:
    return struct.pack("!BBI", code, 4, value)


def build_options(*opts: bytes) -> bytes:
    """Concatenate pre-built TLV options and terminate the list with option 255."""
    return b"".join(opts) + struct.pack("!B", OPT_END)


def build_dhcp_packet(op: int, xid: int, chaddr_mac: str, options: bytes,
                       ciaddr: str = "0.0.0.0", yiaddr: str = "0.0.0.0",
                       siaddr: str = "0.0.0.0", giaddr: str = "0.0.0.0",
                       secs: int = 0, flags: int = 0,
                       htype: int = 1, hlen: int = 6, hops: int = 0) -> bytes:
    chaddr = mac_to_bytes(chaddr_mac).ljust(16, b"\x00")
    fixed = struct.pack(
        _FIXED_FMT,
        op, htype, hlen, hops,
        xid, secs, flags,
        socket.inet_aton(ciaddr), socket.inet_aton(yiaddr),
        socket.inet_aton(siaddr), socket.inet_aton(giaddr),
        chaddr, b"\x00" * 64, b"\x00" * 128,
    )
    return fixed + struct.pack("!I", MAGIC_COOKIE) + options


def parse_dhcp_packet(data: bytes) -> dict:
    if len(data) < _FIXED_LEN + 4:
        return None
    fields = struct.unpack(_FIXED_FMT, data[:_FIXED_LEN])
    (op, htype, hlen, hops, xid, secs, flags,
     ciaddr, yiaddr, siaddr, giaddr, chaddr, _sname, _file) = fields

    magic = struct.unpack("!I", data[_FIXED_LEN:_FIXED_LEN + 4])[0]
    if magic != MAGIC_COOKIE:
        return None

    options = {}
    i = _FIXED_LEN + 4
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            break
        if code == 0:
            i += 1
            continue
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        options[code] = value
        i += 2 + length

    msg_type = options.get(OPT_MSG_TYPE)
    return {
        "op": op,
        "xid": xid,
        "ciaddr": socket.inet_ntoa(ciaddr),
        "yiaddr": socket.inet_ntoa(yiaddr),
        "siaddr": socket.inet_ntoa(siaddr),
        "giaddr": socket.inet_ntoa(giaddr),
        "chaddr": mac_to_str(chaddr[:6]),
        "options": options,
        "msg_type": msg_type[0] if msg_type else None,
        "requested_ip": socket.inet_ntoa(options[OPT_REQUESTED_IP]) if OPT_REQUESTED_IP in options else None,
        "server_id": socket.inet_ntoa(options[OPT_SERVER_ID]) if OPT_SERVER_ID in options else None,
    }
