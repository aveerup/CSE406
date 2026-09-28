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

    # This lab is Ethernet-only, so a DHCP hardware address must be a MAC.
    if htype != 1 or hlen != 6:
        return None

    magic = struct.unpack("!I", data[_FIXED_LEN:_FIXED_LEN + 4])[0]
    if magic != MAGIC_COOKIE:
        return None

    options = {}
    saw_end = False
    i = _FIXED_LEN + 4
    while i < len(data):
        code = data[i]
        if code == OPT_END:
            saw_end = True
            break
        if code == 0:
            i += 1
            continue
        if i + 2 > len(data):
            return None
        length = data[i + 1]
        if i + 2 + length > len(data):
            return None
        value = data[i + 2:i + 2 + length]
        options[code] = value
        i += 2 + length

    if not saw_end:
        return None

    msg_type = options.get(OPT_MSG_TYPE)
    if msg_type is not None and len(msg_type) != 1:
        return None

    def option_ip(code):
        raw = options.get(code)
        if raw is None:
            return None
        if len(raw) != 4:
            return None
        return socket.inet_ntoa(raw)

    requested_ip = option_ip(OPT_REQUESTED_IP)
    server_id = option_ip(OPT_SERVER_ID)
    if (OPT_REQUESTED_IP in options and requested_ip is None) or (OPT_SERVER_ID in options and server_id is None):
        return None
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
        "requested_ip": requested_ip,
        "server_id": server_id,
    }
