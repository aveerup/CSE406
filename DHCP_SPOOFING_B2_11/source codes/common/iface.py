import fcntl
import socket
import struct

SIOCGIFADDR = 0x8915


def get_mac(iface: str) -> str:
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def get_ip(iface: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = fcntl.ioctl(
            s.fileno(),
            SIOCGIFADDR,
            struct.pack("256s", iface[:15].encode("utf-8")),
        )
        return socket.inet_ntoa(packed[20:24])
    finally:
        s.close()
