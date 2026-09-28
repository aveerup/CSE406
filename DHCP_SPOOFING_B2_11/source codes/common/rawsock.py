import socket

from .eth import ETHERTYPE_IPV4, parse_eth_header
from .ip import PROTO_UDP, parse_ip_header
from .udp import parse_udp_header

def open_raw_socket(iface: str) -> socket.socket:
    # This project processes only IPv4 DHCP. Limit the protocol at socket
    # creation so unrelated Ethernet traffic is not copied into Python.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4))
    s.bind((iface, 0))
    return s


def try_parse_dhcp_frame(frame: bytes):
    if len(frame) < 14:
        return None
    eth = parse_eth_header(frame)
    if eth["ethertype"] != ETHERTYPE_IPV4:
        return None
    ip = parse_ip_header(eth["payload"])
    if not ip or ip["protocol"] != PROTO_UDP:
        return None
    udp = parse_udp_header(ip["payload"])
    if not udp or (udp["src_port"] not in (67, 68) and udp["dst_port"] not in (67, 68)):
        return None
    return eth, ip, udp
