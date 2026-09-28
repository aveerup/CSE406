import socket

from .eth import ETHERTYPE_IPV4, parse_eth_header
from .ip import PROTO_UDP, parse_ip_header
from .udp import parse_udp_header

ETH_P_ALL = 0x0003


def open_raw_socket(iface: str) -> socket.socket:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    return s


def try_parse_dhcp_frame(frame: bytes):
    if len(frame) < 14:
        return None
    eth = parse_eth_header(frame)
    if eth["ethertype"] != ETHERTYPE_IPV4:
        return None
    ip = parse_ip_header(eth["payload"])
    if ip["protocol"] != PROTO_UDP:
        return None
    udp = parse_udp_header(ip["payload"])
    if udp["src_port"] not in (67, 68) and udp["dst_port"] not in (67, 68):
        return None
    return eth, ip, udp
