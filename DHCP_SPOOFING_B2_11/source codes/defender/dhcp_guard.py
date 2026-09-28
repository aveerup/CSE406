import argparse
import atexit
import json
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import dhcp
from common.rawsock import open_raw_socket, try_parse_dhcp_frame

IPTABLES_COMMENT = "dhcp_guard_defense"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [dhcp-guard] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "..", "logs", "dhcp_guard_alerts.log")),
    ],
)
log = logging.getLogger(__name__)


def load_trusted(path: str):
    with open(path) as f:
        data = json.load(f)
    return [(e["mac"].lower(), e["ip"]) for e in data["trusted_servers"]]


def is_trusted(trusted, mac: str, ip: str, server_id) -> bool:
    for tmac, tip in trusted:
        if mac.lower() == tmac and ip == tip and (server_id is None or server_id == tip):
            return True
    return False


class Enforcer:
    def __init__(self, trusted):
        self.trusted = trusted
        self.active = False

    def install(self):
        subprocess.run(
            ["iptables", "-I", "INPUT", "-p", "udp", "--sport", "67",
            "-m", "comment", "--comment", IPTABLES_COMMENT, "-j", "DROP"],
            check=True,
        )
        for mac, _ip in self.trusted:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-p", "udp", "--sport", "67",
                "-m", "mac", "--mac-source", mac,
                "-m", "comment", "--comment", IPTABLES_COMMENT, "-j", "ACCEPT"],
                check=True,
            )
        self.active = True
        log.info("Enforcement ENABLED: only %s may deliver DHCP server replies to this host",
                ", ".join(m for m, _ in self.trusted))

    def remove(self):
        if not self.active:
            return
        while True:
            result = subprocess.run(
                ["bash", "-c",
                 f"iptables -D INPUT $(iptables -L INPUT --line-numbers -n | "
                 f"grep '{IPTABLES_COMMENT}' | head -n1 | awk '{{print $1}}') 2>/dev/null"],
                capture_output=True,
            )
            if result.returncode != 0:
                break
        self.active = False
        log.info("Enforcement rules removed.")


class DHCPGuard:
    def __init__(self, iface, trusted, enforcer):
        self.sock = open_raw_socket(iface)
        self.trusted = trusted
        self.enforcer = enforcer
        self.seen_offers_by_xid = {}  # xid -> set of (mac, ip)

    def handle_server_message(self, eth, ip, pkt):
        mac, src_ip = eth["src_mac"], ip["src_ip"]
        server_id = pkt.get("server_id")
        msg_name = dhcp.MSG_TYPE_NAMES.get(pkt["msg_type"], pkt["msg_type"])

        responders = self.seen_offers_by_xid.setdefault(pkt["xid"], set())
        responders.add((mac, src_ip))
        if len(responders) > 1:
            log.warning(
                "RACE CONDITION: xid=%08x has %d distinct DHCP servers replying (%s) - "
                "likely a rogue server racing the legitimate one",
                pkt["xid"], len(responders), responders,
            )

        if not is_trusted(self.trusted, mac, src_ip, server_id):
            log.warning(
                "ROGUE DHCP %s: src_mac=%s src_ip=%s server_id=%s victim_mac=%s offered_ip=%s "
                "gateway=%s dns=%s -- NOT in trusted_servers.json",
                msg_name, mac, src_ip, server_id, pkt["chaddr"], pkt["yiaddr"],
                _opt_ip(pkt, dhcp.OPT_ROUTER), _opt_ip(pkt, dhcp.OPT_DNS),
            )
        else:
            log.info("Legit DHCP %s from trusted server %s (%s) for victim %s -> %s",
                      msg_name, mac, src_ip, pkt["chaddr"], pkt["yiaddr"])

    def run(self):
        log.info("DHCP Guard watching for rogue DHCP servers (trusted=%s, enforce=%s)",
                  self.trusted, self.enforcer.active)
        while True:
            frame = self.sock.recv(65535)
            parsed = try_parse_dhcp_frame(frame)
            if not parsed:
                continue
            eth, ip, udp = parsed
            if udp["src_port"] != dhcp.SERVER_PORT:
                continue  
            pkt = dhcp.parse_dhcp_packet(udp["payload"])
            if not pkt or pkt["msg_type"] not in (dhcp.OFFER, dhcp.ACK, dhcp.NAK):
                continue
            self.handle_server_message(eth, ip, pkt)


def _opt_ip(pkt, code):
    import socket
    raw = pkt["options"].get(code)
    return socket.inet_ntoa(raw) if raw else None


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iface", required=True)
    p.add_argument("--trusted-file", default=os.path.join(os.path.dirname(__file__), "trusted_servers.json"))
    p.add_argument("--enforce", action="store_true",
                    help="also install iptables rules dropping DHCP replies from untrusted MACs")
    return p.parse_args()


def main():
    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("DHCP Guard needs CAP_NET_RAW (and CAP_NET_ADMIN for --enforce) - run as root.")

    trusted = load_trusted(args.trusted_file)
    if not trusted:
        sys.exit(f"No trusted servers configured in {args.trusted_file}")

    enforcer = Enforcer(trusted)
    if args.enforce:
        enforcer.install()
        atexit.register(enforcer.remove)

    DHCPGuard(args.iface, trusted, enforcer).run()


if __name__ == "__main__":
    main()
