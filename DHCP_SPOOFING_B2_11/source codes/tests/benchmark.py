import csv
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common import dhcp
from common.checksum import checksum
from common.eth import build_eth_header
from common.ip import build_ip_header
from common.udp import build_udp_header

N = 20_000
CLIENT_MAC = "02:11:22:33:44:55"
ATTACKER_MAC = "02:aa:bb:cc:dd:ee"
XID = 0xDEADBEEF


def timed(label, n, fn):
    start = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - start
    avg_us = (elapsed / n) * 1e6
    print(f"{label:32s} n={n:<8d} total={elapsed:.4f}s avg={avg_us:.3f} us/op")
    return elapsed, avg_us


def build_options():
    return dhcp.build_options(
        dhcp.opt_byte(dhcp.OPT_MSG_TYPE, dhcp.OFFER),
        dhcp.opt_ip(dhcp.OPT_SERVER_ID, "10.0.0.66"),
        dhcp.opt_ip(dhcp.OPT_SUBNET_MASK, "255.255.255.0"),
        dhcp.opt_ip(dhcp.OPT_ROUTER, "10.0.0.66"),
        dhcp.opt_ip(dhcp.OPT_DNS, "10.0.0.66"),
        dhcp.opt_u32(dhcp.OPT_LEASE_TIME, 300),
    )


def build_dhcp_offer_payload():
    return dhcp.build_dhcp_packet(
        op=dhcp.BOOTREPLY, xid=XID, chaddr_mac=CLIENT_MAC, options=build_options(),
        yiaddr="10.0.0.50", siaddr="10.0.0.66",
    )


def build_full_offer_frame():
    payload = build_dhcp_offer_payload()
    udp_h = build_udp_header(67, 68, payload, "10.0.0.66", "255.255.255.255")
    ip_h = build_ip_header("10.0.0.66", "255.255.255.255", len(udp_h) + len(payload))
    eth_h = build_eth_header(CLIENT_MAC, ATTACKER_MAC)
    return eth_h + ip_h + udp_h + payload


def parse_full_offer_frame(frame_cache=[None]):
    if frame_cache[0] is None:
        frame_cache[0] = build_full_offer_frame()
    from common.eth import parse_eth_header
    from common.ip import parse_ip_header
    from common.udp import parse_udp_header
    frame = frame_cache[0]
    eth = parse_eth_header(frame)
    ip_ = parse_ip_header(eth["payload"])
    udp_ = parse_udp_header(ip_["payload"])
    dhcp.parse_dhcp_packet(udp_["payload"])


def main():
    sample_payload = build_dhcp_offer_payload()

    rows = []
    rows.append(("checksum() on ~250B DHCP payload", *timed(
        "checksum() on ~250B payload", N, lambda: checksum(sample_payload))))
    rows.append(("build_eth_header", *timed(
        "build_eth_header", N, lambda: build_eth_header(CLIENT_MAC, ATTACKER_MAC))))
    rows.append(("build_ip_header", *timed(
        "build_ip_header", N, lambda: build_ip_header("10.0.0.66", "255.255.255.255", 250))))
    rows.append(("build_udp_header", *timed(
        "build_udp_header", N, lambda: build_udp_header(67, 68, sample_payload, "10.0.0.66", "255.255.255.255"))))
    rows.append(("build_dhcp_offer_payload", *timed(
        "build_dhcp_offer_payload", N, build_dhcp_offer_payload)))
    rows.append(("build_full_offer_frame (end-to-end forge)", *timed(
        "build_full_offer_frame", N, build_full_offer_frame)))
    rows.append(("parse_full_offer_frame (end-to-end parse)", *timed(
        "parse_full_offer_frame", N, parse_full_offer_frame)))

    out_path = os.path.join(os.path.dirname(__file__), "..", "logs", "benchmark.csv")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["operation", "n_iterations", "total_seconds", "avg_microseconds"])
        for row in rows:
            label, elapsed, avg_us = row
            writer.writerow([label, N, f"{elapsed:.6f}", f"{avg_us:.3f}"])
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
