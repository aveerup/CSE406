import struct

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def build_eth_header(dst_mac: str, src_mac: str, ethertype: int = ETHERTYPE_IPV4) -> bytes:
    return struct.pack("!6s6sH", mac_to_bytes(dst_mac), mac_to_bytes(src_mac), ethertype)


def parse_eth_header(frame: bytes) -> dict:
    dst, src, ethertype = struct.unpack("!6s6sH", frame[:ETH_HEADER_LEN])
    return {
        "dst_mac": mac_to_str(dst),
        "src_mac": mac_to_str(src),
        "ethertype": ethertype,
        "payload": frame[ETH_HEADER_LEN:],
    }
