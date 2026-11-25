"""Tiny Ethernet/IPv4/TCP packet builder + classic PCAP writer.

Used to generate the built-in samples and the self-test fixtures.  It is
deliberately dependency-free.
"""

from __future__ import annotations

import socket
import struct
from typing import Iterable

from .packet_codec import TCP_ACK, TCP_SYN  # noqa: F401  (re-exported)


def ipv4_bytes(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip)


def build_tcp_packet(
    *,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    seq: int,
    ack: int = 0,
    flags: int = TCP_ACK,
    payload: bytes = b"",
    ttl: int = 64,
    identification: int = 1,
    mtu_payload_cap: int | None = None,
    frag_bits: int = 0,
) -> bytes:
    """Build a full Ethernet frame (without checksums, which are allowed 0)."""
    src_b = ipv4_bytes(src_ip)
    dst_b = ipv4_bytes(dst_ip)

    tcp_hdr_no_opts = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        (5 << 4),          # data offset 5 (20 bytes)
        flags,
        65535,             # window
        0,                 # checksum (not validated by pcapdiff)
        0,                 # urgent pointer
    )
    tcp_segment = tcp_hdr_no_opts + payload

    total_len = 20 + len(tcp_segment)
    ip_hdr = struct.pack(
        "!BBHHHBBH",
        0x45,
        0,
        total_len,
        identification & 0xFFFF,
        frag_bits & 0xFFFF,  # flags + fragment offset
        ttl,
        6,                 # protocol TCP
        0,                 # header checksum left zero
    ) + src_b + dst_b

    eth = (
        b"\x02\x00\x00\x00\x00\x02"   # dst mac
        b"\x02\x00\x00\x00\x00\x01"   # src mac
        b"\x08\x00"                    # EtherType IPv4
    )
    frame = eth + ip_hdr + tcp_segment

    if mtu_payload_cap is not None and len(payload) > mtu_payload_cap:
        raise ValueError("payload exceeds requested cap")
    return frame


def write_classic_pcap(
    path: str,
    frames: Iterable[bytes],
    *,
    linktype: int = 1,
    snaplen: int = 65535,
    little_endian: bool = True,
) -> int:
    """Write frames to a classic microsecond PCAP. Returns frame count."""
    e = "<" if little_endian else ">"
    magic = 0xA1B2C3D4 if little_endian else 0xA1B2C3D4
    # For big-endian the same numeric magic is packed '>' -> a1 b2 c3 d4.
    ghdr = struct.pack(
        e + "IHHiIII",
        magic,
        2,
        4,
        0,
        0,
        snaplen,
        linktype,
    )
    count = 0
    ts = 1_700_000_000
    with open(path, "wb") as fh:
        fh.write(ghdr)
        for frame in frames:
            fh.write(struct.pack(e + "IIII", ts, count * 1000,
                                 len(frame), len(frame)))
            fh.write(frame)
            count += 1
            ts += 1
    return count


def write_pcapng_epb(path: str, frames: Iterable[bytes], *,
                     linktype: int = 1) -> int:
    """Minimal little-endian PCAPNG writer (SHB + IDB + EPB) for tests."""

    def block(btype: int, body: bytes) -> bytes:
        # pad body to a 4-byte boundary
        padded = body + b"\x00" * ((-len(body)) % 4)
        total = 12 + len(padded)
        return struct.pack("<II", btype, total) + padded + struct.pack("<I", total)

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb_body = struct.pack("<HHI", linktype, 0, 65535)

    out = [block(0x0A0D0D0A, shb_body), block(1, idb_body)]
    count = 0
    for frame in frames:
        pad = (-len(frame)) % 4
        epb_body = struct.pack(
            "<IIIII", 0, 0, count, len(frame), len(frame)
        ) + frame + b"\x00" * pad
        out.append(block(6, epb_body))
        count += 1
    with open(path, "wb") as fh:
        fh.write(b"".join(out))
    return count
