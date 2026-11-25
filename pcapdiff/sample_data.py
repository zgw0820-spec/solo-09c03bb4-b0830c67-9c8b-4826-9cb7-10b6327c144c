"""Built-in sample captures.

Two deterministic scenarios are generated on demand:

* ``basic`` — three evidence classes, retransmission and different
  segmentation at the receiver.
* ``wrap``  — ISN chosen near 2^32 so sequence numbers wrap mid-stream.

The scenarios are small (a few hundred bytes) but exercise every classifier
branch.  Expected segment lists are exposed for self-tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .packet_codec import TCP_ACK, TCP_SYN
from .pcap_writer import build_tcp_packet, write_classic_pcap

CLIENT = "10.10.0.1"
CLIENT_PORT = 51000
SERVER = "10.10.0.2"
SERVER_PORT = 443


@dataclass(frozen=True)
class ExpectedSegment:
    start: int
    end: int       # exclusive
    category: str


@dataclass(frozen=True)
class SampleSpec:
    key: str
    title: str
    description: str
    isn: int
    total_bytes: int
    expected: tuple[ExpectedSegment, ...]


def _payload(seed: int, length: int) -> bytes:
    # Deterministic byte pattern (content is irrelevant to comparison).
    return bytes((seed + i) & 0xFF for i in range(length))


def _seq(isn: int, offset: int) -> int:
    """TCP sequence number carrying data at byte ``offset``."""
    return (isn + 1 + offset) & 0xFFFFFFFF


def _ack_for_offset(isn: int, acked_offset: int) -> int:
    return (isn + 1 + acked_offset) & 0xFFFFFFFF


def _handshake(isn: int, server_isn: int = 7777):
    syn = build_tcp_packet(
        src_ip=CLIENT, src_port=CLIENT_PORT,
        dst_ip=SERVER, dst_port=SERVER_PORT,
        seq=isn, flags=TCP_SYN,
    )
    synack = build_tcp_packet(
        src_ip=SERVER, src_port=SERVER_PORT,
        dst_ip=CLIENT, dst_port=CLIENT_PORT,
        seq=server_isn, ack=(isn + 1) & 0xFFFFFFFF,
        flags=TCP_SYN | TCP_ACK,
    )
    ack = build_tcp_packet(
        src_ip=CLIENT, src_port=CLIENT_PORT,
        dst_ip=SERVER, dst_port=SERVER_PORT,
        seq=(isn + 1) & 0xFFFFFFFF, ack=(server_isn + 1) & 0xFFFFFFFF,
        flags=TCP_ACK,
    )
    return syn, synack, ack


def _data(offset: int, length: int, isn: int, seed: int = 0) -> bytes:
    return build_tcp_packet(
        src_ip=CLIENT, src_port=CLIENT_PORT,
        dst_ip=SERVER, dst_port=SERVER_PORT,
        seq=_seq(isn, offset),
        ack=7778,
        flags=TCP_ACK | 0x08,  # ACK + PSH
        payload=_payload(seed or (offset // max(length, 1)), length),
    )


def _ack(acked_offset: int, isn: int) -> bytes:
    return build_tcp_packet(
        src_ip=SERVER, src_port=SERVER_PORT,
        dst_ip=CLIENT, dst_port=CLIENT_PORT,
        seq=7778, ack=_ack_for_offset(isn, acked_offset),
        flags=TCP_ACK,
    )


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

BASIC = SampleSpec(
    key="basic",
    title="基础样例：三类证据 + 重传 + 分段不同",
    description=(
        "1000 字节数据流。发端按 100 字节分段并重复发送了 200–300；"
        "收端抓包按 120/130、80/70 等不同边界分段，只直接抓到 "
        "[0,250)、[300,450)、[700,800)，但累计 ACK 推进到 700。"
    ),
    isn=1000,
    total_bytes=1000,
    expected=(
        ExpectedSegment(0, 250, "captured"),
        ExpectedSegment(250, 300, "acked_only"),
        ExpectedSegment(300, 450, "captured"),
        ExpectedSegment(450, 700, "acked_only"),
        ExpectedSegment(700, 800, "captured"),
        ExpectedSegment(800, 1000, "missing"),
    ),
)

WRAP = SampleSpec(
    key="wrap",
    title="序号回绕样例：ISN 接近 2³²",
    description=(
        "ISN=4294967280，数据在偏移 15 处越过 32 位序号边界回绕到 0。"
        "共 300 字节；收端直接抓到 [0,80)、[120,200)，"
        "累计 ACK 推进到 220。"
    ),
    isn=0xFFFFFFF0,
    total_bytes=300,
    expected=(
        ExpectedSegment(0, 80, "captured"),
        ExpectedSegment(80, 120, "acked_only"),
        ExpectedSegment(120, 200, "captured"),
        ExpectedSegment(200, 220, "acked_only"),
        ExpectedSegment(220, 300, "missing"),
    ),
)

SAMPLES = {s.key: s for s in (BASIC, WRAP)}


def build_sample(spec_key: str, out_dir: str) -> tuple[str, str, SampleSpec]:
    """Write ``sender.pcap`` / ``receiver.pcap`` for a sample into out_dir."""
    spec = SAMPLES[spec_key]
    isn = spec.isn
    os.makedirs(out_dir, exist_ok=True)
    sender_path = os.path.join(out_dir, "sender.pcap")
    receiver_path = os.path.join(out_dir, "receiver.pcap")

    syn, synack, hs_ack = _handshake(isn)

    if spec_key == "basic":
        sender_frames = [syn, synack, hs_ack]
        # Ten 100-byte segments + one retransmission of [200,300).
        for off in range(0, 1000, 100):
            sender_frames.append(_data(off, 100, isn, seed=off // 100))
        sender_frames.append(_data(200, 100, isn, seed=2))
        # Cumulative ACKs observed back at the sender.
        for acked in (100, 250, 450, 700):
            sender_frames.append(_ack(acked, isn))

        receiver_frames = [syn, synack, hs_ack]
        # Different segmentation, coverage [0,250), [300,450), [700,800).
        for off, length in ((0, 120), (120, 130),
                             (300, 80), (380, 70),
                             (700, 100)):
            receiver_frames.append(_data(off, length, isn))
        for acked in (250, 450, 700):
            receiver_frames.append(_ack(acked, isn))

    elif spec_key == "wrap":
        sender_frames = [syn, synack, hs_ack]
        for off, length in ((0, 100), (100, 100), (200, 100)):
            sender_frames.append(_data(off, length, isn))
        for acked in (80, 200, 220):
            sender_frames.append(_ack(acked, isn))

        receiver_frames = [syn, synack, hs_ack]
        for off, length in ((0, 80), (120, 80)):
            receiver_frames.append(_data(off, length, isn))
        for acked in (80, 200, 220):
            receiver_frames.append(_ack(acked, isn))
    else:
        raise KeyError(spec_key)

    write_classic_pcap(sender_path, sender_frames)
    write_classic_pcap(receiver_path, receiver_frames)
    return sender_path, receiver_path, spec
