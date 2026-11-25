"""Shared pytest helpers."""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapdiff.engine import create_run_dir, run_analysis  # noqa: E402
from pcapdiff.pcap_writer import (  # noqa: E402
    build_tcp_packet,
    write_classic_pcap,
)
from pcapdiff.packet_codec import TCP_ACK, TCP_SYN  # noqa: E402

C = "192.168.0.1"
S = "192.168.0.2"
CP = 40000
SP = 80
ISN = 1000
SISN = 5000


def syn_packet(isn: int = ISN):
    return build_tcp_packet(src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
                            seq=isn, flags=TCP_SYN)


def synack_packet(isn: int = ISN, sisn: int = SISN):
    return build_tcp_packet(src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
                            seq=sisn, ack=(isn + 1) & 0xFFFFFFFF,
                            flags=TCP_SYN | TCP_ACK)


def handshake_ack(isn: int = ISN, sisn: int = SISN):
    return build_tcp_packet(src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
                            seq=(isn + 1) & 0xFFFFFFFF,
                            ack=(sisn + 1) & 0xFFFFFFFF, flags=TCP_ACK)


def data_packet(offset: int, length: int = 10, isn: int = ISN,
                payload: bytes | None = None, **kw):
    if payload is None:
        payload = bytes([0x41 + (offset % 26)]) * length
    return build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=(isn + 1 + offset) & 0xFFFFFFFF, ack=SISN + 1,
        flags=TCP_ACK, payload=payload, **kw,
    )


def ack_packet(acked_offset: int, isn: int = ISN):
    return build_tcp_packet(
        src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
        seq=SISN + 1, ack=(isn + 1 + acked_offset) & 0xFFFFFFFF,
        flags=TCP_ACK,
    )


def handshake(isn: int = ISN):
    return [syn_packet(isn), synack_packet(isn), handshake_ack(isn)]


@pytest.fixture()
def var_dir():
    d = tempfile.mkdtemp(prefix="pcapdiff-test-")
    return d


def write_and_analyze(var_dir, sender_frames, receiver_frames,
                      s_kwargs=None, r_kwargs=None):
    run_id, run_dir = create_run_dir(var_dir)
    sp = os.path.join(run_dir, "s.pcap")
    rp = os.path.join(run_dir, "r.pcap")
    write_classic_pcap(sp, sender_frames, **(s_kwargs or {}))
    write_classic_pcap(rp, receiver_frames, **(r_kwargs or {}))
    return run_analysis(run_id, run_dir, sp, rp, "s.pcap", "r.pcap")


def all_segments(run_dir):
    """Return all result segments directly from SQLite, ordered."""
    import sqlite3
    conn = sqlite3.connect(os.path.join(run_dir, "analysis.sqlite"))
    try:
        rows = conn.execute(
            "SELECT start, \"end\", cat FROM segment ORDER BY idx"
        ).fetchall()
    finally:
        conn.close()
    return [(a, b, c) for a, b, c in rows]
