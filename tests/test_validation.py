"""Validation / failure-reason behaviour."""

import os

from conftest import (  # type: ignore
    CP,
    C,
    ISN,
    SP,
    S,
    ack_packet,
    data_packet,
    handshake,
    syn_packet,
    write_and_analyze,
)
from pcapdiff.pcap_writer import build_tcp_packet, write_classic_pcap
from pcapdiff.packet_codec import TCP_SYN


def test_missing_syn_in_receiver(var_dir):
    s = handshake() + [data_packet(0, 10)]
    # Receiver file has data/ACKs but no initial SYN.
    r = [ack_packet(0), data_packet(0, 10)]
    out = write_and_analyze(var_dir, s, r)
    assert not out.ok
    joined = " ".join(out.errors)
    assert "起始 SYN" in joined
    assert "收端" in joined


def test_missing_syn_in_both(var_dir):
    frames = [data_packet(0, 10)]
    out = write_and_analyze(var_dir, frames, frames)
    assert not out.ok
    assert any("发端" in e and "起始 SYN" in e for e in out.errors)
    assert any("收端" in e and "起始 SYN" in e for e in out.errors)


def test_ip_fragment_rejected(var_dir):
    frag = build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=ISN + 1, flags=0x10, payload=b"12345678",
        frag_bits=0x2000,  # MF flag, offset 0
    )
    s = handshake() + [frag]
    r = handshake()
    out = write_and_analyze(var_dir, s, r)
    assert not out.ok
    assert any("IP 分片" in e for e in out.errors)


def test_nonzero_fragment_offset_rejected(var_dir):
    frag = build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=ISN + 1, flags=0x10, payload=b"1234",
        frag_bits=100 // 8,  # offset measured in 8-byte units
    )
    out = write_and_analyze(var_dir, handshake() + [frag], handshake())
    assert not out.ok
    assert any("IP 分片" in e for e in out.errors)


def test_tuple_mismatch(var_dir):
    s = handshake()
    other_syn = build_tcp_packet(
        src_ip="10.0.0.9", src_port=1234, dst_ip="10.0.0.10", dst_port=80,
        seq=42, flags=TCP_SYN,
    )
    r = [other_syn]
    out = write_and_analyze(var_dir, s, r)
    assert not out.ok
    assert any("四元组" in e for e in out.errors)


def test_isn_mismatch(var_dir):
    s = handshake(isn=100)
    r = handshake(isn=200)
    out = write_and_analyze(var_dir, s, r)
    assert not out.ok
    assert any("ISN" in e for e in out.errors)


def test_garbage_file(var_dir, tmp_path):
    p1 = tmp_path / "g1.pcap"
    p2 = tmp_path / "g2.pcap"
    p1.write_bytes(b"not a pcap file at all" * 4)
    p2.write_bytes(b"also not pcap" * 4)
    from pcapdiff.engine import create_run_dir, run_analysis
    run_id, rd = create_run_dir(var_dir)
    out = run_analysis(run_id, rd, str(p1), str(p2))
    assert not out.ok
    assert any("无法识别" in e or "无法解析" in e for e in out.errors)
    # Both files are reported independently.
    assert out.sender_report["readable"] is False
    assert out.receiver_report["readable"] is False


def test_truncated_pcap_header(var_dir, tmp_path):
    p = tmp_path / "t.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)  # short global header
    good = tmp_path / "good.pcap"
    write_classic_pcap(str(good), handshake())
    from pcapdiff.engine import create_run_dir, run_analysis
    run_id, rd = create_run_dir(var_dir)
    out = run_analysis(run_id, rd, str(p), str(good))
    assert not out.ok
    assert "截断" in " ".join(out.errors)


def test_unsupported_linktype(var_dir, tmp_path):
    p1 = tmp_path / "s.pcap"
    p2 = tmp_path / "r.pcap"
    # 105 = IEEE 802.11, not a supported wired link layer.
    write_classic_pcap(str(p1), handshake(), linktype=105)
    write_classic_pcap(str(p2), handshake(), linktype=105)
    from pcapdiff.engine import create_run_dir, run_analysis
    run_id, rd = create_run_dir(var_dir)
    out = run_analysis(run_id, rd, str(p1), str(p2))
    assert not out.ok
    assert any("linktype" in e or "Ethernet" in e for e in out.errors)


def test_raw_ip_linktype_228_accepted(var_dir, tmp_path):
    # Strip the 14-byte Ethernet header and label frames as LINKTYPE_IPV4.
    eth_frames = handshake() + [data_packet(0, 10), data_packet(10, 10)]
    raw_frames = [f[14:] for f in eth_frames]
    p1 = tmp_path / "raw.pcap"
    write_classic_pcap(str(p1), raw_frames, linktype=228)
    from pcapdiff.engine import create_run_dir, run_analysis
    run_id, rd = create_run_dir(var_dir)
    out = run_analysis(run_id, rd, str(p1), str(p1))
    assert out.ok, out.errors
    assert out.summary["total_bytes"] == 20


def _span_pair(var_dir, huge_offset, payload_len=10):
    """SYN then a data segment at a crafted modular offset."""
    s = handshake()
    s.append(data_packet(huge_offset, payload_len))
    return write_and_analyze(var_dir, s, handshake())


def test_span_at_limit_rejected(var_dir):
    # End offset exactly 2 GiB -> strict '< 2 GiB' violated.
    out = _span_pair(var_dir, 2 ** 31 - 10, payload_len=10)
    assert not out.ok
    assert any("2 GiB" in e for e in out.errors)


def test_span_beyond_limit_modular_boundary_rejected(var_dir):
    # seq encodes base + 2^31 exactly (maps to signed -2^31).
    out = _span_pair(var_dir, 2 ** 31, payload_len=100)
    assert not out.ok
    assert any("2 GiB" in e for e in out.errors)


def test_span_just_under_limit_accepted(var_dir):
    out = _span_pair(var_dir, 2 ** 31 - 11, payload_len=10)
    assert out.ok, out.errors
    assert out.meta["sender_span"] == 2 ** 31 - 1


def test_syn_retransmit_dedup_does_not_break_selection(var_dir):
    # Same SYN twice (retransmission) is still one connection candidate.
    s = [syn_packet(), syn_packet()] + handshake()[1:]
    out = write_and_analyze(var_dir, s, handshake())
    assert out.ok, out.errors
