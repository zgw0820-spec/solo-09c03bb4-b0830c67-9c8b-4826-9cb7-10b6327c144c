"""Tests for the sender-side receive-window exhaustion check."""

from __future__ import annotations

import io
import os
import struct

import pytest

from pcapdiff.app import create_app
from pcapdiff.engine import create_run_dir, get_window_page, run_analysis
from pcapdiff.packet_codec import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN
from pcapdiff.pcap_writer import (
    build_tcp_packet,
    write_classic_pcap,
    write_pcapng_epb,
)
from pcapdiff.window_check import (
    KIND_FULL,
    KIND_ZERO,
    analyze_window,
    analyze_window_exhaustion,
)

C = "192.168.0.1"
S = "192.168.0.2"
CP = 40000
SP = 80
ISN = 1000
SISN = 5000
T0 = 1_700_000_000.0
TUPLE = (C, CP, S, SP)


def at(delta: float, pkt: bytes):
    return (pkt, T0 + delta)


def syn_packet(isn: int = ISN, options: bytes = b"") -> bytes:
    return build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=isn, flags=TCP_SYN, options=options,
    )


def synack_packet(win: int = 100, isn: int = ISN, sisn: int = SISN,
                  options: bytes = b"") -> bytes:
    return build_tcp_packet(
        src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
        seq=sisn, ack=(isn + 1) & 0xFFFFFFFF,
        flags=TCP_SYN | TCP_ACK, window=win, options=options,
    )


def hsack_packet(isn: int = ISN, sisn: int = SISN) -> bytes:
    return build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=(isn + 1) & 0xFFFFFFFF, ack=(sisn + 1) & 0xFFFFFFFF,
        flags=TCP_ACK,
    )


def data_packet(off: int, n: int = 10, isn: int = ISN,
                flags: int = TCP_ACK) -> bytes:
    return build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=(isn + 1 + off) & 0xFFFFFFFF, ack=SISN + 1,
        flags=flags, payload=b"x" * n,
    )


def ack_packet(acked_off: int, win: int = 100, isn: int = ISN) -> bytes:
    return build_tcp_packet(
        src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
        seq=SISN + 1, ack=(isn + 1 + acked_off) & 0xFFFFFFFF,
        flags=TCP_ACK, window=win,
    )


def server_data_packet(seq: int, n: int = 10, win: int = 100) -> bytes:
    return build_tcp_packet(
        src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
        seq=seq & 0xFFFFFFFF, ack=(ISN + 1) & 0xFFFFFFFF,
        flags=TCP_ACK, window=win, payload=b"y" * n,
    )


def fin_packet(off_next: int, isn: int = ISN) -> bytes:
    return build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=(isn + 1 + off_next) & 0xFFFFFFFF, ack=SISN + 1,
        flags=TCP_FIN | TCP_ACK,
    )


def rst_packet() -> bytes:
    return build_tcp_packet(
        src_ip=S, src_port=SP, dst_ip=C, dst_port=CP,
        seq=SISN + 1, flags=TCP_RST | TCP_ACK, window=0,
        ack=(ISN + 1) & 0xFFFFFFFF,
    )


def other_conn_packet() -> bytes:
    return build_tcp_packet(
        src_ip="10.9.9.9", src_port=1234, dst_ip="10.8.8.8", dst_port=443,
        seq=1, flags=TCP_ACK,
    )


def write_pcap(path, items, **kw):
    write_classic_pcap(str(path), items, **kw)
    return str(path)


def run_check(path, isn=ISN):
    return analyze_window(path, TUPLE, isn)


def eps(path, isn=ISN):
    rep = run_check(path, isn)
    assert rep.applicable, rep.reasons
    return rep.episodes


# ---------------------------------------------------------------------------
# Core replay semantics
# ---------------------------------------------------------------------------

def test_full_window_episode_recovered_with_duration(tmp_path):
    items = [
        at(0.00, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.10, data_packet(0, 100)),     # frame 4: quota -> 0 (full)
        at(0.20, ack_packet(0, 100)),      # duplicate ACK, stays full
        at(0.50, ack_packet(50, 100)),     # frame 6: opens quota
    ]
    p = write_pcap(tmp_path / "w.pcap", items)
    ep = eps(p)
    assert len(ep) == 1
    e = ep[0]
    assert e.kind == KIND_FULL
    assert (e.start_frame, e.end_frame) == (4, 6)
    assert e.recovered is True
    assert e.end_reason == "recovered"
    assert e.duration_ns == 400_000_000
    assert e.end_window == 100


def test_retransmit_does_not_restart_or_extend_episode(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 100)),       # start frame 4
        at(0.2, data_packet(0, 100)),      # retransmit same bytes
        at(0.3, data_packet(0, 100)),      # another retransmit
        at(0.9, ack_packet(100, 100)),     # recover frame 7
    ]
    p = write_pcap(tmp_path / "r.pcap", items)
    ep = eps(p)
    assert len(ep) == 1
    assert (ep[0].start_frame, ep[0].end_frame) == (4, 7)
    assert ep[0].duration_ns == 800_000_000


def test_zero_window_initial_then_update_recovers(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(0)),
        at(0.02, hsack_packet()),          # initial zero episode starts here
        at(0.20, ack_packet(0, 0)),
        at(0.50, ack_packet(0, 500)),      # WL-equal duplicate ACK updates win
    ]
    p = write_pcap(tmp_path / "z.pcap", items)
    rep = run_check(p)
    assert rep.applicable, rep.reasons
    assert rep.initial_window_raw == 0
    assert len(rep.episodes) == 1
    e = rep.episodes[0]
    assert e.kind == KIND_ZERO
    assert (e.start_frame, e.end_frame) == (3, 5)
    assert e.recovered is True
    assert e.duration_ns == 480_000_000
    assert e.end_window == 500


def test_full_switches_to_zero_and_back(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 100)),      # full start frame 4
        at(0.2, ack_packet(100, 0)),       # frame 5: switch to zero
        at(0.9, ack_packet(100, 800)),     # frame 6: recover
    ]
    p = write_pcap(tmp_path / "sw.pcap", items)
    ep = eps(p)
    assert [e.kind for e in ep] == [KIND_FULL, KIND_ZERO]
    assert (ep[0].start_frame, ep[0].end_frame) == (4, 5)
    assert ep[0].end_reason == "switch"
    assert ep[1].start_frame == 5
    assert (ep[1].start_frame, ep[1].end_frame) == (5, 6)
    assert ep[1].recovered is True


def test_window_scale_both_sides(tmp_path):
    ws_client = b"\x03\x03\x00"           # shift 0 offered
    ws_server = b"\x03\x03\x02"           # shift 2 -> x4
    items = [
        at(0.0, syn_packet(options=ws_client)),
        at(0.01, synack_packet(10, options=ws_server)),  # raw initial = 10
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 10)),       # quota 1+10-11 = 0 full
        at(0.2, ack_packet(0, 10)),       # scaled to 40 -> quota 30
    ]
    p = write_pcap(tmp_path / "ws.pcap", items)
    rep = run_check(p)
    assert rep.applicable, rep.reasons
    assert rep.client_wscale == 0
    assert rep.server_wscale == 2
    assert rep.wscale_negotiated is True
    assert rep.window_shift == 2
    assert rep.initial_window_raw == 10
    assert rep.initial_window_effective == 10  # SYN-ACK never scaled
    assert len(rep.episodes) == 1
    e = rep.episodes[0]
    assert (e.start_frame, e.end_frame) == (4, 5)
    assert e.end_window == 40
    assert e.recovered is True


def test_window_scale_only_one_side_not_applied(tmp_path):
    ws_server = b"\x03\x03\x02"
    items = [
        at(0.0, syn_packet(options=b"")),
        at(0.01, synack_packet(10, options=ws_server)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 10)),
        at(0.2, ack_packet(0, 10)),        # unscaled: quota stays 0
        at(0.3, ack_packet(0, 20)),        # unscaled 20 -> recovers
    ]
    p = write_pcap(tmp_path / "ws1.pcap", items)
    rep = run_check(p)
    assert rep.wscale_negotiated is False
    assert rep.window_shift == 0
    assert len(rep.episodes) == 1
    assert rep.episodes[0].end_window == 20
    assert rep.episodes[0].recovered is True


def test_sequence_number_wrap_supported(tmp_path):
    isn = 0xFFFFFFF0
    items = [
        at(0.0, syn_packet(isn=isn)),
        at(0.01, synack_packet(300, isn=isn)),
        at(0.02, hsack_packet(isn=isn)),
        at(0.1, data_packet(0, 100, isn=isn)),
        at(0.2, data_packet(100, 100, isn=isn)),
        at(0.3, data_packet(200, 100, isn=isn)),   # frame 6 fills 300
        at(0.6, ack_packet(300, 300, isn=isn)),    # wraps ACK, recovers
    ]
    p = write_pcap(tmp_path / "wrap.pcap", items)
    rep = analyze_window(p, TUPLE, isn)
    assert rep.applicable, rep.reasons
    assert len(rep.episodes) == 1
    e = rep.episodes[0]
    assert (e.start_frame, e.end_frame) == (6, 7)
    assert e.recovered is True


def test_fin_while_exhausted_marked_no_recovery(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 100)),
        at(0.4, fin_packet(100)),
    ]
    p = write_pcap(tmp_path / "fin.pcap", items)
    rep = run_check(p)
    assert rep.terminal == "fin"
    assert rep.unrecovered_episodes == 1
    e = rep.episodes[-1]
    assert (e.start_frame, e.end_frame) == (4, 5)
    assert e.end_reason == "fin"
    assert e.recovered is False
    assert e.to_dict()["unrecovered"] is True


def test_rst_while_exhausted_marked_no_recovery(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 100)),
        at(0.2, rst_packet()),
    ]
    p = write_pcap(tmp_path / "rst.pcap", items)
    rep = run_check(p)
    assert rep.terminal == "rst"
    e = rep.episodes[-1]
    assert e.end_reason == "rst"
    assert (e.start_frame, e.end_frame) == (4, 5)


def test_capture_end_uses_last_pcap_frame(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 100)),     # start frame 4
        at(0.2, other_conn_packet()),     # ignored connection, last frame 5
    ]
    p = write_pcap(tmp_path / "end.pcap", items)
    rep = run_check(p)
    assert rep.terminal is None
    assert rep.last_frame == 5
    e = rep.episodes[-1]
    assert (e.start_frame, e.end_frame) == (4, 5)
    assert e.end_reason == "capture_end"
    assert rep.unrecovered_episodes == 1
    assert e.to_dict()["unrecovered"] is True


def test_no_exhaustion_is_applicable_empty(tmp_path):
    items = [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(65535)),
        at(0.02, hsack_packet()),
        at(0.1, data_packet(0, 10)),
        at(0.2, ack_packet(10, 65535)),
    ]
    p = write_pcap(tmp_path / "ok.pcap", items)
    rep = run_check(p)
    assert rep.applicable
    assert rep.episode_count == 0
    assert analyze_window_exhaustion is analyze_window


# ---------------------------------------------------------------------------
# Applicability failures
# ---------------------------------------------------------------------------

def test_pcapng_not_applicable(tmp_path):
    frames = [syn_packet(), synack_packet(), hsack_packet()]
    p = tmp_path / "x.pcapng"
    write_pcapng_epb(str(p), frames)
    rep = run_check(str(p))
    assert rep.applicable is False
    joined = " ".join(rep.reasons)
    assert "经典 PCAP" in joined
    assert "PCAPNG" in joined


def test_non_ethernet_linktype_not_applicable(tmp_path):
    p = write_pcap(tmp_path / "raw.pcap",
                   [syn_packet(), synack_packet(), hsack_packet()],
                   linktype=105)
    rep = run_check(p)
    assert rep.applicable is False
    assert any("Ethernet" in r and "105" in r for r in rep.reasons)


def test_truncated_record_not_applicable(tmp_path):
    p = tmp_path / "trunc.pcap"
    write_pcap(p, [syn_packet(), synack_packet(), hsack_packet(),
                   data_packet(0, 100)])
    raw = bytearray(p.read_bytes())
    # Classic record 1 header starts at 24; incl_len @+8, orig_len @+12.
    raw[36:40] = struct.pack("<I", 99999)   # orig_len > incl_len
    p2 = tmp_path / "trunc-fixed.pcap"
    p2.write_bytes(bytes(raw))
    rep = run_check(str(p2))
    assert rep.applicable is False
    assert any("截断" in r for r in rep.reasons)
    assert rep.first_truncated_frame == 1


def test_incomplete_handshake_not_applicable(tmp_path):
    p = write_pcap(tmp_path / "nohs.pcap",
                   [at(0, syn_packet()), at(0.01, synack_packet(100))])
    rep = run_check(p)
    assert rep.applicable is False
    assert any("握手" in r and "ACK" in r for r in rep.reasons)


def test_handshake_payload_not_applicable(tmp_path):
    payload_syn = build_tcp_packet(
        src_ip=C, src_port=CP, dst_ip=S, dst_port=SP,
        seq=ISN, flags=TCP_SYN, payload=b"abc",
    )
    p = write_pcap(tmp_path / "hsp.pcap", [
        at(0, payload_syn),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
    ])
    rep = run_check(p)
    assert rep.applicable is False
    assert any("载荷" in r for r in rep.reasons)


def test_backward_timestamp_not_applicable(tmp_path):
    p = write_pcap(tmp_path / "time.pcap", [
        at(0.20, syn_packet()),
        at(0.10, synack_packet(100)),   # goes backwards
        at(0.30, hsack_packet()),
    ])
    rep = run_check(p)
    assert rep.applicable is False
    assert rep.backward_timestamps >= 1
    assert any("时间戳" in r and "回拨" in r for r in rep.reasons)


def test_reverse_direction_span_limit_not_applicable(tmp_path):
    huge_seq = SISN + 1 + (2 ** 31 - 10)
    p = write_pcap(tmp_path / "span.pcap", [
        at(0.0, syn_packet()),
        at(0.01, synack_packet(100)),
        at(0.02, hsack_packet()),
        at(0.1, server_data_packet(huge_seq, 100)),
    ])
    rep = run_check(p)
    assert rep.applicable is False
    assert any("2 GiB" in r and "接收方→发起方" in r for r in rep.reasons)


def test_garbage_file_reports_reason(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"nonsense" * 10)
    rep = analyze_window(str(p), TUPLE, ISN)
    assert rep.applicable is False
    assert rep.reasons


# ---------------------------------------------------------------------------
# Engine persistence / pagination + web
# ---------------------------------------------------------------------------

def test_engine_persists_and_paginates_window_episodes(var_dir):
    from pcapdiff.sample_data import build_sample
    rid, rd = create_run_dir(var_dir)
    sp, rp, _ = build_sample("window", rd)
    out = run_analysis(rid, rd, sp, rp)
    assert out.ok, out.errors
    assert out.window["applicable"] is True
    assert out.window["episode_count"] == 4

    p1 = get_window_page(rd, 1, 2)
    assert p1["total_episodes"] == 4
    assert p1["total_pages"] == 2
    assert [i["start_frame"] for i in p1["items"]] == [5, 8]
    p2 = get_window_page(rd, 2, 2)
    assert [i["end_frame"] for i in p2["items"]] == [13, 17]
    zero = get_window_page(rd, 1, 50, "zero")
    assert [i["idx"] for i in zero["items"]] == [3]
    assert zero["items"][0]["kind_label"] == "零窗口"


@pytest.fixture()
def web_client(var_dir):
    app = create_app(var_dir=var_dir)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_window_sample_page_renders_episodes(web_client):
    resp = web_client.get("/sample/window", follow_redirects=True)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'data-testid="window-panel"' in body
    assert "接收窗口耗尽" in body
    assert 'data-testid="window-row"' in body
    assert "未见恢复" in body
    assert "0.300 秒" in body
    assert "1.000 秒" in body


def test_window_pagination_route_and_api(var_dir):
    app = create_app(var_dir=var_dir)
    c = app.test_client()
    from pcapdiff.sample_data import build_sample
    rid, rd = create_run_dir(var_dir)
    sp, rp, _ = build_sample("window", rd)
    run_analysis(rid, rd, sp, rp)

    resp = c.get(f"/r/{rid}?wsize=2&wpage=2")
    body = resp.get_data(as_text=True)
    assert 'data-testid="window-pagination"' in body
    assert "<strong>2</strong> / 2 页" in body

    j = c.get(f"/api/r/{rid}/windows?wkind=zero").get_json()
    assert j["window"]["applicable"] is True
    assert j["window_page"]["total_episodes"] == 1
    assert j["window_page"]["items"][0]["start_frame"] == 11

    j2 = c.get(f"/api/r/{rid}?wsize=2").get_json()
    assert len(j2["window_page"]["items"]) == 2


def test_window_panel_on_failed_comparison(var_dir):
    app = create_app(var_dir=var_dir)
    c = app.test_client()
    from pcapdiff.sample_data import build_sample
    d = os.path.join(var_dir, "src")
    sp, _, _ = build_sample("window", d)
    bad = os.path.join(var_dir, "bad-receiver.pcap")
    with open(bad, "wb") as fh:
        fh.write(b"xxxx" * 30)
    with open(sp, "rb") as f1, open(bad, "rb") as f2:
        resp = c.post("/analyze", data={
            "sender": (io.BytesIO(f1.read()), "s.pcap"),
            "receiver": (io.BytesIO(f2.read()), "r.pcap"),
        }, content_type="multipart/form-data")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "validation-failed" in body
    # Sender-only window check still renders its episodes.
    assert 'data-testid="window-panel"' in body
    assert 'data-testid="window-row"' in body


def test_raw_ip_sender_shows_ethernet_requirement(var_dir):
    """Comparison accepts LINKTYPE_IPV4(228), but the window check does not."""
    app = create_app(var_dir=var_dir)
    c = app.test_client()
    eth = [syn_packet(), synack_packet(100), hsack_packet(),
           data_packet(0, 10)]
    raw = [f[14:] for f in eth]
    p1 = os.path.join(var_dir, "raw-s.pcap")
    p2 = os.path.join(var_dir, "raw-r.pcap")
    write_classic_pcap(p1, raw, linktype=228)
    write_classic_pcap(p2, raw, linktype=228)
    with open(p1, "rb") as f1, open(p2, "rb") as f2:
        resp = c.post("/analyze", data={
            "sender": (io.BytesIO(f1.read()), "raw-s.pcap"),
            "receiver": (io.BytesIO(f2.read()), "raw-r.pcap"),
        }, content_type="multipart/form-data")
    body = resp.get_data(as_text=True)
    assert 'data-testid="result-page"' in body
    assert 'data-testid="window-na"' in body
    assert "Ethernet" in body
