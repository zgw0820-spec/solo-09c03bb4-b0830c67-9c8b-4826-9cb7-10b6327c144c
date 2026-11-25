"""Classification / alignment / merge behaviour."""

from conftest import (  # type: ignore
    ISN,
    ack_packet,
    all_segments,
    data_packet,
    handshake,
    write_and_analyze,
)
from pcapdiff import (
    CATEGORY_ACKED,
    CATEGORY_CAPTURED,
    CATEGORY_MISSING,
)
from pcapdiff.sample_data import SAMPLES, build_sample


def test_all_three_categories_and_merge(var_dir):
    # Sender: contiguous 0..100 in 25-byte segments + retransmission.
    s = handshake()
    for off in range(0, 100, 25):
        s.append(data_packet(off, 25))
    s.append(data_packet(25, 25))  # retransmit, must not change universe
    s += [ack_packet(40)]

    # Receiver captures [0,30) and [60,80) with different segmentation,
    # ACK boundary at 90.
    r = handshake()
    r.append(data_packet(0, 12))
    r.append(data_packet(12, 18))
    r.append(data_packet(60, 20))
    r.append(ack_packet(90))

    out = write_and_analyze(var_dir, s, r)
    assert out.ok, out.errors
    segs = all_segments(out.run_dir)
    assert segs == [
        (0, 30, CATEGORY_CAPTURED),
        (30, 60, CATEGORY_ACKED),
        (60, 80, CATEGORY_CAPTURED),
        (80, 90, CATEGORY_ACKED),
        (90, 100, CATEGORY_MISSING),
    ]
    assert out.summary["total_bytes"] == 100
    cats = out.summary["categories"]
    assert cats[CATEGORY_CAPTURED]["bytes"] == 50
    assert cats[CATEGORY_ACKED]["bytes"] == 40
    assert cats[CATEGORY_MISSING]["bytes"] == 10


def test_adjacent_same_category_merged_across_evidence_sources(var_dir):
    # Two receiver intervals separated only logically but overlapping via
    # adjacency must become one captured segment.
    s = handshake()
    for off in range(0, 40, 10):
        s.append(data_packet(off, 10))
    r = handshake()
    r.append(data_packet(0, 10))
    r.append(data_packet(10, 10))  # adjacent -> merged union
    r.append(data_packet(20, 10))
    r.append(data_packet(30, 10))
    out = write_and_analyze(var_dir, s, r)
    assert out.ok, out.errors
    segs = all_segments(out.run_dir)
    assert segs == [(0, 40, CATEGORY_CAPTURED)]
    assert out.summary["categories"][CATEGORY_CAPTURED]["ranges"] == 1


def test_no_ack_means_uncaptured_is_missing(var_dir):
    s = handshake() + [data_packet(0, 10), data_packet(10, 10)]
    r = handshake() + [data_packet(0, 10)]
    out = write_and_analyze(var_dir, s, r)
    assert out.ok
    assert all_segments(out.run_dir) == [
        (0, 10, CATEGORY_CAPTURED),
        (10, 20, CATEGORY_MISSING),
    ]


def test_ack_from_sender_file_also_counts(var_dir):
    # Receiver pcap has no ACKs, but the sender-side capture saw the
    # receiver's cumulative ACK up to offset 15.
    s = handshake()
    s += [data_packet(0, 10), data_packet(10, 10), ack_packet(15)]
    r = handshake() + [data_packet(0, 10)]
    out = write_and_analyze(var_dir, s, r)
    assert out.ok
    assert all_segments(out.run_dir) == [
        (0, 10, CATEGORY_CAPTURED),
        (10, 15, CATEGORY_ACKED),
        (15, 20, CATEGORY_MISSING),
    ]
    assert out.meta["ack_boundary"] == 15


def test_sequence_wrap_sample_matches_expectation(var_dir):
    for key in ("basic", "wrap"):
        run_id = f"{key}-run".encode().hex()[:32].ljust(32, "0")
        import os
        from pcapdiff.engine import run_analysis
        rd = os.path.join(var_dir, run_id)
        os.makedirs(rd)
        sp, rp, spec = build_sample(key, os.path.join(rd, "sample"))
        out = run_analysis(run_id, rd, sp, rp)
        assert out.ok, out.errors
        got = all_segments(rd)
        expected = [(e.start, e.end, e.category) for e in SAMPLES[key].expected]
        assert got == expected, key


def test_big_endian_classic_pcap(var_dir):
    s = handshake() + [data_packet(0, 10)]
    out = write_and_analyze(
        var_dir, s, s,
        s_kwargs={"little_endian": False},
        r_kwargs={"little_endian": False},
    )
    assert out.ok, out.errors
    assert all_segments(out.run_dir) == [(0, 10, CATEGORY_CAPTURED)]


def test_one_huge_sender_interval_many_receiver_ranges(var_dir):
    # Contiguous sender stream 0..2m; receiver catches every other 1-byte
    # piece -> thousands of alternations inside a single S union interval.
    m = 3000
    s = handshake()
    # Build contiguous stream using m-byte? Keep packets modest: one-byte
    # segments at every offset would be 2m packets; instead cover contiguous
    # 0..2m with 100-byte segments is awkward for byte granularity.  Use
    # length-2 segments at offsets 0,2,4,... giving contiguous [0,2m).
    for i in range(m):
        s.append(data_packet(i * 2, 2))
    r = handshake()
    for i in range(0, m, 2):
        r.append(data_packet(i * 2, 1))  # catches first byte of every 4 block
    out = write_and_analyze(var_dir, s, r)
    assert out.ok, out.errors
    segs = all_segments(out.run_dir)
    # For i even block: [4k,4k+1) captured, [4k+1,4k+4) missing unless next
    # captured begins at 4k+4 -> so pattern captured(1), missing(3).
    assert segs[0] == (0, 1, CATEGORY_CAPTURED)
    assert segs[1] == (1, 4, CATEGORY_MISSING)
    assert segs[2] == (4, 5, CATEGORY_CAPTURED)
    assert len(segs) == 2 * ((m + 1) // 2)


def test_isn_exactly_ffffffff_wrap(var_dir):
    isn = 0xFFFFFFFF
    s = handshake(isn=isn)
    # base = (isn+1) mod 2^32 = 0; first byte seq 0.
    s.append(data_packet(0, 10, isn=isn))
    s.append(data_packet(10, 10, isn=isn))
    r = handshake(isn=isn) + [data_packet(0, 15, isn=isn)]
    out = write_and_analyze(var_dir, s, r)
    assert out.ok, out.errors
    assert all_segments(out.run_dir) == [
        (0, 15, CATEGORY_CAPTURED),
        (15, 20, CATEGORY_MISSING),
    ]


def test_captured_beyond_ack_boundary_still_captured(var_dir):
    s = handshake()
    s += [data_packet(0, 50), data_packet(50, 50)]
    s += [ack_packet(20)]
    r = handshake()
    r += [data_packet(0, 20), data_packet(90, 10)]  # [90,100) beyond ACK=20
    out = write_and_analyze(var_dir, s, r)
    assert out.ok, out.errors
    segs = all_segments(out.run_dir)
    # 0-20 captured; 20-90 acked only up to... ACK boundary 20, so 20-90
    # missing (no ACK advance); 90-100 captured.
    assert segs == [
        (0, 20, CATEGORY_CAPTURED),
        (20, 90, CATEGORY_MISSING),
        (90, 100, CATEGORY_CAPTURED),
    ]


def test_pcapng_format(var_dir, tmp_path):
    from pcapdiff.pcap_writer import write_pcapng_epb
    s = handshake() + [data_packet(0, 10), data_packet(10, 10)]
    p1 = str(tmp_path / "a.pcapng")
    p2 = str(tmp_path / "b.pcapng")
    write_pcapng_epb(p1, s)
    write_pcapng_epb(p2, handshake() + [data_packet(0, 10)])
    from pcapdiff.engine import create_run_dir, run_analysis
    run_id, rd = create_run_dir(var_dir)
    out = run_analysis(run_id, rd, p1, p2)
    assert out.ok, out.errors
    assert all_segments(rd) == [
        (0, 10, CATEGORY_CAPTURED),
        (10, 20, CATEGORY_MISSING),
    ]
