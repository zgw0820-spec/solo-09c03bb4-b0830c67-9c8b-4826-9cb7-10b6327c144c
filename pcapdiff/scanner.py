"""Pass 1: streaming validation / SYN discovery; Pass 2: range extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .pcap_reader import PcapFormatError, PcapReader
from .packet_codec import (
    SUPPORTED_LINKTYPES,
    TCP_ACK,
    TCP_SYN,
    TcpSegment,
    ack_offset,
    decode_frame,
)

# 2 GiB strict upper bound on initiator data span.
SPAN_LIMIT = 2 * 1024 ** 3

# A modular delta in the upper half of the 32-bit space normally means a
# negative offset (e.g. the 1-byte keepalive at seq=ISN -> -1).  Negative
# offsets farther from zero than this tolerance are indistinguishable from a
# forward jump of >= 2 GiB, which the specification forbids.
NEGATIVE_ORIGIN_TOLERANCE = 1 << 20  # 1 MiB

Tuple4 = tuple[str, int, str, int]


def tuple_of(seg: TcpSegment) -> Tuple4:
    return seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port


def reverse_tuple(t: Tuple4) -> Tuple4:
    src_ip, src_port, dst_ip, dst_port = t
    return dst_ip, dst_port, src_ip, src_port


def format_tuple(t: Tuple4) -> str:
    return f"{t[0]}:{t[1]} → {t[2]}:{t[3]}"


@dataclass
class SynCandidate:
    tuple4: Tuple4
    isn: int
    frame_no: int


@dataclass
class ScanReport:
    role: str                 # "sender" / "receiver"
    display_name: str         # original uploaded file name
    path: str
    readable: bool = True
    format_name: str = ""
    linktype: Optional[int] = None
    linktype_ok: bool = True
    error: Optional[str] = None       # fatal format error
    syns: list[SynCandidate] = field(default_factory=list)
    syn_list_truncated: bool = False
    fragmented_packets: int = 0
    first_fragment_frame: Optional[int] = None
    malformed_packets: int = 0
    truncated_packets: int = 0
    frame_count: int = 0

    @property
    def syn_tuples(self) -> list[Tuple4]:
        return [s.tuple4 for s in self.syns]


# Distinct initial SYNs are connection candidates, not packet state.  A
# capture with more than this many *different* SYNs is far outside the
# intended single-connection scope; cap retention so memory stays bounded
# even for a SYN-flood file.  Retransmits of the same tuple+ISN never grow it.
MAX_SYN_CANDIDATES = 4096


def scan_capture(path: str, role: str, display_name: str) -> ScanReport:
    """First pass: format, link layer, fragments and initial SYNs.

    Packets are decoded one at a time; only SYN candidates are retained.
    """
    report = ScanReport(role=role, display_name=display_name, path=path)
    try:
        reader = PcapReader(path)
    except PcapFormatError as exc:
        report.readable = False
        report.error = str(exc)
        return report
    except OSError as exc:
        report.readable = False
        report.error = f"文件无法读取：{exc}"
        return report

    with reader:
        assert reader.info is not None
        report.format_name = reader.info.format_name
        report.linktype = reader.info.linktype
        if reader.info.linktype not in SUPPORTED_LINKTYPES:
            report.linktype_ok = False
            report.error = (
                f"链路层类型 linktype={reader.info.linktype} 暂不支持；"
                "请上传 Ethernet（DLT_EN10MB=1）封装的 PCAP/PCAPNG"
            )
            # Decoders assume a known link layer; stop here.
            return report

        seen_syn_keys: set[tuple[Tuple4, int]] = set()
        linktype = reader.info.linktype
        try:
            for frame in reader.frames():
                report.frame_count = frame.index
                decoded = decode_frame(frame.index, frame.data, linktype)
                if decoded.fragment:
                    report.fragmented_packets += 1
                    if report.first_fragment_frame is None:
                        report.first_fragment_frame = frame.index
                    continue
                if decoded.malformed:
                    report.malformed_packets += 1
                    continue
                seg = decoded.tcp
                if seg is None:
                    continue
                if seg.truncated:
                    report.truncated_packets += 1
                # Initial SYN: SYN set, ACK not set.  Deduplicate retransmits
                # of the same tuple+ISN.
                if (seg.flags & TCP_SYN) and not (seg.flags & TCP_ACK):
                    if len(report.syns) >= MAX_SYN_CANDIDATES:
                        report.syn_list_truncated = True
                        continue
                    t = tuple_of(seg)
                    key = (t, seg.seq)
                    if key not in seen_syn_keys:
                        seen_syn_keys.add(key)
                        report.syns.append(
                            SynCandidate(tuple4=t, isn=seg.seq,
                                         frame_no=frame.index)
                        )
        except PcapFormatError as exc:
            report.readable = False
            report.error = str(exc)
            return report

    return report


@dataclass
class ExtractResult:
    span: int = 0                  # max payload end offset
    min_start: Optional[int] = None
    ack_boundary: int = 0          # max cumulative-ACK offset observed
    fwd_data_packets: int = 0
    fwd_payload_bytes: int = 0
    reverse_ack_packets: int = 0
    span_ok: bool = True
    huge_forward_frame: Optional[int] = None
    huge_forward_delta: Optional[int] = None
    error: Optional[str] = None


def extract_ranges(
    path: str,
    conn: Tuple4,
    isn: int,
    raw_table: str,
    db,
    ack_source: str = "both",
) -> ExtractResult:
    """Second pass for one capture.

    Inserts every forward payload byte-range into ``raw_table``
    ``(start, end)`` (disk-backed SQLite, primary key de-duplicates
    retransmissions) and tracks the largest cumulative ACK from reverse
    packets.  Python-side memory stays at one packet plus scalar state.
    """
    result = ExtractResult()
    rev = reverse_tuple(conn)
    insert_sql = (
        f"INSERT OR IGNORE INTO {raw_table}(start, end) VALUES (?, ?)"
    )
    pending: list[tuple[int, int]] = []
    BATCH = 2000

    def flush() -> None:
        if pending:
            db.executemany(insert_sql, pending)
            pending.clear()

    try:
        reader = PcapReader(path)
    except PcapFormatError as exc:
        result.error = str(exc)
        return result

    with reader:
        if reader.info is None or reader.info.linktype not in SUPPORTED_LINKTYPES:
            result.error = "链路层类型不受支持，无法提取数据区间"
            return result
        linktype = reader.info.linktype
        try:
            for frame in reader.frames():
                decoded = decode_frame(frame.index, frame.data, linktype)
                seg = decoded.tcp
                if seg is None:
                    continue
                t = tuple_of(seg)
                if t == conn:
                    if seg.payload_len > 0:
                        base = (isn + 1) & 0xFFFFFFFF
                        payload_seq = (
                            seg.seq + (1 if seg.flags & TCP_SYN else 0)
                        ) & 0xFFFFFFFF
                        u_delta = (payload_seq - base) & 0xFFFFFFFF

                        if u_delta < SPAN_LIMIT:
                            start = u_delta
                        else:
                            # Upper half: small negative = pre-origin noise;
                            # large negative magnitude = >= 2 GiB forward.
                            signed = u_delta - 0x100000000
                            if signed < -NEGATIVE_ORIGIN_TOLERANCE:
                                result.span_ok = False
                                if result.huge_forward_frame is None:
                                    result.huge_forward_frame = frame.index
                                    result.huge_forward_delta = u_delta
                                continue
                            start = signed

                        end = start + seg.payload_len
                        # Clip to the non-negative offset domain measured
                        # from the initial SYN.
                        if end <= 0:
                            continue
                        if start < 0:
                            start = 0
                        pending.append((start, end))
                        result.fwd_data_packets += 1
                        result.fwd_payload_bytes += seg.payload_len
                        if result.min_start is None or start < result.min_start:
                            result.min_start = start
                        if end > result.span:
                            result.span = end
                        if len(pending) >= BATCH:
                            flush()
                elif t == rev:
                    if seg.flags & TCP_ACK:
                        off = ack_offset(seg.ack, isn)
                        if off > result.ack_boundary:
                            result.ack_boundary = off
                        result.reverse_ack_packets += 1
        except PcapFormatError as exc:
            result.error = str(exc)
            flush()
            return result

    flush()
    if result.huge_forward_frame is not None:
        result.span_ok = False
        result.error = (
            f"第 {result.huge_forward_frame} 帧的序号相对起始 SYN 的前向跨度"
            f"已达到/超过 2 GiB 歧义边界（模 32 位偏移 "
            f"{result.huge_forward_delta}），发起方数据跨度必须严格小于 "
            f"2 GiB（{SPAN_LIMIT:,} 字节）"
        )
    elif result.span >= SPAN_LIMIT:
        result.span_ok = False
        result.error = (
            f"发起方数据跨度约 {result.span:,} 字节，"
            f"达到或超过 2 GiB（{SPAN_LIMIT:,} 字节）上限"
        )
    return result
