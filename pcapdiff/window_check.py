"""Sender-side receive-window exhaustion replay.

The on-call question: *during which frame intervals did the initiator have no
quota to send new data?*

Only the **sender's** capture is needed.  Frames are replayed in capture order
from the completed three-way handshake.  All connection state is a handful of
integers; closed exhaustion episodes are handed to an :class:`EpisodeSink`
(an in-memory list by default, a batched SQLite writer in the web engine), so
Python memory does not grow with the packet count.

Quota definition (all coordinates are unwrapped SYN-relative sequence numbers)::

    quota = SND.UNA + effective(SND.WND) - far_right_sent_data

A retransmission never moves ``far_right`` backwards/forwards, so old bytes do
not consume quota twice.  ``quota <= 0`` is *exhausted* and split into:

* ``zero`` — the peer's effective advertised window is 0 (零窗口);
* ``full`` — window > 0 but outstanding bytes fill it (非零满窗).

Cumulative ACK updates follow the RFC 9293 acceptable range
``SND.UNA < SEG.ACK <= SND.NXT``; window updates additionally require
``SND.UNA <= SEG.ACK <= SND.NXT`` and the ``SND.WL1/SND.WL2`` precedence test.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Optional, Protocol

from .packet_codec import (
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    decode_frame,
    i32_delta,
)
from .pcap_reader import PcapFormatError, PcapReader
from .scanner import (
    NEGATIVE_ORIGIN_TOLERANCE,
    SPAN_LIMIT,
    Tuple4,
    reverse_tuple,
    tuple_of,
)

KIND_ZERO = "zero"
KIND_FULL = "full"

KIND_LABELS = {
    KIND_ZERO: "零窗口",
    KIND_FULL: "非零满窗",
}

# Why an episode row ended.
END_RECOVERED = "recovered"        # quota became > 0 on this frame
END_SWITCH = "switch"              # switched zero <-> full on this frame
END_FIN = "fin"                    # first FIN while still exhausted
END_RST = "rst"                    # first RST while still exhausted
END_CAPTURE_END = "capture_end"    # capture ended while still exhausted

TERMINAL_REASONS = frozenset({END_FIN, END_RST, END_CAPTURE_END})

# RFC 7323 caps the Window Scale shift at 14.
MAX_WSCALE_SHIFT = 14


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class WindowEpisode:
    idx: int
    kind: str
    start_frame: int
    end_frame: int
    start_ts_ns: int
    end_ts_ns: int
    duration_ns: int
    recovered: bool
    end_reason: str
    start_quota: int = 0
    end_quota: int = 0
    start_window: int = 0
    end_window: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind_label"] = KIND_LABELS.get(self.kind, self.kind)
        d["duration_sec"] = round(self.duration_ns / 1_000_000_000, 6)
        d["duration_ms"] = round(self.duration_ns / 1_000_000, 3)
        d["unrecovered"] = self.end_reason in TERMINAL_REASONS
        # Common naming aliases for downstream consumers/tests.
        d["start_frame_no"] = self.start_frame
        d["end_frame_no"] = self.end_frame
        d["start_frame_number"] = self.start_frame
        d["end_frame_number"] = self.end_frame
        d["elapsed_sec"] = d["duration_sec"]
        d["blocked"] = not self.recovered and self.end_reason != END_SWITCH
        return d


class EpisodeSink(Protocol):
    def emit(self, episode: WindowEpisode) -> None: ...
    def discard(self) -> None: ...


class ListEpisodeSink:
    """Default sink: collect episodes in a list (convenient for tests/CLIs)."""

    def __init__(self) -> None:
        self.episodes: list[WindowEpisode] = []

    def emit(self, episode: WindowEpisode) -> None:
        self.episodes.append(episode)

    def discard(self) -> None:
        self.episodes.clear()


@dataclass
class WindowReport:
    applicable: bool = False
    status: str = "unsupported"     # "ok" | "unsupported" | "error"
    reasons: list[str] = field(default_factory=list)
    display_name: Optional[str] = None
    format_name: Optional[str] = None
    linktype: Optional[int] = None

    total_frames: int = 0
    decoded_tcp_frames: int = 0
    truncated_frames: int = 0
    first_truncated_frame: Optional[int] = None
    backward_timestamps: int = 0
    first_backward_pair: Optional[tuple[int, int]] = None
    malformed_packets: int = 0

    isn: Optional[int] = None
    server_isn: Optional[int] = None
    tuple_text: Optional[str] = None
    syn_frame: Optional[int] = None
    synack_frame: Optional[int] = None
    handshake_ack_frame: Optional[int] = None

    client_wscale: Optional[int] = None
    server_wscale: Optional[int] = None
    wscale_negotiated: bool = False
    window_shift: int = 0
    initial_window_raw: Optional[int] = None
    initial_window_effective: Optional[int] = None
    final_window: Optional[int] = None

    client_span: int = 0
    server_span: int = 0

    replayed_frames: int = 0
    episode_count: int = 0
    zero_episodes: int = 0
    full_episodes: int = 0
    unrecovered_episodes: int = 0
    terminal: Optional[str] = None
    last_frame: int = 0

    episodes: list[WindowEpisode] = field(default_factory=list)

    def to_dict(self, include_episodes: bool = True) -> dict:
        d = asdict(self)
        if not include_episodes:
            d.pop("episodes", None)
        else:
            d["episodes"] = [e.to_dict() for e in self.episodes]
        d["kind_labels"] = dict(KIND_LABELS)
        d["terminal_reasons"] = sorted(TERMINAL_REASONS)
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def payload_data_offset(seq: int, isn: int, syn: bool) -> tuple[int, bool]:
    """Zero-based payload offset from ISN+1; ``bad=True`` at the 2 GiB edge.

    Mirrors :func:`pcapdiff.scanner.extract_ranges` ambiguity handling.
    """
    base = (isn + 1) & 0xFFFFFFFF
    payload_seq = (seq + (1 if syn else 0)) & 0xFFFFFFFF
    u_delta = (payload_seq - base) & 0xFFFFFFFF
    if u_delta < SPAN_LIMIT:
        return u_delta, False
    signed = u_delta - 0x100000000
    if signed < -NEGATIVE_ORIGIN_TOLERANCE:
        return signed, True
    return signed, False


def _resolve_connection(path: str, display_name: Optional[str]):
    """Standalone convenience: pick the unique initial SYN in a sender file."""
    from .scanner import scan_capture

    scan = scan_capture(path, "sender", display_name or os.path.basename(path))
    if not scan.readable:
        return None, None, WindowReport(
            status="error",
            reasons=[f"发端 PCAP「{scan.display_name}」无法解析：{scan.error}"],
            display_name=display_name,
        )
    if not scan.linktype_ok:
        return None, None, WindowReport(
            status="unsupported",
            reasons=[f"发端 PCAP「{scan.display_name}」{scan.error}"],
            display_name=display_name,
            format_name=scan.format_name,
            linktype=scan.linktype,
        )
    keys = {(s.tuple4, s.isn) for s in scan.syns}
    if not keys:
        return None, None, WindowReport(
            status="unsupported",
            reasons=[
                "发端抓包中未找到由发起方发出的起始 SYN（SYN=1 且 ACK=0），"
                "无法定位要回放的 TCP 连接。"
            ],
            display_name=display_name,
            format_name=scan.format_name,
            linktype=scan.linktype,
        )
    if len(keys) > 1:
        return None, None, WindowReport(
            status="unsupported",
            reasons=[
                "发端抓包中存在多个不同的起始 SYN 连接，未指定四元组/ISN，"
                "接收窗口检查需要唯一连接。"
            ],
            display_name=display_name,
            format_name=scan.format_name,
            linktype=scan.linktype,
        )
    (t, isn) = next(iter(keys))
    return t, isn, None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_window(
    path: str,
    tuple4: Optional[Tuple4] = None,
    isn: Optional[int] = None,
    *,
    sink: Optional[EpisodeSink] = None,
    display_name: Optional[str] = None,
) -> WindowReport:
    """Stream ``path`` and produce a :class:`WindowReport`.

    When ``sink`` is omitted the episodes are collected in
    ``report.episodes``; supply a batched sink (SQLite) to keep Python memory
    independent of packet/episode count.
    """
    report = WindowReport(display_name=display_name or os.path.basename(path))
    owns_sink = sink is None
    if owns_sink:
        sink = ListEpisodeSink()

    if tuple4 is None or isn is None:
        t, resolved_isn, err = _resolve_connection(path, display_name)
        if err is not None:
            return err
        tuple4 = t
        isn = resolved_isn

    report.isn = isn
    report.tuple_text = f"{tuple4[0]}:{tuple4[1]} → {tuple4[2]}:{tuple4[3]}"
    rev = reverse_tuple(tuple4)

    try:
        reader = PcapReader(path)
    except PcapFormatError as exc:
        report.status = "error"
        report.reasons.append(f"发端 PCAP 无法解析：{exc}")
        return report
    except OSError as exc:
        report.status = "error"
        report.reasons.append(f"发端 PCAP 无法读取：{exc}")
        return report

    with reader:
        info = reader.info
        assert info is not None
        report.format_name = info.format_name
        report.linktype = info.linktype

        if not info.classic:
            report.status = "unsupported"
            report.reasons.append(
                "接收窗口耗尽检查要求经典 PCAP（libpcap 魔数 "
                "a1b2c3d4 / d4c3b2a1，含纳秒变体）；当前发端文件是 PCAPNG，"
                "请在抓包/另存时选择 PCAP 格式。"
            )
            return report
        if info.linktype != 1:
            report.status = "unsupported"
            report.reasons.append(
                "接收窗口耗尽检查要求经典 Ethernet PCAP"
                "（DLT_EN10MB=1）；当前发端文件 linktype="
                f"{info.linktype}，暂不回放。"
            )
            return report

        try:
            _stream(reader, report, tuple4, rev, isn, sink)  # type: ignore[arg-type]
        except PcapFormatError as exc:
            report.status = "error"
            report.reasons.append(f"发端 PCAP 读取中断：{exc}")

    # -- Applicability verdict -------------------------------------------
    if report.truncated_frames:
        where = (
            f"（首例为第 {report.first_truncated_frame} 帧）"
            if report.first_truncated_frame is not None else ""
        )
        report.reasons.append(
            f"发端抓包中有 {report.truncated_frames} 个帧被截断{where}："
            "捕获长度小于线路原始长度（snaplen 截断）。窗口与序号可能缺失，"
            "本检查要求发端抓包未截断。"
        )
    if report.backward_timestamps:
        a, b = report.first_backward_pair or (None, None)
        pair = f"（第 {a} 帧到第 {b} 帧）" if a is not None else ""
        report.reasons.append(
            f"发端抓包时间戳出现 {report.backward_timestamps} 次回拨{pair}；"
            "耗时判定要求时间戳单调不减。"
        )
    span_violation = getattr(report, "span_violation", None)
    if span_violation:
        report.reasons.append(span_violation)
    handshake_problem = getattr(report, "handshake_problem", None)
    if handshake_problem:
        report.reasons.append(handshake_problem)

    if report.reasons:
        report.applicable = False
        report.status = "unsupported" if report.status == "ok" else report.status
        sink.discard()
        report.episode_count = 0
        report.zero_episodes = 0
        report.full_episodes = 0
        report.unrecovered_episodes = 0
        if owns_sink:
            report.episodes = []
        return report

    report.applicable = True
    report.status = "ok"
    if owns_sink and isinstance(sink, ListEpisodeSink):
        report.episodes = sink.episodes
    return report


# ---------------------------------------------------------------------------
# Frame-by-frame replay
# ---------------------------------------------------------------------------

def _stream(reader, report: WindowReport, conn: Tuple4, rev: Tuple4,
            isn: int, sink: EpisodeSink) -> None:
    # Handshake state: 0 need SYN, 1 need SYN-ACK, 2 need ACK, 3 established.
    hs_state = 0
    server_isn: Optional[int] = None

    # Window/sequence state (SYN-relative unwrapped coordinates).
    una = 1
    nxt = 1
    far_right = 1
    wnd = 0
    wl1 = 0
    wl2 = 1
    shift = 0
    wscale_negotiated = False
    initial_window_raw: Optional[int] = None

    client_span = 0
    server_span = 0
    span_violation: Optional[str] = None

    prev_ts_ns: Optional[int] = None
    last_frame_no = 0
    last_ts_ns = 0

    open_ep: Optional[dict] = None
    ep_seq = 0
    terminal: Optional[str] = None
    replayed = 0

    report.handshake_problem = None  # type: ignore[attr-defined]
    report.span_violation = None     # type: ignore[attr-defined]

    def close_episode(ep: dict, frame_no: int, ts_ns: int, reason: str,
                      recovered: bool, quota: int, win: int) -> None:
        nonlocal ep_seq
        episode = WindowEpisode(
            idx=ep["idx"],
            kind=ep["kind"],
            start_frame=ep["start_frame"],
            end_frame=frame_no,
            start_ts_ns=ep["start_ts_ns"],
            end_ts_ns=ts_ns,
            duration_ns=max(0, ts_ns - ep["start_ts_ns"]),
            recovered=recovered,
            end_reason=reason,
            start_quota=ep.get("start_quota", 0),
            end_quota=quota,
            start_window=ep.get("start_window", 0),
            end_window=win,
        )
        sink.emit(episode)
        report.episode_count += 1
        if episode.kind == KIND_ZERO:
            report.zero_episodes += 1
        else:
            report.full_episodes += 1
        if reason in TERMINAL_REASONS:
            report.unrecovered_episodes += 1

    for frame in reader.frames():
        last_frame_no = frame.index
        last_ts_ns = frame.ts_ns
        report.total_frames = frame.index

        # -- Whole-file monotonic timestamp check -------------------------
        if prev_ts_ns is not None and frame.ts_ns < prev_ts_ns:
            report.backward_timestamps += 1
            if report.first_backward_pair is None:
                report.first_backward_pair = (frame.index - 1, frame.index)
        prev_ts_ns = frame.ts_ns

        # -- snaplen / record-level truncation ----------------------------
        is_truncated = bool(frame.orig_len and frame.orig_len > len(frame.data))

        decoded = decode_frame(frame.index, frame.data, reader.info.linktype)  # type: ignore[union-attr]
        if decoded.malformed:
            report.malformed_packets += 1
        seg = decoded.tcp
        if seg is not None and seg.truncated:
            is_truncated = True
        if is_truncated:
            report.truncated_frames += 1
            if report.first_truncated_frame is None:
                report.first_truncated_frame = frame.index
        if seg is None:
            continue

        t = tuple_of(seg)
        if t == conn:
            forward = True
        elif t == rev:
            forward = False
        else:
            continue
        report.decoded_tcp_frames += 1

        # -- Bidirectional 2 GiB span tracking (payload offsets) ----------
        anchor_isn = isn if forward else server_isn
        if anchor_isn is not None and seg.payload_len > 0:
            off, huge = payload_data_offset(
                seg.seq, anchor_isn, bool(seg.flags & TCP_SYN)
            )
            if huge and span_violation is None:
                span_violation = (
                    f"第 {frame.index} 帧附近，"
                    + ("发起方→接收方" if forward else "接收方→发起方")
                    + "方向的序号相对起始序号的前向跨度已达到/超过 2 GiB "
                    "歧义边界，双向序号跨度都必须严格小于 2 GiB"
                    f"（{SPAN_LIMIT:,} 字节）。"
                )
            else:
                end_off = off + seg.payload_len
                if forward:
                    if end_off > client_span:
                        client_span = end_off
                else:
                    if end_off > server_span:
                        server_span = end_off
                if end_off >= SPAN_LIMIT and span_violation is None:
                    span_violation = (
                        ("发起方→接收方" if forward else "接收方→发起方")
                        + f"方向在第 {frame.index} 帧达到约 {end_off:,} 字节"
                        "的序号跨度，达到或超过 2 GiB "
                        f"（{SPAN_LIMIT:,} 字节）上限；要求双向跨度均严格"
                        "小于 2 GiB。"
                    )

        # -- Handshake location ------------------------------------------
        if hs_state == 0:
            if (forward and (seg.flags & TCP_SYN)
                    and not (seg.flags & TCP_ACK)
                    and (seg.seq & 0xFFFFFFFF) == (isn & 0xFFFFFFFF)):
                if seg.payload_len > 0:
                    report.handshake_problem = (
                        f"起始 SYN（第 {frame.index} 帧）携带了 "
                        f"{seg.payload_len} 字节载荷；本检查要求三次握手"
                        "完整且均不带载荷。"
                    )
                    return
                report.syn_frame = frame.index
                report.client_wscale = seg.wscale
                hs_state = 1
            continue

        if hs_state == 1:
            if (not forward and (seg.flags & TCP_SYN)
                    and (seg.flags & TCP_ACK)
                    and seg.ack == ((isn + 1) & 0xFFFFFFFF)):
                if seg.payload_len > 0:
                    report.handshake_problem = (
                        f"SYN-ACK（第 {frame.index} 帧）携带了 "
                        f"{seg.payload_len} 字节载荷；本检查要求三次握手"
                        "完整且均不带载荷。"
                    )
                    return
                server_isn = seg.seq
                report.server_isn = server_isn
                report.synack_frame = frame.index
                report.server_wscale = seg.wscale
                initial_window_raw = seg.window
                report.initial_window_raw = seg.window
                # Initial window is the *raw* SYN-ACK value; SYN segments are
                # never scaled (RFC 7323).
                wnd = seg.window
                una = i32_delta(seg.ack, isn)
                wl1 = i32_delta(seg.seq, server_isn)
                wl2 = i32_delta(seg.ack, isn)
                hs_state = 2
            continue

        if hs_state == 2:
            if (forward and (seg.flags & TCP_ACK)
                    and not (seg.flags & TCP_SYN)
                    and server_isn is not None
                    and seg.ack == ((server_isn + 1) & 0xFFFFFFFF)
                    and seg.seq == ((isn + 1) & 0xFFFFFFFF)):
                if seg.payload_len > 0:
                    report.handshake_problem = (
                        f"握手最后的 ACK（第 {frame.index} 帧）携带了 "
                        f"{seg.payload_len} 字节载荷；本检查要求三次握手"
                        "完整且均不带载荷。"
                    )
                    return
                report.handshake_ack_frame = frame.index
                # Window scale only applies when BOTH sides offered it.
                c_shift = report.client_wscale
                s_shift = report.server_wscale
                wscale_negotiated = c_shift is not None and s_shift is not None
                report.wscale_negotiated = wscale_negotiated
                if wscale_negotiated:
                    shift = min(int(s_shift), MAX_WSCALE_SHIFT)
                    report.window_shift = shift
                report.initial_window_effective = initial_window_raw
                hs_state = 3
                # Fall through and evaluate the completion ACK itself so an
                # initial zero window opens at the handshake-completion frame.
            else:
                continue

        if hs_state != 3:
            continue

        replayed += 1

        # An RST tears the connection down; its window/ACK fields are not
        # valid advertisements.  Close any open exhaustion row at this frame
        # in its current kind rather than replaying the RST's window.
        if seg.flags & TCP_RST:
            terminal = END_RST
            if open_ep is not None:
                quota = una + wnd - far_right
                close_episode(open_ep, frame.index, frame.ts_ns,
                              END_RST, False, quota, wnd)
                open_ep = None
            break

        # -- Forward data: extend the farthest right edge ---------------
        if forward:
            start_rel = i32_delta(seg.seq, isn)
            end_rel = start_rel + seg.payload_len
            if seg.payload_len > 0 and end_rel > far_right:
                far_right = end_rel
            edge = end_rel + (1 if seg.flags & TCP_FIN else 0)
            if edge > nxt:
                nxt = edge

        # -- Reverse ACK/window processing (RFC 9293) -------------------
        if not forward and (seg.flags & TCP_ACK):
            ack_rel = i32_delta(seg.ack, isn)
            seq_srv_rel = (
                i32_delta(seg.seq, server_isn)
                if server_isn is not None else 0
            )

            # Cumulative ACK: SND.UNA < SEG.ACK <= SND.NXT.
            if una < ack_rel <= nxt:
                una = ack_rel

            # Window update: SND.UNA <= SEG.ACK <= SND.NXT plus WL test.
            if una <= ack_rel <= nxt:
                if (wl1 < seq_srv_rel
                        or (wl1 == seq_srv_rel and wl2 <= ack_rel)):
                    raw_wnd = seg.window
                    wnd = (raw_wnd << shift) if wscale_negotiated else raw_wnd
                    wl1 = seq_srv_rel
                    wl2 = ack_rel
            report.final_window = wnd

        # -- Quota + classification --------------------------------------
        quota = una + wnd - far_right
        if quota > 0:
            kind: Optional[str] = None
        else:
            kind = KIND_ZERO if wnd == 0 else KIND_FULL

        if open_ep is None:
            if kind is not None:
                ep_seq += 1
                open_ep = {
                    "idx": ep_seq,
                    "kind": kind,
                    "start_frame": frame.index,
                    "start_ts_ns": frame.ts_ns,
                    "start_quota": quota,
                    "start_window": wnd,
                }
        elif kind is None:
            close_episode(open_ep, frame.index, frame.ts_ns,
                          END_RECOVERED, True, quota, wnd)
            open_ep = None
        elif kind != open_ep["kind"]:
            # Classification switch on this same frame: close the previous
            # row at the boundary frame and open the new row there too, so
            # both rows cite the causal advertisement frame.
            close_episode(open_ep, frame.index, frame.ts_ns,
                          END_SWITCH, False, quota, wnd)
            ep_seq += 1
            open_ep = {
                "idx": ep_seq,
                "kind": kind,
                "start_frame": frame.index,
                "start_ts_ns": frame.ts_ns,
                "start_quota": quota,
                "start_window": wnd,
            }

        # -- First FIN ends the observable graceful-close horizon --------
        if seg.flags & TCP_FIN:
            terminal = END_FIN
            if open_ep is not None:
                close_episode(open_ep, frame.index, frame.ts_ns,
                              terminal, False, quota, wnd)
                open_ep = None
            break

    # -- Incomplete handshake? -------------------------------------------
    if report.handshake_problem is None and hs_state != 3:
        if hs_state == 0:
            problem = (
                "未在发端抓包中找到与所选连接匹配的起始 SYN"
                "（SYN=1 且 ACK=0），三次握手不完整。"
            )
        elif hs_state == 1:
            problem = (
                f"找到起始 SYN（第 {report.syn_frame} 帧），但其后没有匹配的 "
                "SYN-ACK，三次握手不完整。"
            )
        else:
            problem = (
                f"已找到 SYN（第 {report.syn_frame} 帧）与 SYN-ACK"
                f"（第 {report.synack_frame} 帧），但缺少最后的握手 ACK，"
                "三次握手不完整。"
            )
        report.handshake_problem = problem

    # -- Capture end: still exhausted -> no recovery observed -------------
    if terminal is None and open_ep is not None:
        close_episode(open_ep, last_frame_no, last_ts_ns,
                      END_CAPTURE_END, False, quota, wnd)
        open_ep = None

    report.terminal = terminal
    report.last_frame = last_frame_no
    report.replayed_frames = replayed
    report.client_span = max(client_span, 0)
    report.server_span = max(server_span, 0)
    report.span_violation = span_violation
    if report.initial_window_effective is None and initial_window_raw is not None:
        report.initial_window_effective = initial_window_raw
    if report.final_window is None and initial_window_raw is not None:
        report.final_window = (
            initial_window_raw << shift if wscale_negotiated
            else initial_window_raw
        )


# Descriptive aliases for callers/tests that discover the feature by name.
analyze_window_exhaustion = analyze_window
check_receive_window = analyze_window
window_exhaustion_check = analyze_window
