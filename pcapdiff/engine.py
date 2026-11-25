"""Comparison engine.

Pipeline (all packet-sized state is streamed):

1. :func:`scan_capture` validates each file and locates the initial SYN(s).
2. The common 4-tuple / ISN is selected and cross-checked.
3. :func:`extract_ranges` writes per-packet byte ranges into a disk-backed
   SQLite table (primary key de-duplicates retransmissions).
4. Ordered cursors merge raw ranges into disjoint unions.
5. Two ordered union cursors plus the scalar cumulative-ACK boundary produce
   maximal same-category result segments, stored in a ``segment`` table that
   backs pagination.

Python working memory therefore stays O(SQLite page cache + one interval) and
does not grow with packet count.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import (
    CATEGORY_ACKED,
    CATEGORY_CAPTURED,
    CATEGORY_MISSING,
    CATEGORY_LABELS,
)
from .scanner import (
    SPAN_LIMIT,
    ExtractResult,
    ScanReport,
    SynCandidate,
    extract_ranges,
    format_tuple,
    scan_capture,
)
from .window_check import (
    KIND_LABELS as WINDOW_KIND_LABELS,
)
from .window_check import (
    TERMINAL_REASONS as WINDOW_TERMINAL_REASONS,
)
from .window_check import WindowEpisode, WindowReport, analyze_window
from .window_check import analyze_window_exhaustion  # re-exported alias

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 10000


# ---------------------------------------------------------------------------
# Run storage
# ---------------------------------------------------------------------------

def default_var_dir() -> str:
    env = os.environ.get("PCAPDIFF_VAR_DIR")
    if env:
        return env
    candidate = os.path.join(os.path.dirname(os.path.dirname(__file__)), "var")
    try:
        os.makedirs(candidate, exist_ok=True)
        testfile = os.path.join(candidate, ".write-test")
        with open(testfile, "w") as fh:
            fh.write("ok")
        os.remove(testfile)
        return candidate
    except OSError:
        path = os.path.join("/tmp", "pcapdiff-var")
        os.makedirs(path, exist_ok=True)
        return path


def create_run_dir(var_dir: str) -> tuple[str, str]:
    run_id = uuid.uuid4().hex
    run_dir = os.path.join(var_dir, "runs", run_id)
    os.makedirs(run_dir, exist_ok=False)
    return run_id, run_dir


def db_path(run_dir: str) -> str:
    return os.path.join(run_dir, "analysis.sqlite")


# ---------------------------------------------------------------------------
# Outcome structures
# ---------------------------------------------------------------------------

@dataclass
class AnalysisOutcome:
    run_id: str
    run_dir: str
    ok: bool = False
    errors: list[str] = field(default_factory=list)
    sender_report: Optional[dict] = None
    receiver_report: Optional[dict] = None
    meta: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    window: Optional[dict] = None

    def to_jsonable(self) -> dict:
        return {
            "run_id": self.run_id,
            "ok": self.ok,
            "errors": self.errors,
            "sender": self.sender_report,
            "receiver": self.receiver_report,
            "meta": self.meta,
            "summary": self.summary,
            "window": self.window,
        }


def _report_to_dict(r: ScanReport) -> dict:
    d = asdict(r)
    # Flatten SYN candidates to readable JSON.
    d["syns"] = [
        {
            "tuple": format_tuple(s.tuple4),
            "isn": s.isn,
            "frame_no": s.frame_no,
        }
        for s in r.syns
    ]
    d["tuple_text"] = format_tuple(r.syns[0].tuple4) if r.syns else None
    return d


# ---------------------------------------------------------------------------
# Connection selection
# ---------------------------------------------------------------------------

def _choose_connection(
    s_scan: ScanReport, r_scan: ScanReport, errors: list[str]
) -> Optional[SynCandidate]:
    s_map: dict = {}
    for syn in s_scan.syns:
        s_map.setdefault(syn.tuple4, syn)
    r_map: dict = {}
    for syn in r_scan.syns:
        r_map.setdefault(syn.tuple4, syn)

    common = [t for t in s_map if t in r_map]

    if not common:
        errors.append(
            "两份抓包没有共同的、由发起方发出的起始 SYN 四元组，"
            "无法认定为同一条 IPv4 TCP 连接。"
        )
        if s_map:
            errors.append(
                "发端文件中的起始 SYN："
                + "；".join(format_tuple(t) for t in list(s_map)[:5])
            )
        if r_map:
            errors.append(
                "收端文件中的起始 SYN："
                + "；".join(format_tuple(t) for t in list(r_map)[:5])
            )
        return None

    if len(common) > 1:
        errors.append(
            "两份抓包中存在多个相同的起始 SYN 四元组，无法唯一确定连接："
            + "；".join(format_tuple(t) for t in common[:5])
            + (" …" if len(common) > 5 else "")
        )
        return None

    t = common[0]
    s_syn = s_map[t]
    r_syn = r_map[t]
    if s_syn.isn != r_syn.isn:
        errors.append(
            "两份抓包中起始 SYN 的初始序号（ISN）不一致："
            f"发端为 {s_syn.isn}（0x{s_syn.isn:08X}），"
            f"收端为 {r_syn.isn}（0x{r_syn.isn:08X}），"
            "请确认两份文件来自同一条连接的同一方向起点。"
        )
        return None
    return s_syn


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    # WAL lets the writer commit while two ordered read cursors are open.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA cache_size=-2048")  # ~2 MiB page cache cap
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    # WITHOUT ROWID primary key gives ordered scans without a sort step and
    # de-duplicates identical retransmitted ranges on insert.
    conn.execute(
        "CREATE TABLE s_raw ("
        "start INTEGER NOT NULL, \"end\" INTEGER NOT NULL, "
        "PRIMARY KEY(start, \"end\")) WITHOUT ROWID"
    )
    conn.execute(
        "CREATE TABLE r_raw ("
        "start INTEGER NOT NULL, \"end\" INTEGER NOT NULL, "
        "PRIMARY KEY(start, \"end\")) WITHOUT ROWID"
    )
    conn.execute(
        "CREATE TABLE s_union ("
        "start INTEGER PRIMARY KEY, \"end\" INTEGER NOT NULL) WITHOUT ROWID"
    )
    conn.execute(
        "CREATE TABLE r_union ("
        "start INTEGER PRIMARY KEY, \"end\" INTEGER NOT NULL) WITHOUT ROWID"
    )
    conn.execute(
        "CREATE TABLE segment ("
        "idx INTEGER PRIMARY KEY, start INTEGER NOT NULL, "
        "\"end\" INTEGER NOT NULL, bytes INTEGER NOT NULL, "
        "cat TEXT NOT NULL)"
    )
    # Receive-window exhaustion episodes (streamed from the sender PCAP once,
    # paginated forever without re-reading the capture).
    conn.execute(
        "CREATE TABLE win_episode ("
        "idx INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
        "start_frame INTEGER NOT NULL, end_frame INTEGER NOT NULL, "
        "start_ts_ns INTEGER NOT NULL, end_ts_ns INTEGER NOT NULL, "
        "duration_ns INTEGER NOT NULL, recovered INTEGER NOT NULL, "
        "end_reason TEXT NOT NULL, start_quota INTEGER NOT NULL DEFAULT 0, "
        "end_quota INTEGER NOT NULL DEFAULT 0, "
        "start_window INTEGER NOT NULL DEFAULT 0, "
        "end_window INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()


def _build_union(conn: sqlite3.Connection, raw: str, union: str) -> int:
    """Merge ordered raw ranges into maximal disjoint intervals."""
    cur = conn.execute(
        f"SELECT start, \"end\" FROM {raw} ORDER BY start, \"end\""
    )
    out_rows: list[tuple[int, int]] = []
    cur_start: Optional[int] = None
    cur_end: Optional[int] = None
    interval_count = 0

    def flush_batch() -> None:
        nonlocal out_rows
        if out_rows:
            conn.executemany(
                f"INSERT INTO {union}(start, \"end\") VALUES (?, ?)", out_rows
            )
            out_rows = []

    for start, end in cur:
        if end is None or start is None or end <= start:
            continue
        if cur_start is None:
            cur_start, cur_end = start, end
        elif start <= cur_end:  # overlap or adjacency -> same union run
            if end > cur_end:
                cur_end = end
        else:
            out_rows.append((cur_start, cur_end))
            interval_count += 1
            if len(out_rows) >= 1000:
                flush_batch()
            cur_start, cur_end = start, end

    if cur_start is not None:
        out_rows.append((cur_start, cur_end))
        interval_count += 1
    flush_batch()
    conn.commit()
    return interval_count


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _peek_next(cur) -> Optional[tuple[int, int]]:
    row = cur.fetchone()
    if row is None:
        return None
    return row[0], row[1]


def classify_and_store(db_file: str, ack_boundary: int) -> dict:
    """Two-pointer streaming classification of S-union vs R-union + ACK."""
    conn_s = _connect(db_file)
    conn_r = _connect(db_file)
    conn_w = _connect(db_file)

    cur_s = conn_s.execute("SELECT start, \"end\" FROM s_union ORDER BY start")
    cur_r = conn_r.execute("SELECT start, \"end\" FROM r_union ORDER BY start")
    r_next = _peek_next(cur_r)

    seg_idx = 0
    last: Optional[list] = None  # current open segment [start, end, cat]
    batch: list[tuple] = []
    FLUSH_AT = 1000

    def flush_batch() -> None:
        if batch:
            conn_w.executemany(
                "INSERT INTO segment(idx,start,\"end\",bytes,cat)"
                " VALUES (?,?,?,?,?)",
                batch,
            )
            conn_w.commit()
            batch.clear()

    def append_segment(start: int, end: int, cat: str) -> None:
        # Called in sequence order.  Only the single open segment is kept in
        # Python; every FLUSH_AT closed rows are spilled to SQLite, so even
        # one enormous sender interval cannot grow the batch with packet count.
        nonlocal seg_idx, last
        if end <= start:
            return
        if last is not None and last[2] == cat and last[1] == start:
            last[1] = end  # merge adjacent same-category range
            return
        if last is not None:
            batch.append(
                (seg_idx, last[0], last[1], last[1] - last[0], last[2])
            )
            seg_idx += 1
            if len(batch) >= FLUSH_AT:
                flush_batch()
        last = [start, end, cat]

    for s_start, s_end in cur_s:
        pos = s_start
        while pos < s_end:
            # Drop receiver intervals that end at or before pos.
            while r_next is not None and r_next[1] <= pos:
                r_next = _peek_next(cur_r)

            if r_next is not None and r_next[0] <= pos < r_next[1]:
                # pos lies inside a receiver-captured union interval.
                piece_end = min(s_end, r_next[1])
                append_segment(pos, piece_end, CATEGORY_CAPTURED)
                pos = piece_end
            else:
                # Uncovered gap until the next receiver interval (or the
                # end of this sender interval); ACK boundary splits it.
                if r_next is not None and r_next[0] > pos:
                    gap_end = min(s_end, r_next[0])
                else:
                    gap_end = s_end
                _classify_ack_gap(pos, gap_end, ack_boundary, append_segment)
                pos = gap_end

    if last is not None:
        batch.append((seg_idx, last[0], last[1], last[1] - last[0], last[2]))
        seg_idx += 1
    flush_batch()

    summary = _build_summary(conn_w, seg_idx)
    for c in (conn_s, conn_r, conn_w):
        c.close()
    return summary


def _classify_ack_gap(pos, end, ack_boundary, append_segment) -> None:
    if end <= ack_boundary:
        append_segment(pos, end, CATEGORY_ACKED)
    elif pos >= ack_boundary:
        append_segment(pos, end, CATEGORY_MISSING)
    else:
        append_segment(pos, ack_boundary, CATEGORY_ACKED)
        append_segment(ack_boundary, end, CATEGORY_MISSING)


def _build_summary(conn: sqlite3.Connection, total_segments: int) -> dict:
    rows = conn.execute(
        "SELECT cat, COUNT(*), COALESCE(SUM(bytes), 0) FROM segment"
        " GROUP BY cat"
    ).fetchall()
    per_cat = {
        cat: {"ranges": 0, "bytes": 0, "label": CATEGORY_LABELS[cat]}
        for cat in (CATEGORY_CAPTURED, CATEGORY_ACKED, CATEGORY_MISSING)
    }
    for cat, count, nbytes in rows:
        per_cat[cat]["ranges"] = count
        per_cat[cat]["bytes"] = nbytes

    total_bytes = sum(v["bytes"] for v in per_cat.values())
    for cat, v in per_cat.items():
        v["percent"] = round(100.0 * v["bytes"] / total_bytes, 2) if total_bytes else 0.0

    return {
        "total_bytes": total_bytes,
        "total_ranges": total_segments,
        "categories": per_cat,
    }


# ---------------------------------------------------------------------------
# Pagination queries
# ---------------------------------------------------------------------------

def get_page(
    run_dir: str,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    category: Optional[str] = None,
) -> dict:
    page_size = max(1, min(int(page_size or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))
    page = max(1, int(page or 1))
    conn = _connect(db_path(run_dir))
    try:
        where = ""
        params_count: tuple = ()
        params_page: tuple
        if category in CATEGORY_LABELS:
            where = "WHERE cat = ?"
            params_count = (category,)

        total = conn.execute(
            f"SELECT COUNT(*) FROM segment {where}", params_count
        ).fetchone()[0]
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = min(page, total_pages)
        offset = (page - 1) * page_size

        rows = conn.execute(
            "SELECT idx, start, \"end\", bytes, cat FROM segment "
            f"{where} ORDER BY idx LIMIT ? OFFSET ?",
            (*params_count, page_size, offset),
        ).fetchall()

        items = [
            {
                "idx": idx,
                # Canonical: zero-based payload byte offsets (first data
                # byte after SYN is offset 0), half-open [start, end).
                "start": start,
                "end": end,            # exclusive
                "last": end - 1,       # inclusive
                "length": nbytes,
                # Wireshark-style relative sequence numbers where SYN is 0:
                # first data byte is 1.  Inclusive seq range [seq_start,
                # seq_last]; half-open seq interval [seq_start, seq_end).
                "seq_start": start + 1,
                "seq_last": end,
                "seq_end": end + 1,
                "category": cat,
                "label": CATEGORY_LABELS[cat],
            }
            for idx, start, end, nbytes, cat in rows
        ]
        meta_rows = conn.execute("SELECT k, v FROM meta").fetchall()
        meta = {k: _loads(v) for k, v in meta_rows}
        summary = meta.get("summary_obj", {})
        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_ranges": total,
            "category": category or "",
            "meta": {k: v for k, v in meta.items() if k != "summary_obj"},
            "summary": summary,
        }
    finally:
        conn.close()


def _loads(v: str):
    try:
        return json.loads(v)
    except (ValueError, TypeError):
        return v


# ---------------------------------------------------------------------------
# Receive-window exhaustion storage / pagination
# ---------------------------------------------------------------------------

class SQLiteEpisodeSink:
    """Batched episode writer; Python holds at most ~1000 rows."""

    FLUSH_AT = 1000

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.batch: list[tuple] = []

    def emit(self, ep: WindowEpisode) -> None:
        self.batch.append((
            ep.idx, ep.kind, ep.start_frame, ep.end_frame,
            ep.start_ts_ns, ep.end_ts_ns, ep.duration_ns,
            1 if ep.recovered else 0, ep.end_reason,
            ep.start_quota, ep.end_quota,
            ep.start_window, ep.end_window,
        ))
        if len(self.batch) >= self.FLUSH_AT:
            self.flush()

    def flush(self) -> None:
        if self.batch:
            self.conn.executemany(
                "INSERT INTO win_episode(idx, kind, start_frame, end_frame,"
                " start_ts_ns, end_ts_ns, duration_ns, recovered, end_reason,"
                " start_quota, end_quota, start_window, end_window)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                self.batch,
            )
            self.conn.commit()
            self.batch.clear()

    def discard(self) -> None:
        self.batch.clear()
        self.conn.execute("DELETE FROM win_episode")
        self.conn.commit()


def _duration_text(duration_ns: int) -> str:
    if duration_ns < 1_000:
        return "0 秒"
    if duration_ns < 1_000_000_000:
        ms = duration_ns / 1_000_000
        if abs(ms - round(ms)) < 0.05:
            return f"{round(ms)} 毫秒"
        return f"{ms:.1f} 毫秒"
    return f"{duration_ns / 1_000_000_000:.3f} 秒"


def win_table_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table'"
        " AND name='win_episode'"
    ).fetchone() is not None


def get_window_page(
    run_dir: str,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    kind: Optional[str] = None,
) -> dict:
    """Paginate stored window episodes without touching the PCAP."""
    page_size = max(1, min(int(page_size or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))
    page = max(1, int(page or 1))
    empty = {
        "items": [], "page": 1, "page_size": page_size,
        "total_pages": 1, "total_episodes": 0, "kind": kind or "",
        "kind_labels": WINDOW_KIND_LABELS,
    }
    path = db_path(run_dir)
    if not os.path.exists(path):
        return empty
    conn = _connect(path)
    try:
        if not win_table_exists(conn):
            return empty
        where = ""
        params_count: tuple = ()
        if kind in WINDOW_KIND_LABELS:
            where = "WHERE kind = ?"
            params_count = (kind,)
        total = conn.execute(
            f"SELECT COUNT(*) FROM win_episode {where}", params_count
        ).fetchone()[0]
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = min(page, total_pages)
        offset = (page - 1) * page_size
        rows = conn.execute(
            "SELECT idx, kind, start_frame, end_frame, start_ts_ns,"
            " end_ts_ns, duration_ns, recovered, end_reason,"
            " start_quota, end_quota, start_window, end_window"
            " FROM win_episode " + where +
            " ORDER BY idx LIMIT ? OFFSET ?",
            (*params_count, page_size, offset),
        ).fetchall()
        items = []
        for (idx, k, sf, ef, sts, ets, dur, rec, reason,
             sq, eq, sw, ew) in rows:
            items.append({
                "idx": idx,
                "kind": k,
                "kind_label": WINDOW_KIND_LABELS.get(k, k),
                "start_frame": sf,
                "end_frame": ef,
                "start_frame_no": sf,
                "end_frame_no": ef,
                "start_ts_ns": sts,
                "end_ts_ns": ets,
                "duration_ns": dur,
                "duration_ms": round(dur / 1_000_000, 3),
                "duration_sec": round(dur / 1_000_000_000, 6),
                "elapsed_sec": round(dur / 1_000_000_000, 6),
                "duration_text": _duration_text(dur),
                "recovered": bool(rec),
                "end_reason": reason,
                "unrecovered": reason in WINDOW_TERMINAL_REASONS,
                "start_quota": sq,
                "end_quota": eq,
                "start_window": sw,
                "end_window": ew,
            })
        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_episodes": total,
            "kind": kind or "",
            "kind_labels": WINDOW_KIND_LABELS,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def run_analysis(
    run_id: str,
    run_dir: str,
    sender_path: str,
    receiver_path: str,
    sender_name: str = "sender.pcap",
    receiver_name: str = "receiver.pcap",
) -> AnalysisOutcome:
    outcome = AnalysisOutcome(run_id=run_id, run_dir=run_dir)
    errors: list[str] = []

    # Pass 1 — validate both files fully before any comparison result.
    s_scan = scan_capture(sender_path, "sender", sender_name)
    r_scan = scan_capture(receiver_path, "receiver", receiver_name)
    outcome.sender_report = _report_to_dict(s_scan)
    outcome.receiver_report = _report_to_dict(r_scan)

    for scan, cn in ((s_scan, "发端"), (r_scan, "收端")):
        if not scan.readable:
            errors.append(f"{cn}文件「{scan.display_name}」无法解析：{scan.error}")
        elif not scan.linktype_ok:
            errors.append(f"{cn}文件「{scan.display_name}」{scan.error}")
        else:
            if scan.fragmented_packets:
                errors.append(
                    f"{cn}文件「{scan.display_name}」中发现 "
                    f"{scan.fragmented_packets} 个带 IP 分片的数据包"
                    f"（首例为第 {scan.first_fragment_frame} 帧），"
                    "本工具要求抓包中不存在 IP 分片。"
                )
            if not scan.syns:
                errors.append(
                    f"{cn}文件「{scan.display_name}」中未找到由发起方发出的"
                    "起始 SYN（SYN=1 且 ACK=0）IPv4 TCP 数据包。"
                )

    chosen: Optional[SynCandidate] = None
    if s_scan.readable and r_scan.readable and s_scan.syns and r_scan.syns:
        chosen = _choose_connection(s_scan, r_scan, errors)

    # The run DB (including the window-episode table) exists even when the
    # byte comparison fails validation, so the sender-only window check can
    # still render/paginate its result.
    db_file = db_path(run_dir)
    if os.path.exists(db_file):
        os.remove(db_file)
    conn = _connect(db_file)
    _init_db(conn)

    win_tuple = chosen.tuple4 if chosen is not None else None
    win_isn = chosen.isn if chosen is not None else None
    if win_tuple is None and len(s_scan.syns) == 1:
        only_syn = s_scan.syns[0]
        win_tuple, win_isn = only_syn.tuple4, only_syn.isn

    win_sink = SQLiteEpisodeSink(conn)
    try:
        win_report = analyze_window(
            sender_path, win_tuple, win_isn,
            sink=win_sink, display_name=sender_name,
        )
        win_sink.flush()
        if not win_report.applicable:
            win_sink.discard()
    except Exception as exc:  # defensive: side check never breaks comparison
        win_sink.discard()
        win_report = WindowReport(
            applicable=False,
            status="error",
            display_name=sender_name,
            reasons=[f"接收窗口耗尽检查执行失败：{type(exc).__name__}: {exc}"],
        )
    outcome.window = win_report.to_dict(include_episodes=False)
    conn.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES ('window_obj', ?)",
        (json.dumps(outcome.window, ensure_ascii=False),),
    )
    conn.commit()

    if errors or chosen is None:
        conn.close()
        outcome.ok = False
        outcome.errors = errors or ["校验未通过，未进行比对。"]
        _write_report_json(outcome)
        return outcome

    # Pass 2 — extract ranges into SQLite.
    s_extract = extract_ranges(
        sender_path, chosen.tuple4, chosen.isn, "s_raw", conn
    )
    r_extract = extract_ranges(
        receiver_path, chosen.tuple4, chosen.isn, "r_raw", conn
    )
    conn.commit()

    for ext, cn, scan in (
        (s_extract, "发端", s_scan),
        (r_extract, "收端", r_scan),
    ):
        if ext.error and not ext.span_ok:
            errors.append(f"{cn}文件「{scan.display_name}」{ext.error}。")
        elif ext.error:
            errors.append(f"{cn}文件「{scan.display_name}」提取区间失败：{ext.error}")

    if errors:
        conn.close()
        outcome.ok = False
        outcome.errors = errors
        _write_report_json(outcome)
        return outcome

    s_intervals = _build_union(conn, "s_raw", "s_union")
    r_intervals = _build_union(conn, "r_raw", "r_union")
    conn.close()

    # Cumulative ACK evidence from BOTH captures (receiver -> sender).
    ack_boundary = max(s_extract.ack_boundary, r_extract.ack_boundary)
    # Never let a stale/odd ACK go below zero evidence semantics.
    ack_boundary = max(0, ack_boundary)

    summary = classify_and_store(db_file, ack_boundary)

    meta = {
        "tuple": format_tuple(chosen.tuple4),
        "isn": chosen.isn,
        "isn_hex": f"0x{chosen.isn:08X}",
        "span_limit": SPAN_LIMIT,
        "ack_boundary": ack_boundary,
        "ack_boundary_from_sender_file": s_extract.ack_boundary,
        "ack_boundary_from_receiver_file": r_extract.ack_boundary,
        "sender_span": s_extract.span,
        "receiver_span": r_extract.span,
        "sender_union_intervals": s_intervals,
        "receiver_union_intervals": r_intervals,
        "sender_fwd_data_packets": s_extract.fwd_data_packets,
        "receiver_fwd_data_packets": r_extract.fwd_data_packets,
        "sender_reverse_ack_packets": s_extract.reverse_ack_packets,
        "receiver_reverse_ack_packets": r_extract.reverse_ack_packets,
        "sender_frame_count": s_scan.frame_count,
        "receiver_frame_count": r_scan.frame_count,
        "sender_truncated_packets": s_scan.truncated_packets,
        "receiver_truncated_packets": r_scan.truncated_packets,
        "sender_malformed_packets": s_scan.malformed_packets,
        "receiver_malformed_packets": r_scan.malformed_packets,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "sender_name": sender_name,
        "receiver_name": receiver_name,
    }
    outcome.ok = True
    outcome.meta = meta
    outcome.summary = summary

    conn = _connect(db_file)
    for k, v in meta.items():
        conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)",
            (k, json.dumps(v, ensure_ascii=False)),
        )
    conn.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES ('summary_obj', ?)",
        (json.dumps(summary, ensure_ascii=False),),
    )
    conn.commit()
    conn.close()

    _write_report_json(outcome)
    return outcome


def _write_report_json(outcome: AnalysisOutcome) -> None:
    try:
        with open(os.path.join(outcome.run_dir, "report.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(outcome.to_jsonable(), fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def load_outcome(run_dir: str, run_id: str) -> Optional[AnalysisOutcome]:
    report = os.path.join(run_dir, "report.json")
    if not os.path.exists(report):
        return None
    try:
        with open(report, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return AnalysisOutcome(
        run_id=run_id,
        run_dir=run_dir,
        ok=data.get("ok", False),
        errors=data.get("errors", []),
        sender_report=data.get("sender"),
        receiver_report=data.get("receiver"),
        meta=data.get("meta", {}),
        summary=data.get("summary", {}),
        window=data.get("window"),
    )
