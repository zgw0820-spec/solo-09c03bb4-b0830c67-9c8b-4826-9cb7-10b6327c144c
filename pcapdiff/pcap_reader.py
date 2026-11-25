"""Streaming reader for Ethernet PCAP files.

Supports:
  * classic libpcap (microsecond / nanosecond magic, little / big endian)
  * pcapng (SHB / IDB / EPB / SPB)

Only one link-layer frame (and its containing block) is held in memory at a
time.  Packet records are never accumulated, so read-side working memory does
not grow with the number of packets.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional

DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

# A single Ethernet frame is far below this; the cap only protects against
# corrupt / malicious length fields causing an unbounded allocation.
MAX_FRAME_BYTES = 64 * 1024 * 1024


class PcapFormatError(Exception):
    """Raised when the capture cannot be parsed as PCAP / PCAPNG."""


@dataclass(frozen=True)
class Frame:
    index: int          # 1-based frame number
    data: bytes         # captured link-layer bytes (truncated to incl_len)
    orig_len: int       # original wire length as recorded by the dumper
    ts_ns: int = 0      # capture timestamp as epoch nanoseconds (0 if unknown)


@dataclass
class PcapInfo:
    format_name: str
    linktype: int
    snaplen: int
    frame_count: int = 0
    classic: bool = True   # classic libpcap format (False -> pcapng)


class PcapReader:
    """Context manager wrapping a binary PCAP/PCAPNG file.

    Iterate :meth:`frames` to process frames one at a time.
    """

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb", buffering=1 << 20)
        self.info: Optional[PcapInfo] = None
        self._frame_index = 0
        self._init_format()

    # -- lifecycle -------------------------------------------------------
    def close(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- low level helpers ----------------------------------------------
    def _read_exact(self, n: int, what: str = "data") -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._f.read(remaining)
            if not chunk:
                raise PcapFormatError(
                    f"文件已截断：读取{what}时期望 {n} 字节，"
                    f"还差 {remaining} 字节"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _peek4(self) -> bytes:
        pos = self._f.tell()
        b = self._f.read(4)
        self._f.seek(pos)
        return b

    # -- format dispatch -------------------------------------------------
    def _init_format(self) -> None:
        magic = self._read_exact(4, "文件魔数")
        if len(magic) < 4:
            raise PcapFormatError("文件过小，不是有效的 PCAP/PCAPNG 文件")

        # Classic pcap magics.
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self._endian = "<"
            nano = magic == b"\x4d\x3c\xb2\xa1"
            self._init_classic(nano)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self._endian = ">"
            nano = magic == b"\xa1\xb2\x3c\x4d"
            self._init_classic(nano)
        elif magic == b"\x0a\x0d\x0d\x0a":
            self._init_pcapng()
        else:
            raise PcapFormatError(
                "无法识别的文件格式（魔数 "
                + magic.hex(" ")
                + "），请上传标准 PCAP 或 PCAPNG 文件"
            )

    def _init_classic(self, nano: bool) -> None:
        rest = self._read_exact(20, "PCAP 全局头")
        e = self._endian
        try:
            (_vmaj, _vmin, _tz, _sigfigs, snaplen, linktype) = struct.unpack(
                e + "HHiIII", rest
            )
        except struct.error as exc:
            raise PcapFormatError("PCAP 全局头解析失败") from exc
        self._nano = nano
        self.info = PcapInfo(
            format_name="PCAP" + ("(纳秒)" if nano else ""),
            linktype=linktype,
            snaplen=snaplen,
            classic=True,
        )
        self._iter_impl = self._iter_classic

    def _iter_classic(self) -> Iterator[Frame]:
        e = self._endian
        f = self._f
        nano = getattr(self, "_nano", False)
        while True:
            hdr = f.read(16)
            if not hdr:
                return
            if len(hdr) < 16:
                raise PcapFormatError("PCAP 记录头被截断")
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(e + "IIII", hdr)
            if incl_len > MAX_FRAME_BYTES:
                raise PcapFormatError(
                    f"第 {self._frame_index + 1} 个数据包声明的捕获长度 "
                    f"{incl_len} 字节异常过大，文件可能已损坏"
                )
            data = self._read_exact(incl_len, "数据包内容") if incl_len else b""
            self._frame_index += 1
            if nano:
                ts_ns = ts_sec * 1_000_000_000 + ts_frac
            else:
                ts_ns = ts_sec * 1_000_000_000 + ts_frac * 1_000
            yield Frame(self._frame_index, data, orig_len, ts_ns)

    # -- pcapng ----------------------------------------------------------
    def _init_pcapng(self) -> None:
        # Already consumed block type (4 bytes).  Read block total length.
        len_bytes = self._read_exact(4, "PCAPNG SHB 长度")
        # Byte order magic sits at offset 8 (after block type + length).
        # BOM value 0x1A2B3C4D: little-endian files store it as
        # 4D 3C 2B 1A, big-endian files as 1A 2B 3C 4D.
        bom = self._read_exact(4, "PCAPNG 字节序魔数")
        if bom == b"\x4d\x3c\x2b\x1a":
            e = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            e = ">"
        else:
            raise PcapFormatError("PCAPNG 字节序魔数无效")
        self._endian = e
        block_len = struct.unpack(e + "I", len_bytes)[0]
        if block_len < 16 or block_len > MAX_FRAME_BYTES:
            raise PcapFormatError("PCAPNG Section Header Block 长度异常")
        # Consumed so far: type(4) + total-len(4) + BOM(4) = 12 bytes.
        # Still to read: rest of body + trailing total-len(4).
        self._read_exact(block_len - 16, "PCAPNG SHB 主体")
        trailing = self._read_exact(4, "PCAPNG SHB 尾部长度")
        trail_len = struct.unpack(e + "I", trailing)[0]
        if trail_len != block_len:
            raise PcapFormatError("PCAPNG SHB 长度字段不一致")

        # Find the first IDB to learn the link type.  Blocks are scanned in
        # frames() too; here we only locate the first IDB by walking blocks.
        linktype: Optional[int] = None
        snaplen = 0
        while linktype is None:
            head = self._f.read(8)
            if not head:
                raise PcapFormatError("PCAPNG 缺少 Interface Description Block")
            if len(head) < 8:
                raise PcapFormatError("PCAPNG 块头被截断")
            btype, blen = struct.unpack(e + "II", head)
            if blen < 12 or blen > MAX_FRAME_BYTES:
                raise PcapFormatError("PCAPNG 块长度异常")
            block = self._read_exact(blen - 8, "PCAPNG 块内容")
            if btype == 1:  # IDB
                if len(block) < 8:
                    raise PcapFormatError("PCAPNG IDB 过短")
                linktype, _reserved, snaplen = struct.unpack(e + "HHI", block[:8])
            # other block types before IDB are skipped
        # Rewind: the IDB was consumed; simplest is to re-open and let the
        # block iterator start from the beginning.
        self._f.close()
        self._f = open(self.path, "rb", buffering=1 << 20)
        self._f.seek(0)
        self.info = PcapInfo(format_name="PCAPNG", linktype=linktype,
                             snaplen=snaplen, classic=False)
        self._iter_impl = self._iter_pcapng

    def _iter_pcapng(self) -> Iterator[Frame]:
        e = self._endian
        f = self._f
        while True:
            head = f.read(8)
            if not head:
                return
            if len(head) < 8:
                raise PcapFormatError("PCAPNG 块头被截断")
            btype, blen = struct.unpack(e + "II", head)
            if blen < 12 or blen > MAX_FRAME_BYTES:
                raise PcapFormatError(
                    f"PCAPNG 块长度异常（type=0x{btype:08x}, len={blen}）"
                )
            block = self._read_exact(blen - 8, "PCAPNG 块内容")
            # block includes body + trailing block-total-length (4 bytes)
            body = block[:-4] if len(block) >= 4 else b""

            if btype == 6:  # Enhanced Packet Block
                if len(body) < 20:
                    raise PcapFormatError("PCAPNG EPB 过短")
                (_iface, ts_hi, ts_lo, caplen, origlen) = struct.unpack(
                    e + "IIIII", body[:20]
                )
                pkt = body[20:20 + caplen]
                if len(pkt) < caplen:
                    raise PcapFormatError("PCAPNG EPB 数据包被截断")
                # Default IDB timestamp resolution is microseconds; the
                # window check itself requires classic PCAP, so this is only
                # used for generic frame metadata.
                ts_units = (ts_hi << 32) | ts_lo
                ts_ns = ts_units * 1000
                self._frame_index += 1
                yield Frame(self._frame_index, pkt, origlen, ts_ns)

            elif btype == 3:  # Simple Packet Block
                if len(body) < 4:
                    raise PcapFormatError("PCAPNG SPB 过短")
                (origlen,) = struct.unpack(e + "I", body[:4])
                available = len(body) - 4
                caplen = min(origlen, available)
                pkt = body[4:4 + caplen]
                self._frame_index += 1
                yield Frame(self._frame_index, pkt, origlen)
            # All other block types (IDB, SHB, NRB, ...) are ignored.

    def frames(self) -> Iterator[Frame]:
        if self.info is None or not hasattr(self, "_iter_impl"):
            raise PcapFormatError("读取器未正确初始化")
        yield from self._iter_impl()
        if self.info is not None:
            self.info.frame_count = self._frame_index


def iter_frames(path: str) -> tuple[PcapReader, Iterator[Frame]]:
    """Convenience helper returning an open reader and its frame iterator."""
    reader = PcapReader(path)
    return reader, reader.frames()
