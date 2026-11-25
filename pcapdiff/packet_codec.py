"""Minimal Ethernet / IPv4 / TCP decoder used by the streaming scanner.

The decoder never returns payload bytes, only their length: this tool compares
sequence-space coverage, not content.  It works on a single frame at a time.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Optional

ETH_P_IPV4 = 0x0800
VLAN_ETYPES = frozenset({0x8100, 0x88A8, 0x9100})

# Link types we can decapsulate.  Ethernet(1) is the documented format; the
# others are accepted so loosely generated fixtures (e.g. Scapy bare IP ->
# LINKTYPE_IPV4 228) still work.
DLT_EN10MB = 1
DLT_NULL = 0
DLT_RAW = 101
LINKTYPE_IPV4 = 228
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
SUPPORTED_LINKTYPES = frozenset({
    DLT_EN10MB, DLT_NULL, DLT_RAW, LINKTYPE_IPV4,
    DLT_LINUX_SLL, DLT_LINUX_SLL2,
})

IPPROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


@dataclass(frozen=True)
class TcpSegment:
    frame_no: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload_len: int          # bytes actually available in the capture
    declared_payload_len: int  # bytes the IP/TCP headers claim
    truncated: bool
    fragmented: bool = False  # IPv4 fragment (such frames carry no TCP info)
    window: int = 0           # raw 16-bit advertised window (pre scaling)
    wscale: Optional[int] = None  # RFC 7323 Window Scale shift (kind=3), if present


@dataclass(frozen=True)
class FrameDecode:
    """Result of decoding one frame.

    ``tcp`` is None for non-IPv4, non-TCP or fragmented frames.  ``fragment``
    is True when the frame is an IPv4 fragment of any protocol.
    """

    frame_no: int
    tcp: Optional[TcpSegment]
    fragment: bool = False
    malformed: bool = False
    truncated_l3: bool = False


def _ipv4_str(packed4: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, packed4)


def _l3_offset(frame_no: int, data: bytes, linktype: int):
    """Return IPv4 header offset, or a FrameDecode for ignore/malformed."""
    if linktype == DLT_EN10MB:
        if len(data) < 14:
            return FrameDecode(frame_no, None, malformed=True)
        eth_type = struct.unpack_from("!H", data, 12)[0]
        l3_off = 14
        while eth_type in VLAN_ETYPES:
            if len(data) < l3_off + 4:
                return FrameDecode(frame_no, None, malformed=True)
            eth_type = struct.unpack_from("!H", data, l3_off + 2)[0]
            l3_off += 4
        if eth_type != ETH_P_IPV4:
            return FrameDecode(frame_no, None)  # ARP / IPv6 / ...
        return l3_off

    if linktype in (DLT_RAW, LINKTYPE_IPV4):
        return 0

    if linktype == DLT_NULL:
        # 4-byte BSD loopback family header; AF_INET is endian-dependent (2).
        if len(data) < 24:
            return FrameDecode(frame_no, None, malformed=True)
        family = struct.unpack_from("<I", data, 0)[0]
        if family != 2 and struct.unpack_from(">I", data, 0)[0] != 2:
            return FrameDecode(frame_no, None)
        return 4

    if linktype == DLT_LINUX_SLL:
        # 16-byte v1 header, big-endian protocol type at offset 14.
        if len(data) < 16:
            return FrameDecode(frame_no, None, malformed=True)
        eth_type = struct.unpack_from("!H", data, 14)[0]
        if eth_type != ETH_P_IPV4:
            return FrameDecode(frame_no, None)
        return 16

    if linktype == DLT_LINUX_SLL2:
        # 20-byte v2 header, big-endian protocol type at offset 0.
        if len(data) < 20:
            return FrameDecode(frame_no, None, malformed=True)
        eth_type = struct.unpack_from("!H", data, 0)[0]
        if eth_type != ETH_P_IPV4:
            return FrameDecode(frame_no, None)
        return 20

    return FrameDecode(frame_no, None)  # unsupported linktype: ignore


def decode_frame(frame_no: int, data: bytes,
                 linktype: int = DLT_EN10MB) -> FrameDecode:
    """Decode one raw link-layer frame.  Never raises on bad packets."""
    try:
        l3 = _l3_offset(frame_no, data, linktype)
        if isinstance(l3, FrameDecode):
            return l3
        l3_off = l3

        if len(data) < l3_off + 20:
            return FrameDecode(frame_no, None, malformed=True)

        ver_ihl = data[l3_off]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4
        if version != 4 or ihl < 20:
            return FrameDecode(frame_no, None, malformed=True)

        total_len = struct.unpack_from("!H", data, l3_off + 2)[0]
        flags_frag = struct.unpack_from("!H", data, l3_off + 6)[0]
        frag_offset = flags_frag & 0x1FFF
        more_fragments = bool((flags_frag >> 13) & 0x1)
        fragmented = more_fragments or frag_offset != 0

        if fragmented:
            return FrameDecode(frame_no, None, fragment=True)

        protocol = data[l3_off + 9]
        if protocol != IPPROTO_TCP:
            return FrameDecode(frame_no, None)

        l4_off = l3_off + ihl
        if len(data) < l4_off + 20:
            return FrameDecode(frame_no, None, malformed=True)

        src_ip = _ipv4_str(data[l3_off + 12:l3_off + 16])
        dst_ip = _ipv4_str(data[l3_off + 16:l3_off + 20])

        src_port, dst_port, seq, ack = struct.unpack_from(
            "!HHII", data, l4_off
        )
        data_byte = data[l4_off + 12]
        data_off = (data_byte >> 4) * 4
        flags = data[l4_off + 13]
        raw_window = struct.unpack_from("!H", data, l4_off + 14)[0]
        if data_off < 20:
            return FrameDecode(frame_no, None, malformed=True)
        if len(data) < l4_off + data_off:
            return FrameDecode(frame_no, None, malformed=True)

        # Parse only the Window Scale option (kind=3, len=3).  Option parsing
        # is bounds-checked and never raises on malformed options.
        wscale: Optional[int] = None
        opt_end = l4_off + data_off
        i = l4_off + 20
        while i + 1 < opt_end:
            kind = data[i]
            if kind == 0:          # End of option list
                break
            if kind == 1:          # NOP
                i += 1
                continue
            opt_len = data[i + 1]
            if opt_len < 2 or i + opt_len > opt_end:
                break
            if kind == 3 and opt_len == 3:
                wscale = data[i + 2]
            i += opt_len

        # Payload length as declared by IP / TCP headers.
        if total_len >= ihl:
            ip_payload = total_len - ihl
            declared_len = max(0, ip_payload - data_off)
        else:
            declared_len = 0

        # Payload bytes actually present in the captured frame.  Ethernet
        # padding is already excluded by total_len above; snaplen truncation
        # may leave fewer bytes than declared.
        captured_tcp_payload = len(data) - l4_off - data_off
        if captured_tcp_payload < 0:
            return FrameDecode(frame_no, None, malformed=True)

        payload_len = min(declared_len, captured_tcp_payload)
        truncated = declared_len > captured_tcp_payload

        seg = TcpSegment(
            frame_no=frame_no,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            payload_len=payload_len,
            declared_payload_len=declared_len,
            truncated=truncated,
            window=raw_window,
            wscale=wscale,
        )
        return FrameDecode(frame_no, seg)
    except (struct.error, IndexError):
        return FrameDecode(frame_no, None, malformed=True)


def i32_delta(value: int, base: int) -> int:
    """Signed distance ``value - base`` in 32-bit TCP sequence space.

    The result is unique as long as the represented span is < 2 GiB.
    """
    d = (value - base) & 0xFFFFFFFF
    if d >= 0x80000000:
        d -= 0x100000000
    return d


def data_start_offset(seq: int, isn: int, syn: bool) -> int:
    """Byte offset of the first payload byte relative to offset 0.

    Offset 0 is the first data byte following the initial SYN, i.e. sequence
    number ``ISN + 1``.  A SYN consumes one sequence number, so payload carried
    inside a SYN packet starts at ``seq + 1``.
    """
    base = (isn + 1) & 0xFFFFFFFF
    payload_seq = (seq + (1 if syn else 0)) & 0xFFFFFFFF
    return i32_delta(payload_seq, base)


def ack_offset(ack: int, isn: int) -> int:
    """Number of data bytes cumulatively acknowledged by ``ack``.

    The handshake ACK of ``ISN + 1`` maps to 0 acknowledged data bytes.
    """
    base = (isn + 1) & 0xFFFFFFFF
    return i32_delta(ack, base)
