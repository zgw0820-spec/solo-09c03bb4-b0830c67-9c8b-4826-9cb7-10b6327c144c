#!/usr/bin/env python3
"""Empirical check that analysis working memory does not grow with packets.

Generates adversarial captures with many disjoint 1-byte ranges separated by
1-byte gaps and runs analysis in a fresh interpreter per size, reporting peak
RSS (KiB on Linux).  Usage:

    python3 tools/selftest_memory.py [sizes...]

The script exits non-zero if peak RSS grows more than ALLOWED_GROWTH_MB between
the smallest and largest run.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pcapdiff.pcap_writer import write_classic_pcap  # noqa: E402
from tests.conftest import data_packet, handshake  # noqa: E402

ALLOWED_GROWTH_MB = 40


def generate(path_s: str, path_r: str, n: int) -> None:
    # Sender: n disjoint 1-byte ranges at offsets 0,2,4,...
    def sender_frames():
        yield from handshake()
        for i in range(n):
            yield data_packet(i * 2, 1)

    def receiver_frames():
        yield from handshake()  # no payload at all -> n missing segments

    write_classic_pcap(path_s, sender_frames())
    write_classic_pcap(path_r, receiver_frames())


def main() -> int:
    sizes = [int(x) for x in sys.argv[1:]] or [5_000, 50_000, 200_000]
    work = tempfile.mkdtemp(prefix="memgen-")
    results = []
    for n in sizes:
        sp = os.path.join(work, f"s-{n}.pcap")
        rp = os.path.join(work, f"r-{n}.pcap")
        if not os.path.exists(sp):
            generate(sp, rp, n)
        env = dict(os.environ, PCAPDIFF_EXPECT_N=str(n))
        code = (
            "import sys, resource; sys.path.insert(0, %r);"
            "from pcapdiff.engine import create_run_dir, run_analysis, get_page;"
            "import tempfile, os;"
            "var=tempfile.mkdtemp(prefix='probe-');"
            "rid,rd=create_run_dir(var);"
            "out=run_analysis(rid,rd,%r,%r);"
            "assert out.ok, out.errors;"
            "exp=int(os.environ['PCAPDIFF_EXPECT_N']);"
            "tot=get_page(rd,1,1)['total_ranges'];"
            "assert tot==exp, (tot,exp);"
            "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)"
            % (ROOT, sp, rp)
        )
        proc = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True, text=True, env=env,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            return 1
        rss_kib = int(proc.stdout.strip().splitlines()[-1])
        size_mb_s = os.path.getsize(sp) / 1e6
        results.append((n, rss_kib / 1024, size_mb_s))
        print(f"N={n:>7d}  peak RSS={rss_kib/1024:7.1f} MiB  "
              f"sender pcap={size_mb_s:6.1f} MB")

    first_rss = results[0][1]
    last_rss = results[-1][1]
    growth = last_rss - first_rss
    print(f"RSS growth {results[0][0]} -> {results[-1][0]} packets: "
          f"{growth:+.1f} MiB (allowed +{ALLOWED_GROWTH_MB} MiB)")
    if growth > ALLOWED_GROWTH_MB:
        print("FAIL: memory grew beyond allowance")
        return 1
    print("PASS: working memory effectively independent of packet count")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
