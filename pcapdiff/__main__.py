"""``python -m pcapdiff sender.pcap receiver.pcap`` — CLI comparison."""

from __future__ import annotations

import argparse
import json
import os
import tempfile

from .engine import create_run_dir, get_page, run_analysis


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="pcapdiff",
        description="Compare two dual-ended TCP captures for byte evidence.",
    )
    ap.add_argument("sender", help="sender-side Ethernet PCAP/PCAPNG")
    ap.add_argument("receiver", help="receiver-side Ethernet PCAP/PCAPNG")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--var-dir", default=None)
    args = ap.parse_args(argv)

    var_dir = args.var_dir or tempfile.mkdtemp(prefix="pcapdiff-cli-")
    os.makedirs(var_dir, exist_ok=True)
    run_id, run_dir = create_run_dir(var_dir)
    outcome = run_analysis(
        run_id, run_dir, args.sender, args.receiver,
        os.path.basename(args.sender), os.path.basename(args.receiver),
    )

    if args.json:
        payload = outcome.to_jsonable()
        if outcome.ok:
            payload["page"] = get_page(run_dir, 1, 10000)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if outcome.ok else 2

    if not outcome.ok:
        print("校验失败：")
        for e in outcome.errors:
            print("  - " + e)
        return 2

    print(f"连接 {outcome.meta['tuple']}  ISN={outcome.meta['isn']} "
          f"ACK边界={outcome.meta['ack_boundary']}")
    print(f"总字节 {outcome.summary['total_bytes']}，"
          f"{outcome.summary['total_ranges']} 段")
    page_no = 1
    while True:
        page = get_page(run_dir, page_no, 10000)
        for it in page["items"]:
            print(f"  {it['start']:>12,} .. {it['last']:>12,}  "
                  f"len={it['length']:>8,}  {it['label']}")
        if page_no >= page["total_pages"]:
            break
        page_no += 1
    for key, c in outcome.summary["categories"].items():
        print(f"  {c['label']}: {c['bytes']:,} 字节 / {c['ranges']} 段")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
