#!/usr/bin/env python3
"""Materialize built-in sample captures under ./samples for manual upload."""

from __future__ import annotations

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pcapdiff.sample_data import SAMPLES, build_sample  # noqa: E402


def main() -> None:
    out_root = os.path.join(ROOT, "samples")
    os.makedirs(out_root, exist_ok=True)
    for key, spec in SAMPLES.items():
        sub = os.path.join(out_root, key)
        s_path, r_path, _ = build_sample(key, sub)
        flat_s = os.path.join(out_root, f"sample-{key}-sender.pcap")
        flat_r = os.path.join(out_root, f"sample-{key}-receiver.pcap")
        shutil.copyfile(s_path, flat_s)
        shutil.copyfile(r_path, flat_r)
        print(f"[{key}] {spec.title}")
        print(f"  {flat_s}")
        print(f"  {flat_r}")
        print(f"  dir: {sub}")


if __name__ == "__main__":
    main()
