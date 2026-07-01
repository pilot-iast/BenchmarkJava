#!/usr/bin/env python3
"""Inspect method pools / graphs for crypto FN tests on the panel."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_traces_and_fn import fetch_graph, panel_session

TESTS = [
    "BenchmarkTest00005",  # crypto
    "BenchmarkTest00003",  # hash
    "BenchmarkTest00023",  # weakrand
    "BenchmarkTest00087",  # securecookie
]


def main() -> int:
    panel = os.environ.get("PANEL_URL", "http://88.218.71.82").rstrip("/")
    if not os.environ.get("PANEL_USER") or not os.environ.get("PANEL_PASS"):
        print("Set PANEL_USER and PANEL_PASS", file=sys.stderr)
        return 2

    session, headers = panel_session(panel)
    now = int(time.time() * 1000)
    week_ago = now - 7 * 86400 * 1000
    project_id = int(os.environ.get("PANEL_PROJECT_ID", "2"))

    for test_name in TESTS:
        payload = {
            "page_size": 5,
            "highlight": 0,
            "search_mode": 1,
            "time_range": [week_ago, now],
            "exclude_ids": [],
            "project_id": project_id,
            "url": test_name,
        }
        resp = session.post(
            f"{panel}/api/v1/engine/method_pool/search",
            json=payload,
            headers=headers,
            timeout=120,
        )
        body = resp.json()
        pools = (body.get("data") or {}).get("method_pools") or []
        print(f"\n=== {test_name} pools={len(pools)} ===")
        if not pools:
            print("  no method pool")
            continue
        pool = pools[0]
        print(f"  id={pool.get('id')} uri={pool.get('uri')}")
        graph = fetch_graph(session, headers, panel, int(pool["id"]))
        names = [n.get("name", "") for n in graph.get("nodes") or []]
        needles = [
            "Cipher",
            "MessageDigest",
            "Math.random",
            "Random.next",
            "Cookie.setSecure",
            "getInstance",
        ]
        for needle in needles:
            hits = [n for n in names if needle in n]
            if hits:
                print(f"  {needle}: {hits[:3]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
