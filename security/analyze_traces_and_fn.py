#!/usr/bin/env python3
"""Benchmark trace coverage + FN taint graph export (panel API, same as frontend)."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

import requests

TEST_RE = re.compile(r"BenchmarkTest\d{5}")
HEADER_TYPES = {
    "Ответ с отключенным X-XSS-Protection",
    "Response Without Content-Security-Policy Header",
    "Response Without X-Content-Type-Options Header",
    "Страницы без защиты от кликджекинга",
}
SENSITIVE_MARKERS = ("Утечка", "Leak", "Email Address", "ID Number")


def panel_session(panel_url: str) -> tuple[requests.Session, dict[str, str]]:
    root = panel_url.rstrip("/")
    session = requests.Session()
    session.headers["Referer"] = root + "/"
    session.verify = os.environ.get("PANEL_VERIFY_SSL", "false").lower() in (
        "1",
        "true",
        "yes",
    )
    session.get(root + "/", timeout=30)
    session.post(
        f"{root}/api/v1/user/login",
        json={
            "username": os.environ["PANEL_USER"],
            "password": os.environ["PANEL_PASS"],
        },
        timeout=30,
    )
    csrf = session.cookies.get("DTCsrfToken") or session.cookies.get("csrftoken") or ""
    headers = {
        "Referer": root + "/",
        "Content-Type": "application/json",
        "X-CSRFToken": csrf,
        "csrf-token": csrf,
        "CSRF-TOKEN": csrf,
    }
    return session, headers


def load_cases(expected_csv: Path) -> dict[str, dict]:
    cases: dict[str, dict] = {}
    with expected_csv.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            cases[parts[0]] = {
                "category": parts[1],
                "vulnerable": parts[2].lower() == "true",
                "cwe": parts[3] if len(parts) > 3 else "",
            }
    return cases


def load_crawler_tests(crawler_xml: Path) -> dict[str, str]:
    urls: dict[str, str] = {}
    root = ET.parse(crawler_xml).getroot()
    for test in root.findall("benchmarkTest"):
        name = test.get("tcName")
        url = test.get("URL")
        if name and url:
            urls[name] = url
    return urls


def is_taint_finding(item: dict) -> bool:
    if str(item.get("is_header_vul", "")).lower() in ("1", "true", "yes"):
        return False
    name = str(item.get("strategy__vul_name") or "")
    if name in HEADER_TYPES:
        return False
    if any(marker in name for marker in SENSITIVE_MARKERS):
        return False
    return True


def fetch_v2_vulns(
    session: requests.Session, headers: dict[str, str], panel_url: str, project_id: int
) -> list[dict]:
    root = panel_url.rstrip("/")
    all_items: list[dict] = []
    page = 1
    while True:
        resp = session.post(
            f"{root}/api/v2/app_vul_list_content",
            json={"page": page, "page_size": 200, "bind_project_id": project_id},
            headers=headers,
            timeout=120,
        )
        resp.raise_for_status()
        items = (resp.json().get("data") or {}).get("messages") or []
        if not items:
            break
        all_items.extend(items)
        if len(items) < 200:
            break
        page += 1
    return all_items


def search_trace(
    session: requests.Session,
    headers: dict[str, str],
    panel_url: str,
    *,
    project_id: int,
    test_name: str | None = None,
    pool_id: int | None = None,
    time_range: tuple[int, int],
) -> dict | None:
    root = panel_url.rstrip("/")
    payload: dict = {
        "page_size": 5,
        "highlight": 1,
        "search_mode": 1,
        "time_range": list(time_range),
        "exclude_ids": [],
        "project_id": project_id,
    }
    if pool_id is not None:
        payload["id"] = pool_id
    elif test_name:
        payload["url"] = test_name
    resp = session.post(
        f"{root}/api/v1/engine/method_pool/search",
        json=payload,
        headers=headers,
        timeout=120,
    )
    if resp.status_code != 200:
        return None
    body = resp.json()
    if body.get("status") not in (200, 201):
        return None
    pools = (body.get("data") or {}).get("method_pools") or []
    if not pools:
        return None
    if test_name:
        for pool in pools:
            if test_name in (pool.get("uri") or "") or test_name in (pool.get("url") or ""):
                return pool
        return pools[0]
    return pools[0]


def fetch_graph(
    session: requests.Session,
    headers: dict[str, str],
    panel_url: str,
    method_pool_id: int,
) -> dict:
    root = panel_url.rstrip("/")
    resp = session.get(
        f"{root}/api/v1/engine/graph",
        params={"method_pool_id": method_pool_id, "method_pool_type": "normal"},
        headers=headers,
        timeout=120,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (200, 201):
        return {"error": body.get("msg"), "nodes": [], "edges": []}
    return body.get("data") or {"nodes": [], "edges": []}


def paginate_benchmark_traces(
    session: requests.Session,
    headers: dict[str, str],
    panel_url: str,
    *,
    project_id: int,
    time_range: tuple[int, int],
    max_batches: int = 500,
) -> tuple[set[str], set[tuple[str, str]], int]:
    root = panel_url.rstrip("/")
    seen_tests: set[str] = set()
    seen_uri_method: set[tuple[str, str]] = set()
    exclude_ids: list[int] = []
    total_rows = 0
    search_after: int | None = None

    for _batch in range(max_batches):
        payload: dict = {
            "page_size": 200,
            "highlight": 1,
            "search_mode": 1,
            "time_range": list(time_range),
            "exclude_ids": exclude_ids[-500:],  # nginx chokes on huge lists
            "project_id": project_id,
            "url": "/benchmark/",
        }
        if search_after is not None:
            payload["search_after_update_time"] = search_after

        resp = session.post(
            f"{root}/api/v1/engine/method_pool/search",
            json=payload,
            headers=headers,
            timeout=120,
        )
        if resp.status_code != 200:
            break
        body = resp.json()
        if body.get("status") not in (200, 201):
            break
        data = body.get("data") or {}
        pools = data.get("method_pools") or []
        if not pools:
            break

        total_rows += len(pools)
        for pool in pools:
            uri = pool.get("uri") or ""
            seen_uri_method.add((uri, pool.get("http_method") or ""))
            match = TEST_RE.search(uri)
            if match:
                seen_tests.add(match.group(0))
            pid = pool.get("id")
            if pid and pid not in exclude_ids:
                exclude_ids.append(pid)

        afterkeys = data.get("afterkeys") or {}
        next_after = afterkeys.get("update_time") or pools[-1].get("update_time")
        if next_after == search_after:
            break
        search_after = next_after
        if len(pools) < 200:
            break

    return seen_tests, seen_uri_method, total_rows


def summarize_graph(graph: dict) -> dict:
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    node_by_id = {n.get("id"): n for n in nodes if n.get("id") is not None}
    taint_nodes = []
    for node in nodes:
        data_type = str(node.get("dataType") or node.get("nodeType") or "").lower()
        label = str(node.get("label") or "")
        if "source" in data_type or "sink" in data_type or "taint" in label.lower():
            taint_nodes.append(
                {
                    "id": node.get("id"),
                    "label": label,
                    "dataType": node.get("dataType"),
                    "nodeType": node.get("nodeType"),
                }
            )
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "taint_nodes": taint_nodes[:20],
        "sample_node_labels": [n.get("label") for n in nodes[:8]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-url", default=os.environ.get("PANEL_URL", ""))
    parser.add_argument("--project-id", type=int, default=2)
    parser.add_argument("--output-dir", default="trace-analysis")
    parser.add_argument("--fn-samples", type=int, default=5)
    args = parser.parse_args()

    panel_url = args.panel_url or os.environ.get("IAST_SERVER_URL", "")
    if not panel_url or not os.environ.get("PANEL_USER") or not os.environ.get("PANEL_PASS"):
        print("Set PANEL_URL, PANEL_USER, PANEL_PASS", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[1]
    cases = load_cases(root / "expectedresults-1.2.csv")
    crawler_urls = load_crawler_tests(root / "data" / "benchmark-crawler-http.xml")
    session, headers = panel_session(panel_url)

    # Agent time window for traces
    agents = session.get(
        f"{panel_url.rstrip('/')}/api/v1/agents",
        params={"bind_project_id": args.project_id, "pageSize": 50},
        timeout=30,
    ).json().get("data") or []
    latest_agent = max(agents, key=lambda a: int(a.get("id") or 0))
    center = int(latest_agent.get("latest_time") or time.time())
    time_range = (center - 86400 * 14, center + 3600)
    agent_flow = int(latest_agent.get("flow") or 0)

    vulns = fetch_v2_vulns(session, headers, panel_url, args.project_id)
    detected_taint: set[str] = set()
    for item in vulns:
        if not is_taint_finding(item):
            continue
        match = TEST_RE.search(item.get("uri") or "")
        if match:
            detected_taint.add(match.group(0))

    expected_vuln = {name for name, c in cases.items() if c["vulnerable"]}
    fn_tests = sorted(expected_vuln - detected_taint)
    tp_tests = sorted(expected_vuln & detected_taint)

    print("=== Planted-vuln detection (taint only, no header/sensitive) ===")
    print(f"Expected vulnerable: {len(expected_vuln)}")
    print(f"Detected (TP):       {len(tp_tests)}")
    print(f"Missed (FN):         {len(fn_tests)}")
    print(f"Recall:              {100 * len(tp_tests) / len(expected_vuln):.2f}%")

    print("\n=== Trace coverage (method pools, project scoped) ===")
    seen_tests, seen_uri_method, pool_rows = paginate_benchmark_traces(
        session,
        headers,
        panel_url,
        project_id=args.project_id,
        time_range=time_range,
    )
    crawler_tests = set(crawler_urls)
    missing_traces = sorted(crawler_tests - seen_tests)
    print(f"Crawler tests:           {len(crawler_tests)}")
    print(f"Agent flow (latest run): {agent_flow}")
    print(f"Method pool rows scanned:{pool_rows}")
    print(f"Unique traced tests:     {len(seen_tests)}")
    print(f"Missing traces:          {len(missing_traces)}")
    print(f"Trace coverage:          {100 * len(seen_tests) / len(crawler_tests):.2f}%")

    fn_no_trace = [t for t in fn_tests if t not in seen_tests]
    fn_with_trace = [t for t in fn_tests if t in seen_tests]
    print(f"\nFN with trace present:   {len(fn_with_trace)} (detection gap, not traffic gap)")
    print(f"FN without trace:        {len(fn_no_trace)} (traffic/processing gap)")

    miss_by_cat = Counter(cases[t]["category"] for t in missing_traces if t in cases)
    print("\nMissing traces by category (top):")
    for cat, count in miss_by_cat.most_common(12):
        print(f"  {cat:12s} {count}")

    # Pick FN samples: prefer traced FNs from diverse categories
    picked: list[str] = []
    fn_by_cat: dict[str, list[str]] = defaultdict(list)
    for name in fn_with_trace:
        fn_by_cat[cases[name]["category"]].append(name)
    for cat in ["sqli", "xss", "cmdi", "pathtraver", "crypto", "hash", "weakrand", "ldapi"]:
        if fn_by_cat.get(cat):
            picked.append(fn_by_cat[cat][0])
        if len(picked) >= args.fn_samples:
            break
    for name in fn_with_trace:
        if name not in picked:
            picked.append(name)
        if len(picked) >= args.fn_samples:
            break
    while len(picked) < args.fn_samples and fn_no_trace:
        picked.append(fn_no_trace.pop(0))

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    fn_reports = []

    print(f"\n=== FN taint graph export ({len(picked)} samples) ===")
    for test_name in picked[: args.fn_samples]:
        cat = cases[test_name]["category"]
        pool = search_trace(
            session,
            headers,
            panel_url,
            project_id=args.project_id,
            test_name=test_name,
            time_range=time_range,
        )
        report: dict = {
            "test": test_name,
            "category": cat,
            "expected": "vulnerable",
            "crawler_url": crawler_urls.get(test_name, ""),
            "has_trace": pool is not None,
            "trace_id": pool.get("id") if pool else None,
            "trace_uri": pool.get("uri") if pool else None,
            "trace_method": pool.get("http_method") if pool else None,
        }
        if pool:
            graph = fetch_graph(session, headers, panel_url, int(pool["id"]))
            report["graph_summary"] = summarize_graph(graph)
            graph_path = out_dir / f"fn-{test_name}-graph.json"
            graph_path.write_text(
                json.dumps(
                    {
                        "test": test_name,
                        "category": cat,
                        "method_pool_id": pool["id"],
                        "uri": pool.get("uri"),
                        "http_method": pool.get("http_method"),
                        "graph": graph,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(
                f"  {test_name} ({cat}): trace=#{pool['id']} "
                f"nodes={report['graph_summary']['node_count']} "
                f"edges={report['graph_summary']['edge_count']} -> {graph_path.name}"
            )
        else:
            print(f"  {test_name} ({cat}): NO TRACE")
        fn_reports.append(report)

    summary = {
        "expected_vulnerable": len(expected_vuln),
        "tp_taint": len(tp_tests),
        "fn_taint": len(fn_tests),
        "recall_taint_pct": round(100 * len(tp_tests) / len(expected_vuln), 2),
        "crawler_tests": len(crawler_tests),
        "agent_flow_latest": agent_flow,
        "traced_tests": len(seen_tests),
        "missing_traces": len(missing_traces),
        "trace_coverage_pct": round(100 * len(seen_tests) / len(crawler_tests), 2),
        "fn_with_trace": len(fn_with_trace),
        "fn_without_trace": len(fn_no_trace),
        "fn_samples": fn_reports,
        "missing_trace_sample": missing_traces[:30],
    }
    summary_path = out_dir / "trace-fn-summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
