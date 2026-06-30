#!/usr/bin/env python3
"""Check agents and method-pool traces on Immunity panel after Benchmark crawl."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import requests


def login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    root = base_url.rstrip("/")
    session.get(f"{root}/", timeout=30)
    resp = session.post(
        f"{root}/api/v1/user/login",
        json={"username": username, "password": password},
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"login failed: {body.get('msg')}")


def csrf_headers(session: requests.Session) -> dict[str, str]:
    token = session.cookies.get("csrftoken")
    headers = {"Referer": session.headers.get("Referer", "")}
    if token:
        headers["X-CSRFToken"] = token
    return headers


def list_agents(session: requests.Session, base_url: str, project_name: str | None) -> list[dict]:
    params = {"page": 1, "page_size": 50}
    if project_name:
        params["project_name"] = project_name
    resp = session.get(f"{base_url.rstrip('/')}/api/v2/agents", params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json().get("data", {})
    return data.get("agents", [])


def search_method_pools(
    session: requests.Session, base_url: str, project_id: int | None, limit: int = 10
) -> tuple[int, list[dict]]:
    end = int(time.time())
    start = end - 7 * 24 * 3600
    payload: dict = {"page_size": limit, "time_range": [start, end]}
    if project_id is not None:
        payload["project_id"] = project_id
    resp = session.post(
        f"{base_url.rstrip('/')}/api/v1/engine/method_pool/search",
        json=payload,
        headers=csrf_headers(session),
        timeout=60,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"method_pool search failed: {body.get('msg')}")
    data = body.get("data", {})
    total = data.get("summary", {}).get("alltotal", len(data.get("items", [])))
    return int(total or 0), data.get("items", [])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-url", default=os.environ.get("PANEL_URL", ""))
    parser.add_argument("--user", default=os.environ.get("PANEL_USER", ""))
    parser.add_argument("--password", default=os.environ.get("PANEL_PASS", ""))
    parser.add_argument("--project-name", default=os.environ.get("IAST_PROJECT_NAME", "benchmarkjava"))
    args = parser.parse_args()

    if not args.panel_url or not args.user or not args.password:
        print("Set PANEL_URL, PANEL_USER, PANEL_PASS (or pass flags)", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers["Referer"] = args.panel_url.rstrip("/") + "/"
    login(session, args.panel_url, args.user, args.password)

    agents = list_agents(session, args.panel_url, args.project_name)
    online = [a for a in agents if a.get("online")]
    print(f"agents project={args.project_name!r}: total={len(agents)} online={len(online)}")
    for agent in online[:5]:
        print(
            f"  id={agent.get('id')} token={agent.get('token')} "
            f"project={agent.get('bind_project__name')} events={len(agent.get('events', []))}"
        )

    project_id = online[0].get("bind_project__id") if online else None
    try:
        total, items = search_method_pools(session, args.panel_url, project_id)
    except requests.HTTPError as exc:
        print(f"method_pool search skipped: {exc}")
        total, items = 0, []
    print(f"method_pools (7d, project_id={project_id}): total={total}")
    for item in items[:5]:
        print(f"  {item.get('url', '?')[:120]}")

    report = {
        "agents_total": len(agents),
        "agents_online": len(online),
        "method_pools_total": total,
        "sample_urls": [i.get("url") for i in items[:10]],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if online else 1


if __name__ == "__main__":
    raise SystemExit(main())
