"""Immunity IAST panel API helpers (login, projects, versions, vulnerabilities)."""

from __future__ import annotations

import os
from typing import Iterator

import requests

# Header / sensitive-info findings are not OWASP Benchmark planted categories.
HEADER_VUL_NAMES = {
    "Ответ с отключенным X-XSS-Protection",
    "Response Without Content-Security-Policy Header",
    "Response Without X-Content-Type-Options Header",
    "Страницы без защиты от кликджекинга",
}
SENSITIVE_INFO_MARKERS = ("Утечка", "Leak", "Email Address", "ID Number", "Phone Number", "Token Or Secret")


def make_session(panel_url: str) -> requests.Session:
    session = requests.Session()
    session.headers["Referer"] = panel_url.rstrip("/") + "/"
    verify_env = os.environ.get("PANEL_VERIFY_SSL", "false").strip().lower()
    session.verify = verify_env in ("1", "true", "yes")
    return session


def _check_api_response(resp: requests.Response, action: str) -> dict:
    try:
        body = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"{action} failed: HTTP {resp.status_code}, non-JSON body: {resp.text[:300]!r}"
        ) from exc
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"{action} failed: {body.get('msg')} (body={body!r})")
    return body


def login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    root = base_url.rstrip("/")
    session.get(f"{root}/", timeout=30)
    resp = session.post(
        f"{root}/api/v1/user/login",
        json={"username": username, "password": password},
        timeout=30,
    )
    resp.raise_for_status()
    _check_api_response(resp, "login")


def csrf_headers(session: requests.Session) -> dict[str, str]:
    token = (
        session.cookies.get("DTCsrfToken")
        or session.cookies.get("csrftoken")
        or session.cookies.get("CSRF-TOKEN")
    )
    headers = {"Referer": session.headers.get("Referer", "")}
    if token:
        headers["X-CSRFToken"] = token
        headers["csrf-token"] = token
        headers["CSRF-TOKEN"] = token
    return headers


def find_project_id(session: requests.Session, base_url: str, project_name: str) -> int:
    project_name = (project_name or "").strip()
    if not project_name:
        raise RuntimeError("project name is empty")
    root = base_url.rstrip("/")
    resp = session.get(
        f"{root}/api/v1/project/search",
        params={"name": project_name},
        timeout=30,
    )
    resp.raise_for_status()
    body = _check_api_response(resp, "project search")
    for item in body.get("data") or []:
        if item.get("name") == project_name:
            return int(item["id"])
    for item in body.get("data") or []:
        if project_name.lower() in str(item.get("name", "")).lower():
            return int(item["id"])
    names = [item.get("name") for item in (body.get("data") or [])[:20]]
    raise RuntimeError(f"project not found: {project_name!r} (search returned: {names})")


def list_project_versions(
    session: requests.Session, base_url: str, project_id: int
) -> list[dict]:
    root = base_url.rstrip("/")
    resp = session.get(f"{root}/api/v1/project/version/list/{project_id}", timeout=30)
    resp.raise_for_status()
    body = _check_api_response(resp, "version list")
    return list(body.get("data") or [])


def resolve_version_id(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_name: str,
) -> tuple[int, str]:
    """Return (version_id, resolved_version_name)."""
    version_name = (version_name or "").strip()
    versions = list_project_versions(session, base_url, project_id)
    if not versions:
        raise RuntimeError(f"project {project_id} has no versions")

    for item in versions:
        if item.get("version_name") == version_name:
            return int(item["version_id"]), str(item["version_name"])

    if version_name:
        prefix_matches = [
            v for v in versions if str(v.get("version_name", "")).startswith(version_name.split("-")[0] + "-")
        ]
        run_matches = [v for v in versions if str(v.get("version_name", "")).startswith("run-")]
        if len(run_matches) == 1:
            item = run_matches[0]
            print(
                f"WARNING: exact version {version_name!r} not found; "
                f"using {item.get('version_name')!r}"
            )
            return int(item["version_id"]), str(item["version_name"])

    for item in versions:
        if int(item.get("current_version") or 0) == 1:
            print(
                f"WARNING: version {version_name!r} not found; "
                f"using current {item.get('version_name')!r}"
            )
            return int(item["version_id"]), str(item["version_name"])

    latest = max(versions, key=lambda v: int(v.get("version_id") or 0))
    print(
        f"WARNING: version {version_name!r} not found; "
        f"using latest {latest.get('version_name')!r}"
    )
    return int(latest["version_id"]), str(latest["version_name"])


def find_version_id(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_name: str,
) -> int:
    version_id, _ = resolve_version_id(session, base_url, project_id, version_name)
    return version_id


def list_project_agents(
    session: requests.Session,
    base_url: str,
    project_id: int,
    *,
    page_size: int = 100,
) -> list[dict]:
    """List agents bound to a project (v1 API)."""
    root = base_url.rstrip("/")
    resp = session.get(
        f"{root}/api/v1/agents",
        params={"bind_project_id": project_id, "pageSize": page_size},
        timeout=30,
    )
    resp.raise_for_status()
    body = _check_api_response(resp, "agent list")
    return list(body.get("data") or [])


def resolve_run_agent_ids(agents: list[dict], version_id: int) -> list[int]:
    """Agent ids for a CI run version; when several agents share a version, keep the latest."""
    matched = [
        int(agent["id"])
        for agent in agents
        if int(agent.get("project_version") or 0) == int(version_id)
    ]
    if matched:
        return [max(matched)]
    if agents:
        latest = max(agents, key=lambda agent: int(agent.get("id") or 0))
        return [int(latest["id"])]
    return []


def is_noise_finding(item: dict) -> bool:
    """Header-policy and sensitive-info findings are not benchmark planted vulns."""
    if str(item.get("is_header_vul", "")).lower() in ("1", "true", "yes"):
        return True
    name = str(item.get("strategy__vul_name") or item.get("type") or "")
    if name in HEADER_VUL_NAMES:
        return True
    return any(marker in name for marker in SENSITIVE_INFO_MARKERS)


def iter_vulnerabilities_v2(
    session: requests.Session,
    base_url: str,
    project_id: int,
    *,
    project_version_id: int | None = None,
    page_size: int = 200,
) -> Iterator[dict]:
    """Fetch all vulnerabilities via POST /api/v2/app_vul_list_content (paginated)."""
    root = base_url.rstrip("/")
    headers = {
        **csrf_headers(session),
        "Content-Type": "application/json",
    }
    page = 1
    while True:
        payload: dict[str, int] = {
            "page": page,
            "page_size": page_size,
            "bind_project_id": project_id,
        }
        if project_version_id:
            payload["project_version_id"] = project_version_id

        resp = session.post(
            f"{root}/api/v2/app_vul_list_content",
            json=payload,
            headers=headers,
            timeout=120,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("status") not in (200, 201):
            raise RuntimeError(f"vulnerability list failed: {body.get('msg')} (body={body!r})")
        items = (body.get("data") or {}).get("messages") or []
        if not items:
            break
        yield from items
        if len(items) < page_size:
            break
        page += 1


def iter_vulnerabilities(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    project_name: str = "",
    scope: str = "version",
    page_size: int = 200,
    exact_version: bool = False,
) -> Iterator[dict]:
    """Fetch vulnerabilities for scoring.

    scope:
      - version: cumulative backlog for bind_project_id + project_version_id
        (matches the panel when a project version is selected)
      - project: all open findings for the project

    exact_version: only rows whose project_version_id equals version_id
        (new in this run — e.g. +22 on the version card).
    """
    version_filter = version_id if scope == "version" else None
    for item in iter_vulnerabilities_v2(
        session,
        base_url,
        project_id,
        project_version_id=version_filter,
        page_size=page_size,
    ):
        if scope == "version" and exact_version:
            item_version = int(item.get("project_version_id") or 0)
            if item_version and item_version != int(version_id):
                continue
        yield item


def read_agent_properties(agent_jar: str) -> dict[str, str]:
    import zipfile
    from pathlib import Path

    path = Path(agent_jar)
    if not path.is_file():
        return {}
    props: dict[str, str] = {}
    try:
        with zipfile.ZipFile(path) as zf:
            raw = zf.read("iast.properties").decode("utf-8", errors="replace")
    except (KeyError, OSError):
        return props
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        props[key.strip()] = value.strip()
    return props
