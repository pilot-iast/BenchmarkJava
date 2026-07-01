"""Immunity IAST panel API helpers (login, projects, versions, vulnerabilities)."""

from __future__ import annotations

import os
from typing import Iterator

import requests


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
    token = session.cookies.get("csrftoken")
    headers = {"Referer": session.headers.get("Referer", "")}
    if token:
        headers["X-CSRFToken"] = token
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


def iter_vulnerabilities(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    page_size: int = 200,
) -> Iterator[dict]:
    root = base_url.rstrip("/")
    page = 1
    while True:
        resp = session.post(
            f"{root}/api/v2/app_vul_list_content",
            json={
                "page": page,
                "page_size": page_size,
                "bind_project_id": project_id,
                "project_version_id": version_id,
            },
            headers=csrf_headers(session),
            timeout=120,
        )
        resp.raise_for_status()
        body = _check_api_response(resp, "vulnerability list")
        data = body.get("data") or {}
        messages = data.get("messages") or []
        if not messages:
            break
        yield from messages
        if len(messages) < page_size:
            break
        page += 1


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
