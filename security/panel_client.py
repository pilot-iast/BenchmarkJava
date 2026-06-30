"""Immunity IAST panel API helpers (login, projects, versions, vulnerabilities)."""

from __future__ import annotations

from typing import Iterator

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


def find_project_id(session: requests.Session, base_url: str, project_name: str) -> int:
    root = base_url.rstrip("/")
    resp = session.get(
        f"{root}/api/v1/project/search",
        params={"name": project_name},
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"project search failed: {body.get('msg')}")
    for item in body.get("data") or []:
        if item.get("name") == project_name:
            return int(item["id"])
    for item in body.get("data") or []:
        if project_name.lower() in str(item.get("name", "")).lower():
            return int(item["id"])
    raise RuntimeError(f"project not found: {project_name!r}")


def list_project_versions(
    session: requests.Session, base_url: str, project_id: int
) -> list[dict]:
    root = base_url.rstrip("/")
    resp = session.get(f"{root}/api/v1/project/version/list/{project_id}", timeout=30)
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"version list failed: {body.get('msg')}")
    return list(body.get("data") or [])


def find_version_id(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_name: str,
) -> int:
    versions = list_project_versions(session, base_url, project_id)
    for item in versions:
        if item.get("version_name") == version_name:
            return int(item["version_id"])
    raise RuntimeError(
        f"project version not found: {version_name!r} "
        f"(available: {[v.get('version_name') for v in versions[:10]]})"
    )


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
        body = resp.json()
        if body.get("status") not in (201, 200):
            raise RuntimeError(f"vulnerability list failed: {body.get('msg')}")
        data = body.get("data") or {}
        messages = data.get("messages") or []
        if not messages:
            break
        yield from messages
        if len(messages) < page_size:
            break
        page += 1
