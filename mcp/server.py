import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

from arl_boost import (
    build_snapshot,
    diff_snapshots,
    export_urls,
    followup_plan,
    make_markdown_report,
    normalize_items,
    score_assets,
    summarize_scored,
)


ARL_BASE_URL = os.getenv("ARL_BASE_URL", "https://web:443").rstrip("/")
ARL_TOKEN = os.getenv("ARL_TOKEN", "")
ARL_VERIFY_TLS = os.getenv("ARL_VERIFY_TLS", "false").strip().lower() in {"1", "true", "yes", "on"}
ARL_TIMEOUT = float(os.getenv("ARL_TIMEOUT", "30"))
ARL_ALLOWED_SUFFIXES = [
    item.strip().lower()
    for item in os.getenv("ARL_ALLOWED_SUFFIXES", "").split(",")
    if item.strip()
]

MCP_NAME = os.getenv("MCP_NAME", "arl-plus-mcp")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8765"))

mcp = FastMCP(MCP_NAME, host=MCP_HOST, port=MCP_PORT)


class ARLError(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "arl-plus-mcp/0.2",
    }
    if ARL_TOKEN:
        headers["token"] = ARL_TOKEN
    return headers


def _request(method: str, path: str, **kwargs: Any) -> Any:
    if not path.startswith("/"):
        path = "/" + path

    try:
        resp = requests.request(
            method=method.upper(),
            url=f"{ARL_BASE_URL}{path}",
            headers=_headers(),
            verify=ARL_VERIFY_TLS,
            timeout=ARL_TIMEOUT,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise ARLError(f"ARL request failed: {exc}") from exc

    if resp.status_code >= 400:
        body = resp.text[:500]
        raise ARLError(f"ARL API error {resp.status_code}: {body}")

    if not resp.text.strip():
        return {"ok": True, "status_code": resp.status_code}

    try:
        return resp.json()
    except ValueError:
        return {"ok": True, "status_code": resp.status_code, "text": resp.text[:2000]}


def _hostname_from_target(target: str) -> str:
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        host = urlparse(target).hostname or ""
    else:
        host = target.split("/", 1)[0].split(":", 1)[0]
    return host.strip(".")


def _is_ip_or_cidr(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_target(target: str) -> None:
    if not target or not isinstance(target, str):
        raise ValueError("target is required")

    clean = target.strip()
    if len(clean) > 253:
        raise ValueError("target is too long")

    if any(ch in clean for ch in ["?", "#", "@", " ", "\t", "\r", "\n"]):
        raise ValueError("target must be a plain domain, IP, or CIDR, not a URL with path/query")

    host = _hostname_from_target(clean)
    if not host:
        raise ValueError("invalid target")

    if not re.fullmatch(r"[a-z0-9.*:/_-]+", clean.lower()):
        raise ValueError("target contains unsupported characters")

    if not ARL_ALLOWED_SUFFIXES:
        raise ValueError("ARL_ALLOWED_SUFFIXES is empty; refuse to create scan task")

    if "*" in ARL_ALLOWED_SUFFIXES:
        return

    if _is_ip_or_cidr(host):
        for allowed in ARL_ALLOWED_SUFFIXES:
            if _is_ip_or_cidr(allowed):
                try:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(allowed, strict=False):
                        return
                except ValueError:
                    pass
        raise ValueError(f"target is not in allowed scope: {target}")

    for allowed in ARL_ALLOWED_SUFFIXES:
        allowed = allowed.lstrip("*.")
        if host == allowed or host.endswith("." + allowed):
            return

    raise ValueError(f"target is not in allowed scope: {target}")


def _fetch_site_items(page: int = 1, size: int = 100, task_id: str = "") -> list[dict[str, Any]]:
    payload = arl_get_sites(page=page, size=size, task_id=task_id)
    return normalize_items(payload)


def _fetch_scored_sites(task_id: str = "", size: int = 200) -> list[dict[str, Any]]:
    items = _fetch_site_items(page=1, size=size, task_id=task_id)
    return score_assets(items)


@mcp.tool()
def arl_mcp_config() -> dict[str, Any]:
    """Return ARL MCP wrapper runtime config without leaking the token."""
    return {
        "arl_base_url": ARL_BASE_URL,
        "arl_verify_tls": ARL_VERIFY_TLS,
        "arl_token_configured": bool(ARL_TOKEN),
        "arl_allowed_suffixes": ARL_ALLOWED_SUFFIXES,
        "mcp_name": MCP_NAME,
        "mcp_host": MCP_HOST,
        "mcp_port": MCP_PORT,
        "version": "0.2",
    }


@mcp.tool()
def arl_health() -> dict[str, Any]:
    """Check whether the ARL web API is reachable."""
    try:
        payload = _request("GET", "/api/task/", params={"page": 1, "size": 1})
        return {"ok": True, "api": "/api/task/", "payload_type": type(payload).__name__}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
def arl_create_task(name: str, target: str, port_scan_type: str = "top100", domain_brute_type: str = "big") -> dict[str, Any]:
    """Create a scoped ARL asset discovery task for one allowed domain, IP, or CIDR."""
    _validate_target(target)

    body = {
        "name": name,
        "target": target,
        "domain_brute_type": domain_brute_type,
        "port_scan_type": port_scan_type,
        "domain_brute": True,
        "alt_dns": True,
        "arl_search": True,
        "port_scan": True,
        "service_detection": True,
        "os_detection": False,
        "ssl_cert": True,
        "site_identify": True,
        "site_spider": False,
        "site_capture": True,
        "file_leak": False,
        "search_engines": True,
    }
    return _request("POST", "/api/task/", json=body)


@mcp.tool()
def arl_list_tasks(page: int = 1, size: int = 20) -> dict[str, Any]:
    """List ARL tasks."""
    page = max(1, int(page))
    size = min(max(1, int(size)), 100)
    return _request("GET", "/api/task/", params={"page": page, "size": size})


@mcp.tool()
def arl_get_sites(page: int = 1, size: int = 100, task_id: str = "") -> dict[str, Any]:
    """Get ARL discovered site assets."""
    page = max(1, int(page))
    size = min(max(1, int(size)), 500)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/site/", params=params)


@mcp.tool()
def arl_get_domains(page: int = 1, size: int = 100, task_id: str = "") -> dict[str, Any]:
    """Get ARL discovered domain assets."""
    page = max(1, int(page))
    size = min(max(1, int(size)), 500)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/domain/", params=params)


@mcp.tool()
def arl_score_sites(task_id: str = "", size: int = 200) -> dict[str, Any]:
    """Rank discovered sites by local asset-intelligence scoring rules."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    return {"count": len(ranked), "items": ranked}


@mcp.tool()
def arl_find_interesting_sites(task_id: str = "", min_score: int = 20, size: int = 200, categories: list[str] | None = None) -> dict[str, Any]:
    """Return high-value sites such as login panels, APIs, documents, test/dev assets, and ops middleware."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    wanted = set(categories or [])
    items = []
    for item in ranked:
        if int(item.get("score", 0)) < int(min_score):
            continue
        if wanted and not (wanted & set(item.get("categories", []))):
            continue
        items.append(item)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_asset_brief(task_id: str = "", size: int = 300, top: int = 20) -> dict[str, Any]:
    """Summarize ARL assets into buckets, categories, fingerprints, status codes, and top assets."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    return summarize_scored(ranked, top=top)


@mcp.tool()
def arl_export_urls(task_id: str = "", min_score: int = 20, size: int = 300, limit: int = 300, categories: list[str] | None = None) -> dict[str, Any]:
    """Export ranked URLs for downstream manual validation or browser-based review."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    urls = export_urls(ranked, min_score=min_score, categories=categories, limit=limit)
    return {"count": len(urls), "urls": urls, "text": "\n".join(urls)}


@mcp.tool()
def arl_markdown_report(task_id: str = "", size: int = 300, limit: int = 50, title: str = "ARL AI Asset Report") -> dict[str, Any]:
    """Generate a Markdown report for high-value ARL assets."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    report = make_markdown_report(ranked, title=title, limit=limit)
    return {"markdown": report, "count": len(ranked)}


@mcp.tool()
def arl_asset_snapshot(task_id: str = "", size: int = 500) -> dict[str, Any]:
    """Return a compact asset snapshot for later diffing."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    return build_snapshot(ranked)


@mcp.tool()
def arl_diff_snapshots(old_snapshot: dict[str, Any], new_snapshot: dict[str, Any]) -> dict[str, Any]:
    """Diff two snapshots returned by arl_asset_snapshot."""
    return diff_snapshots(old_snapshot, new_snapshot)


@mcp.tool()
def arl_followup_plan(task_id: str = "", size: int = 300, limit: int = 30) -> dict[str, Any]:
    """Generate grouped follow-up tasks for AI/Hermes-style asset review."""
    ranked = _fetch_scored_sites(task_id=task_id, size=size)
    tasks = followup_plan(ranked, limit=limit)
    return {"count": len(tasks), "tasks": tasks}


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse").strip().lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse")
