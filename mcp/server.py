import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP


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
        "User-Agent": "arl-plus-mcp/0.1",
    }
    if ARL_TOKEN:
        # ARL API examples commonly use a `token` header.
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


def _normalize_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    for key in ("items", "data", "result", "results", "rows"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _normalize_items(value)
            if nested:
                return nested

    return []


def _extract_url(item: dict[str, Any]) -> str:
    for key in ("site", "url", "link", "addr", "host", "domain"):
        value = item.get(key)
        if value:
            text = str(value).strip()
            if not text:
                continue
            if text.startswith(("http://", "https://")):
                return text
            port = str(item.get("port", "")).strip()
            scheme = "https" if port in {"443", "8443"} else "http"
            if port and ":" not in text:
                return f"{scheme}://{text}:{port}"
            return f"{scheme}://{text}"
    return ""


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

    # Keep the wrapper scoped to simple ARL targets. Do not accept paths or query strings.
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
        allowed = allowed.lstrip("*." )
        if host == allowed or host.endswith("." + allowed):
            return

    raise ValueError(f"target is not in allowed scope: {target}")


def _interesting_score(item: dict[str, Any]) -> tuple[int, list[str]]:
    url = _extract_url(item)
    text = " ".join(str(v) for v in item.values() if v is not None).lower()
    blob = f"{url} {text}".lower()

    score = 0
    reasons: list[str] = []

    rules: list[tuple[int, str, list[str]]] = [
        (35, "admin/login/console", ["admin", "login", "signin", "sso", "auth", "oauth", "cas", "console", "dashboard", "manage", "manager", "后台", "登录", "管理"]),
        (30, "api/gateway/swagger", ["api", "gateway", "openapi", "swagger", "graphql", "rest", "接口"]),
        (25, "test/dev/stage", ["dev", "test", "uat", "stage", "staging", "beta", "pre", "sandbox", "qa"]),
        (20, "ops middleware", ["jenkins", "gitlab", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "etcd", "rabbitmq", "redis", "mongo", "elasticsearch"]),
        (15, "object storage/cdn", ["oss", "cos", "s3", "bucket", "minio", "cdn"]),
        (10, "doc/portal", ["docs", "doc", "portal", "wiki", "help"]),
    ]

    for weight, reason, keywords in rules:
        if any(keyword in blob for keyword in keywords):
            score += weight
            reasons.append(reason)

    port = str(item.get("port", ""))
    if port and port not in {"80", "443"}:
        score += 10
        reasons.append(f"non-standard-port:{port}")

    status = str(item.get("status", item.get("status_code", "")))
    if status.startswith(("2", "3")):
        score += 5
        reasons.append(f"alive:{status}")

    return score, reasons


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
    """Rank discovered sites by pentest follow-up value using local scoring rules."""
    payload = arl_get_sites(page=1, size=size, task_id=task_id)
    items = _normalize_items(payload)

    ranked: list[dict[str, Any]] = []
    for item in items:
        score, reasons = _interesting_score(item)
        url = _extract_url(item)
        ranked.append({
            "score": score,
            "reasons": reasons,
            "url": url,
            "title": item.get("title") or item.get("site_title") or "",
            "status": item.get("status") or item.get("status_code") or "",
            "fingerprint": item.get("finger") or item.get("fingerprint") or item.get("app") or "",
            "raw": item,
        })

    ranked.sort(key=lambda row: row["score"], reverse=True)
    return {"count": len(ranked), "items": ranked}


@mcp.tool()
def arl_find_interesting_sites(task_id: str = "", min_score: int = 20, size: int = 200) -> dict[str, Any]:
    """Return high-value sites such as login panels, APIs, Swagger, test/dev assets, and ops middleware."""
    scored = arl_score_sites(task_id=task_id, size=size)
    items = [item for item in scored["items"] if int(item["score"]) >= int(min_score)]
    return {"count": len(items), "items": items}


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse").strip().lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse")
