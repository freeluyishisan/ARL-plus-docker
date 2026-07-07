import hashlib
import ipaddress
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
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
MCP_DATA_DIR = Path(os.getenv("MCP_DATA_DIR", "/data")).resolve()
MCP_MAX_PAGE_SIZE = int(os.getenv("MCP_MAX_PAGE_SIZE", "500"))
MCP_DEFAULT_MAX_PAGES = int(os.getenv("MCP_DEFAULT_MAX_PAGES", "10"))

mcp = FastMCP(MCP_NAME, host=MCP_HOST, port=MCP_PORT)


class ARLError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _ensure_data_dir() -> Path:
    MCP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    (MCP_DATA_DIR / "snapshots").mkdir(parents=True, exist_ok=True)
    (MCP_DATA_DIR / "exports").mkdir(parents=True, exist_ok=True)
    (MCP_DATA_DIR / "reports").mkdir(parents=True, exist_ok=True)
    return MCP_DATA_DIR


def _safe_name(value: str, fallback: str = "arl") -> str:
    value = (value or fallback).strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-._")
    return value[:120] or fallback


def _headers() -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "arl-plus-mcp/0.2",
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

    for key in ("items", "data", "result", "results", "rows", "records"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _normalize_items(value)
            if nested:
                return nested

    return []


def _get_total(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    for key in ("total", "count", "total_count"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    for value in payload.values():
        if isinstance(value, dict):
            nested = _get_total(value)
            if nested is not None:
                return nested
    return None


def _fetch_paged(path: str, task_id: str = "", size: int = 500, max_pages: int = 10, extra_params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    size = min(max(1, int(size)), MCP_MAX_PAGE_SIZE)
    max_pages = min(max(1, int(max_pages)), 100)

    items: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    for page in range(1, max_pages + 1):
        params: dict[str, Any] = {"page": page, "size": size}
        if task_id:
            params["task_id"] = task_id
        if extra_params:
            params.update(extra_params)

        payload = _request("GET", path, params=params)
        page_items = _normalize_items(payload)
        if not page_items:
            break

        for item in page_items:
            item_hash = hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()
            if item_hash not in seen_hashes:
                items.append(item)
                seen_hashes.add(item_hash)

        total = _get_total(payload)
        if total is not None and len(items) >= total:
            break

        if len(page_items) < size:
            break

    return items


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


def _extract_host(item: dict[str, Any]) -> str:
    url = _extract_url(item)
    if url:
        host = urlparse(url).hostname or ""
        if host:
            return host.lower().strip(".")
    for key in ("host", "domain", "ip", "addr"):
        value = item.get(key)
        if value:
            host = str(value).strip().split("/", 1)[0].split(":", 1)[0].lower().strip(".")
            if host:
                return host
    return ""


def _extract_port(item: dict[str, Any]) -> str:
    port = str(item.get("port", "") or "").strip()
    if port:
        return port
    url = _extract_url(item)
    if url:
        parsed = urlparse(url)
        if parsed.port:
            return str(parsed.port)
        if parsed.scheme == "https":
            return "443"
        if parsed.scheme == "http":
            return "80"
    return ""


def _extract_status(item: dict[str, Any]) -> str:
    for key in ("status", "status_code", "code"):
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _extract_title(item: dict[str, Any]) -> str:
    for key in ("title", "site_title", "web_title"):
        value = item.get(key)
        if value:
            return str(value).strip()
    return ""


def _extract_fingerprint(item: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("finger", "fingerprint", "app", "server", "service", "product", "component"):
        value = item.get(key)
        if isinstance(value, list):
            values.extend(str(v) for v in value if v)
        elif value:
            values.append(str(value))
    return ", ".join(dict.fromkeys(v.strip() for v in values if v.strip()))


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
        allowed = allowed.lstrip("*.") 
        if host == allowed or host.endswith("." + allowed):
            return

    raise ValueError(f"target is not in allowed scope: {target}")


CATEGORY_RULES: list[tuple[str, int, list[str]]] = [
    ("login_panel", 35, ["admin", "login", "signin", "sso", "auth", "oauth", "cas", "console", "dashboard", "manage", "manager", "后台", "登录", "管理"]),
    ("api_asset", 30, ["api", "gateway", "openapi", "swagger", "graphql", "rest", "接口", "knife4j", "yapi", "apifox"]),
    ("dev_test_asset", 25, ["dev", "test", "uat", "stage", "staging", "beta", "pre", "sandbox", "qa", "sit"]),
    ("ops_middleware", 20, ["jenkins", "gitlab", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "etcd", "rabbitmq", "redis", "mongo", "elasticsearch", "solr", "actuator"]),
    ("storage_cdn", 15, ["oss", "cos", "s3", "bucket", "minio", "cdn", "static", "upload", "file"]),
    ("doc_portal", 10, ["docs", "doc", "portal", "wiki", "help", "manual", "readme"]),
    ("payment_business", 10, ["pay", "payment", "order", "trade", "cart", "checkout", "invoice", "wallet"]),
]


def _site_blob(item: dict[str, Any]) -> str:
    url = _extract_url(item)
    text = " ".join(str(v) for v in item.values() if v is not None).lower()
    return f"{url} {text}".lower()


def _categorize_site(item: dict[str, Any]) -> list[str]:
    blob = _site_blob(item)
    categories = []
    for category, _weight, keywords in CATEGORY_RULES:
        if any(keyword in blob for keyword in keywords):
            categories.append(category)

    port = _extract_port(item)
    if port and port not in {"80", "443"}:
        categories.append("non_standard_port")

    status = _extract_status(item)
    if status.startswith(("2", "3")):
        categories.append("alive")

    if not categories:
        categories.append("normal_web")

    return categories


def _interesting_score(item: dict[str, Any]) -> tuple[int, list[str]]:
    blob = _site_blob(item)
    score = 0
    reasons: list[str] = []

    for category, weight, keywords in CATEGORY_RULES:
        if any(keyword in blob for keyword in keywords):
            score += weight
            reasons.append(category)

    port = _extract_port(item)
    if port and port not in {"80", "443"}:
        score += 10
        reasons.append(f"non-standard-port:{port}")

    status = _extract_status(item)
    if status.startswith(("2", "3")):
        score += 5
        reasons.append(f"alive:{status}")

    fingerprint = _extract_fingerprint(item).lower()
    if fingerprint and any(key in fingerprint for key in ["spring", "tomcat", "weblogic", "shiro", "struts", "thinkphp", "phpmyadmin"]):
        score += 10
        reasons.append("sensitive-fingerprint")

    return score, reasons


def _asset_id(item: dict[str, Any]) -> str:
    url = _extract_url(item)
    host = _extract_host(item)
    port = _extract_port(item)
    title = _extract_title(item)
    fingerprint = _extract_fingerprint(item)
    material = "|".join([url, host, port, title, fingerprint])
    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _normalize_site(item: dict[str, Any]) -> dict[str, Any]:
    score, reasons = _interesting_score(item)
    url = _extract_url(item)
    host = _extract_host(item)
    port = _extract_port(item)
    title = _extract_title(item)
    fingerprint = _extract_fingerprint(item)
    categories = _categorize_site(item)
    status = _extract_status(item)

    return {
        "id": _asset_id(item),
        "score": score,
        "reasons": reasons,
        "categories": categories,
        "url": url,
        "host": host,
        "port": port,
        "status": status,
        "title": title,
        "fingerprint": fingerprint,
        "raw": item,
    }


def _rank_sites(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = [_normalize_site(item) for item in items]
    ranked.sort(key=lambda row: (row["score"], row["url"], row["host"]), reverse=True)
    return ranked


def _filter_sites(ranked: list[dict[str, Any]], category: str = "", min_score: int = 0) -> list[dict[str, Any]]:
    result = []
    for item in ranked:
        if int(item["score"]) < int(min_score):
            continue
        if category and category not in item["categories"] and category not in item["reasons"]:
            continue
        result.append(item)
    return result


def _load_snapshot(path: str) -> dict[str, Any]:
    snapshot_path = Path(path)
    if not snapshot_path.is_absolute():
        snapshot_path = MCP_DATA_DIR / "snapshots" / snapshot_path.name
    if not snapshot_path.exists():
        raise FileNotFoundError(f"snapshot not found: {snapshot_path}")
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


def _snapshot_diff(old_snapshot: dict[str, Any], new_snapshot: dict[str, Any]) -> dict[str, Any]:
    old_items = {item["id"]: item for item in old_snapshot.get("items", []) if isinstance(item, dict) and item.get("id")}
    new_items = {item["id"]: item for item in new_snapshot.get("items", []) if isinstance(item, dict) and item.get("id")}

    added_ids = sorted(set(new_items) - set(old_items))
    removed_ids = sorted(set(old_items) - set(new_items))
    common_ids = sorted(set(old_items) & set(new_items))

    changed = []
    for asset_id in common_ids:
        old = old_items[asset_id]
        new = new_items[asset_id]
        fields = {}
        for key in ("url", "host", "port", "status", "title", "fingerprint", "score", "categories"):
            if old.get(key) != new.get(key):
                fields[key] = {"old": old.get(key), "new": new.get(key)}
        if fields:
            changed.append({"id": asset_id, "url": new.get("url") or old.get("url"), "changes": fields})

    added = [new_items[asset_id] for asset_id in added_ids]
    removed = [old_items[asset_id] for asset_id in removed_ids]

    return {
        "old_snapshot": old_snapshot.get("snapshot_file", old_snapshot.get("created_at")),
        "new_snapshot": new_snapshot.get("snapshot_file", new_snapshot.get("created_at")),
        "old_count": len(old_items),
        "new_count": len(new_items),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _summarize_sites(ranked: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    by_port: Counter[str] = Counter()
    by_fingerprint: Counter[str] = Counter()

    for item in ranked:
        by_category.update(item.get("categories", []))
        status = item.get("status") or "unknown"
        port = item.get("port") or "unknown"
        by_status[status] += 1
        by_port[port] += 1
        fp = item.get("fingerprint") or "unknown"
        for piece in str(fp).split(","):
            piece = piece.strip()
            if piece:
                by_fingerprint[piece] += 1

    return {
        "total": len(ranked),
        "by_category": dict(by_category.most_common()),
        "by_status": dict(by_status.most_common(20)),
        "by_port": dict(by_port.most_common(20)),
        "by_fingerprint": dict(by_fingerprint.most_common(20)),
        "top_assets": ranked[:20],
    }


def _markdown_report(ranked: list[dict[str, Any]], min_score: int = 20) -> str:
    summary = _summarize_sites(ranked)
    high = [item for item in ranked if int(item["score"]) >= int(min_score)]

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in high:
        for category in item.get("categories", []):
            buckets[category].append(item)

    lines = [
        "# ARL 攻击面资产报告",
        "",
        f"- 生成时间：{_now()}",
        f"- 资产总数：{summary['total']}",
        f"- 高价值资产：{len(high)}",
        "",
        "## 分类统计",
        "",
    ]

    for category, count in summary["by_category"].items():
        lines.append(f"- {category}: {count}")

    lines.extend(["", "## 高价值资产 Top 20", ""])

    for idx, item in enumerate(high[:20], 1):
        lines.append(f"{idx}. `{item.get('url') or item.get('host')}`")
        lines.append(f"   - score: {item['score']}")
        lines.append(f"   - categories: {', '.join(item.get('categories', []))}")
        if item.get("title"):
            lines.append(f"   - title: {item['title']}")
        if item.get("fingerprint"):
            lines.append(f"   - fingerprint: {item['fingerprint']}")
        if item.get("status"):
            lines.append(f"   - status: {item['status']}")
        lines.append("")

    lines.extend(["## 按场景分组", ""])

    for category in [
        "login_panel",
        "api_asset",
        "dev_test_asset",
        "ops_middleware",
        "storage_cdn",
        "doc_portal",
        "payment_business",
        "non_standard_port",
    ]:
        items = buckets.get(category, [])
        if not items:
            continue
        lines.append(f"### {category}")
        for item in items[:30]:
            lines.append(f"- `{item.get('url') or item.get('host')}` score={item['score']} title={item.get('title') or '-'}")
        lines.append("")

    lines.extend([
        "## 后续验证建议",
        "",
        "- login_panel：优先检查登录态、权限矩阵、越权、SSO 回跳、会话固定、账号隔离。",
        "- api_asset：优先检查接口枚举、鉴权缺失、对象级权限、批量查询、IDOR、租户隔离。",
        "- dev_test_asset：优先确认是否误暴露、是否连接生产数据、是否存在调试接口或默认账号。",
        "- ops_middleware：优先确认访问控制、版本、默认路径、未授权面板、弱鉴权配置。",
        "- storage_cdn：优先确认对象读写权限、目录索引、敏感文件、跨域策略和上传链路。",
        "",
    ])

    return "\n".join(lines)


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
        "mcp_data_dir": str(MCP_DATA_DIR),
        "mcp_max_page_size": MCP_MAX_PAGE_SIZE,
        "mcp_default_max_pages": MCP_DEFAULT_MAX_PAGES,
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
    size = min(max(1, int(size)), MCP_MAX_PAGE_SIZE)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/site/", params=params)


@mcp.tool()
def arl_get_domains(page: int = 1, size: int = 100, task_id: str = "") -> dict[str, Any]:
    """Get ARL discovered domain assets."""
    page = max(1, int(page))
    size = min(max(1, int(size)), MCP_MAX_PAGE_SIZE)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/domain/", params=params)


@mcp.tool()
def arl_get_ports(page: int = 1, size: int = 100, task_id: str = "") -> dict[str, Any]:
    """Get ARL discovered port assets if the ARL version exposes /api/port/."""
    page = max(1, int(page))
    size = min(max(1, int(size)), MCP_MAX_PAGE_SIZE)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/port/", params=params)


@mcp.tool()
def arl_score_sites(task_id: str = "", size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Rank discovered sites by pentest follow-up value using local scoring rules."""
    items = _fetch_paged("/api/site/", task_id=task_id, size=size, max_pages=max_pages)
    ranked = _rank_sites(items)
    return {"count": len(ranked), "items": ranked}


@mcp.tool()
def arl_find_interesting_sites(task_id: str = "", min_score: int = 20, size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Return high-value sites such as login panels, APIs, Swagger, test/dev assets, and ops middleware."""
    scored = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)
    items = _filter_sites(scored["items"], min_score=min_score)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_login_panels(task_id: str = "", size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Return likely login/admin/SSO/console assets."""
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    items = _filter_sites(ranked, category="login_panel", min_score=1)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_api_assets(task_id: str = "", size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Return likely API, gateway, Swagger, OpenAPI, GraphQL, and API doc assets."""
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    items = _filter_sites(ranked, category="api_asset", min_score=1)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_dev_assets(task_id: str = "", size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Return likely dev/test/uat/stage/beta assets."""
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    items = _filter_sites(ranked, category="dev_test_asset", min_score=1)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_ops_assets(task_id: str = "", size: int = 500, max_pages: int = 5) -> dict[str, Any]:
    """Return likely exposed ops middleware assets such as Jenkins, GitLab, Grafana, Kibana, Redis panels, and similar systems."""
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    items = _filter_sites(ranked, category="ops_middleware", min_score=1)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_export_urls(task_id: str = "", category: str = "", min_score: int = 0, size: int = 500, max_pages: int = 5, output_format: str = "text") -> dict[str, Any]:
    """Export ranked URLs for follow-up tools. output_format can be text, json, or markdown."""
    _ensure_data_dir()
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    items = _filter_sites(ranked, category=category, min_score=min_score)
    urls = [item["url"] for item in items if item.get("url")]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = _safe_name(category or "all")
    if output_format == "json":
        content = json.dumps(items, ensure_ascii=False, indent=2)
        ext = "json"
    elif output_format == "markdown":
        lines = [f"- `{item['url']}` score={item['score']} categories={','.join(item['categories'])}" for item in items if item.get("url")]
        content = "\n".join(lines) + "\n"
        ext = "md"
    else:
        content = "\n".join(urls) + ("\n" if urls else "")
        ext = "txt"

    path = MCP_DATA_DIR / "exports" / f"urls-{suffix}-{stamp}.{ext}"
    path.write_text(content, encoding="utf-8")

    return {
        "count": len(urls),
        "category": category,
        "min_score": min_score,
        "output_format": output_format,
        "file": str(path),
        "urls": urls[:500],
    }


@mcp.tool()
def arl_snapshot_sites(task_id: str = "", name: str = "", size: int = 500, max_pages: int = 10) -> dict[str, Any]:
    """Create a persisted normalized site snapshot for later diffing."""
    _ensure_data_dir()
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    summary = _summarize_sites(ranked)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    label = _safe_name(name or task_id or "all")
    path = MCP_DATA_DIR / "snapshots" / f"{label}-{stamp}.json"

    snapshot = {
        "created_at": _now(),
        "task_id": task_id,
        "name": name,
        "snapshot_file": str(path),
        "summary": summary,
        "items": ranked,
    }
    path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "file": str(path),
        "created_at": snapshot["created_at"],
        "task_id": task_id,
        "count": len(ranked),
        "summary": summary,
    }


@mcp.tool()
def arl_list_snapshots() -> dict[str, Any]:
    """List persisted site snapshots."""
    _ensure_data_dir()
    files = sorted((MCP_DATA_DIR / "snapshots").glob("*.json"), reverse=True)
    items = []
    for path in files[:200]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items.append({
                "file": str(path),
                "created_at": data.get("created_at", ""),
                "task_id": data.get("task_id", ""),
                "name": data.get("name", ""),
                "count": len(data.get("items", [])),
            })
        except Exception as exc:
            items.append({"file": str(path), "error": str(exc)})
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_diff_snapshots(old_snapshot_file: str, new_snapshot_file: str) -> dict[str, Any]:
    """Diff two persisted snapshots and return added, removed, and changed assets."""
    old_snapshot = _load_snapshot(old_snapshot_file)
    new_snapshot = _load_snapshot(new_snapshot_file)
    return _snapshot_diff(old_snapshot, new_snapshot)


@mcp.tool()
def arl_diff_latest_sites(task_id: str = "", name: str = "", size: int = 500, max_pages: int = 10) -> dict[str, Any]:
    """Create a fresh snapshot and diff it against the previous snapshot for the same task/name label."""
    _ensure_data_dir()
    label = _safe_name(name or task_id or "all")
    existing = sorted((MCP_DATA_DIR / "snapshots").glob(f"{label}-*.json"))

    new_snapshot_meta = arl_snapshot_sites(task_id=task_id, name=name, size=size, max_pages=max_pages)
    new_snapshot = _load_snapshot(new_snapshot_meta["file"])

    if not existing:
        return {
            "baseline_exists": False,
            "new_snapshot": new_snapshot_meta["file"],
            "message": "no previous snapshot for this label",
            "diff": {
                "old_count": 0,
                "new_count": new_snapshot_meta["count"],
                "added_count": new_snapshot_meta["count"],
                "removed_count": 0,
                "changed_count": 0,
                "added": new_snapshot.get("items", []),
                "removed": [],
                "changed": [],
            },
        }

    old_snapshot = _load_snapshot(str(existing[-1]))
    diff = _snapshot_diff(old_snapshot, new_snapshot)
    return {
        "baseline_exists": True,
        "old_snapshot": str(existing[-1]),
        "new_snapshot": new_snapshot_meta["file"],
        "diff": diff,
    }


@mcp.tool()
def arl_attack_surface_report(task_id: str = "", min_score: int = 20, size: int = 500, max_pages: int = 10, save: bool = True) -> dict[str, Any]:
    """Build a markdown attack-surface report from ARL site assets."""
    _ensure_data_dir()
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]
    markdown = _markdown_report(ranked, min_score=min_score)

    result: dict[str, Any] = {
        "created_at": _now(),
        "task_id": task_id,
        "count": len(ranked),
        "summary": _summarize_sites(ranked),
        "markdown": markdown,
    }

    if save:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        label = _safe_name(task_id or "all")
        path = MCP_DATA_DIR / "reports" / f"attack-surface-{label}-{stamp}.md"
        path.write_text(markdown, encoding="utf-8")
        result["file"] = str(path)

    return result


@mcp.tool()
def arl_build_followup_plan(task_id: str = "", size: int = 500, max_pages: int = 10) -> dict[str, Any]:
    """Create a follow-up testing plan split by ider/worker/heier roles from ranked ARL assets."""
    ranked = arl_score_sites(task_id=task_id, size=size, max_pages=max_pages)["items"]

    buckets = {
        "login_panel": _filter_sites(ranked, category="login_panel", min_score=1)[:30],
        "api_asset": _filter_sites(ranked, category="api_asset", min_score=1)[:30],
        "dev_test_asset": _filter_sites(ranked, category="dev_test_asset", min_score=1)[:30],
        "ops_middleware": _filter_sites(ranked, category="ops_middleware", min_score=1)[:30],
        "storage_cdn": _filter_sites(ranked, category="storage_cdn", min_score=1)[:30],
        "non_standard_port": _filter_sites(ranked, category="non_standard_port", min_score=1)[:30],
    }

    tasks = []
    role_map = {
        "login_panel": {
            "ider": "设计登录态、权限矩阵、SSO 回跳、会话边界测试思路。",
            "worker": "只在授权账号内复现登录态流程，记录请求、角色、资源 ID、响应差异。",
            "heier": "复核是否存在越权证据、是否有业务影响、是否误把普通登录页当漏洞。",
        },
        "api_asset": {
            "ider": "拆 API 枚举、对象级权限、租户隔离、批量查询、参数边界测试思路。",
            "worker": "基于正常业务请求做最小化重放，记录鉴权头、对象 ID、响应字段。",
            "heier": "复核是否有跨用户/跨租户读取或修改证据，去除误报。",
        },
        "dev_test_asset": {
            "ider": "判断测试环境是否连接真实数据、是否存在调试入口、版本泄露和默认配置。",
            "worker": "只做访问控制和信息暴露验证，不破坏数据。",
            "heier": "复核环境归属、数据真实性和可提交性。",
        },
        "ops_middleware": {
            "ider": "识别中间件类型、认证边界、版本、默认路径和暴露面。",
            "worker": "验证访问控制、页面证据和版本信息，不做破坏性操作。",
            "heier": "确认是否属于有效暴露，避免把受保护登录页当成果。",
        },
        "storage_cdn": {
            "ider": "设计对象存储读权限、列表权限、上传链路、敏感文件验证方案。",
            "worker": "只验证读取/列表/上传权限边界，避免覆盖或删除对象。",
            "heier": "复核对象权限影响范围和证据链。",
        },
        "non_standard_port": {
            "ider": "根据端口和指纹判断服务类型，设计低风险访问控制验证。",
            "worker": "记录服务 banner、HTTP 标题、证书、访问控制表现。",
            "heier": "复核是否为真实业务暴露、是否可提交。",
        },
    }

    for category, assets in buckets.items():
        if not assets:
            continue
        tasks.append({
            "category": category,
            "asset_count": len(assets),
            "top_assets": assets[:10],
            "roles": role_map[category],
        })

    return {
        "created_at": _now(),
        "task_id": task_id,
        "asset_count": len(ranked),
        "tasks": tasks,
    }


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse").strip().lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse")
