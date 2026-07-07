import hashlib
import ipaddress
import json
import os
import re
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
ARL_DATA_DIR = Path(os.getenv("ARL_DATA_DIR", "/data"))
ARL_SNAPSHOT_DIR = ARL_DATA_DIR / "snapshots"

MCP_NAME = os.getenv("MCP_NAME", "arl-plus-mcp")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8765"))

mcp = FastMCP(MCP_NAME, host=MCP_HOST, port=MCP_PORT)


class ARLError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_name(value: str) -> str:
    value = (value or "default").strip()
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value[:120] or "default"


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

    for key in ("items", "data", "result", "results", "rows", "list"):
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


def _canonical_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
    if not parsed.hostname:
        return ""
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc.lower()
    return f"{scheme}://{netloc}".rstrip("/")


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
        allowed = allowed.lstrip("*.").strip()
        if host == allowed or host.endswith("." + allowed):
            return

    raise ValueError(f"target is not in allowed scope: {target}")


def _blob_from_item(item: dict[str, Any]) -> str:
    url = _extract_url(item)
    text = " ".join(str(v) for v in item.values() if v is not None)
    return f"{url} {text}".lower()


def _rule_score(blob: str, rules: list[tuple[int, str, list[str]]]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for weight, reason, keywords in rules:
        if any(keyword in blob for keyword in keywords):
            score += weight
            reasons.append(reason)
    return score, reasons


def _interesting_score(item: dict[str, Any]) -> tuple[int, list[str], list[str]]:
    blob = _blob_from_item(item)

    rules: list[tuple[int, str, list[str]]] = [
        (40, "admin/login/console", ["admin", "login", "signin", "sso", "auth", "oauth", "cas", "console", "dashboard", "manage", "manager", "后台", "登录", "管理"]),
        (35, "api/gateway/swagger", ["api", "gateway", "openapi", "swagger", "graphql", "rest", "接口", "apifox", "knife4j"]),
        (30, "test/dev/stage", ["dev", "test", "uat", "stage", "staging", "beta", "pre", "sandbox", "qa", "sit"]),
        (25, "ops middleware", ["jenkins", "gitlab", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "etcd", "rabbitmq", "redis", "mongo", "elasticsearch", "solr", "xxl-job", "nacos"]),
        (20, "object storage/cdn", ["oss", "cos", "s3", "bucket", "minio", "cdn", "static", "upload"]),
        (15, "doc/portal", ["docs", "doc", "portal", "wiki", "help", "manual", "文档"]),
        (15, "identity/tenant", ["tenant", "org", "role", "permission", "iam", "rbac", "usercenter", "account"]),
        (10, "payment/order", ["pay", "payment", "order", "trade", "cart", "invoice", "wallet"]),
    ]

    score, reasons = _rule_score(blob, rules)
    tags = list(reasons)

    port = str(item.get("port", ""))
    if port and port not in {"80", "443"}:
        score += 10
        reasons.append(f"non-standard-port:{port}")
        tags.append("non-standard-port")

    status = str(item.get("status", item.get("status_code", "")))
    if status.startswith(("2", "3")):
        score += 5
        reasons.append(f"alive:{status}")
        tags.append("alive")

    title = str(item.get("title") or item.get("site_title") or "")
    if title and len(title) <= 3:
        score += 3
        reasons.append("short-title")
        tags.append("short-title")

    return score, reasons, sorted(set(tags))


def _classify(item: dict[str, Any]) -> list[str]:
    blob = _blob_from_item(item)
    groups: dict[str, list[str]] = {
        "login_panel": ["login", "signin", "sso", "oauth", "cas", "auth", "admin", "console", "后台", "登录"],
        "api_asset": ["api", "gateway", "graphql", "rest", "json", "接口"],
        "swagger_asset": ["swagger", "openapi", "knife4j", "apidoc", "apifox"],
        "dev_asset": ["dev", "test", "uat", "stage", "staging", "beta", "pre", "sandbox", "qa", "sit"],
        "ops_middleware": ["jenkins", "gitlab", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "etcd", "rabbitmq", "redis", "mongo", "elasticsearch", "solr", "nacos"],
        "storage_asset": ["oss", "cos", "s3", "bucket", "minio", "upload"],
        "business_core": ["order", "pay", "payment", "trade", "wallet", "cart", "invoice", "tenant", "role", "permission"],
    }
    tags = []
    for name, keywords in groups.items():
        if any(keyword in blob for keyword in keywords):
            tags.append(name)
    return tags


def _compact_item(item: dict[str, Any]) -> dict[str, Any]:
    score, reasons, score_tags = _interesting_score(item)
    url = _canonical_url(_extract_url(item))
    title = item.get("title") or item.get("site_title") or ""
    status = item.get("status") or item.get("status_code") or ""
    fingerprint = item.get("finger") or item.get("fingerprint") or item.get("app") or item.get("server") or ""
    host = urlparse(url).hostname or item.get("host") or item.get("domain") or ""
    port = item.get("port") or (urlparse(url).port if url else "")

    return {
        "id": hashlib.sha1(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12],
        "url": url,
        "host": host,
        "port": str(port or ""),
        "title": title,
        "status": status,
        "fingerprint": fingerprint,
        "score": score,
        "reasons": reasons,
        "tags": sorted(set(score_tags + _classify(item))),
        "raw": item,
    }


def _fetch_all_sites(task_id: str = "", size: int = 500) -> list[dict[str, Any]]:
    size = min(max(1, int(size)), 2000)
    page_size = min(size, 500)
    items: list[dict[str, Any]] = []

    for page in range(1, 50):
        payload = arl_get_sites(page=page, size=page_size, task_id=task_id)
        batch = _normalize_items(payload)
        if not batch:
            break
        items.extend(batch)
        if len(items) >= size or len(batch) < page_size:
            break

    compacted = [_compact_item(item) for item in items]
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in compacted:
        key = item["url"] or item["host"] or item["id"]
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _filter_by_tags(items: list[dict[str, Any]], wanted: set[str], min_score: int = 0) -> list[dict[str, Any]]:
    result = [
        item for item in items
        if int(item.get("score", 0)) >= int(min_score)
        and wanted.intersection(set(item.get("tags", [])))
    ]
    result.sort(key=lambda row: row.get("score", 0), reverse=True)
    return result


def _snapshot_path(snapshot_name: str) -> Path:
    ARL_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    return ARL_SNAPSHOT_DIR / f"{_safe_name(snapshot_name)}.json"


def _load_snapshot(snapshot_name: str) -> dict[str, Any] | None:
    path = _snapshot_path(snapshot_name)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _save_snapshot(snapshot_name: str, items: list[dict[str, Any]], meta: dict[str, Any]) -> dict[str, Any]:
    path = _snapshot_path(snapshot_name)
    payload = {
        "created_at": _now(),
        "meta": meta,
        "count": len(items),
        "items": items,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "snapshot": snapshot_name, "path": str(path), "count": len(items), "created_at": payload["created_at"]}


def _map_by_url(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item.get("url") or item.get("host") or item.get("id"): item for item in items if item.get("url") or item.get("host") or item.get("id")}


@mcp.tool()
def arl_mcp_config() -> dict[str, Any]:
    """Return ARL MCP wrapper runtime config without leaking the token."""
    return {
        "arl_base_url": ARL_BASE_URL,
        "arl_verify_tls": ARL_VERIFY_TLS,
        "arl_token_configured": bool(ARL_TOKEN),
        "arl_allowed_suffixes": ARL_ALLOWED_SUFFIXES,
        "arl_data_dir": str(ARL_DATA_DIR),
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
def arl_get_ports(page: int = 1, size: int = 100, task_id: str = "") -> dict[str, Any]:
    """Get ARL discovered port assets if the ARL version exposes /api/port/."""
    page = max(1, int(page))
    size = min(max(1, int(size)), 500)
    params: dict[str, Any] = {"page": page, "size": size}
    if task_id:
        params["task_id"] = task_id
    return _request("GET", "/api/port/", params=params)


@mcp.tool()
def arl_score_sites(task_id: str = "", size: int = 500) -> dict[str, Any]:
    """Rank discovered sites by pentest follow-up value using local scoring rules."""
    items = _fetch_all_sites(task_id=task_id, size=size)
    items.sort(key=lambda row: row["score"], reverse=True)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_interesting_sites(task_id: str = "", min_score: int = 20, size: int = 500) -> dict[str, Any]:
    """Return high-value sites such as login panels, APIs, Swagger, test/dev assets, and ops middleware."""
    scored = arl_score_sites(task_id=task_id, size=size)
    items = [item for item in scored["items"] if int(item["score"]) >= int(min_score)]
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_login_panels(task_id: str = "", min_score: int = 0, size: int = 500) -> dict[str, Any]:
    """Return likely login/admin/console/SSO assets."""
    items = _filter_by_tags(_fetch_all_sites(task_id=task_id, size=size), {"login_panel"}, min_score)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_api_assets(task_id: str = "", min_score: int = 0, size: int = 500) -> dict[str, Any]:
    """Return likely API, gateway, GraphQL, REST, Swagger, OpenAPI and Knife4j assets."""
    items = _filter_by_tags(_fetch_all_sites(task_id=task_id, size=size), {"api_asset", "swagger_asset"}, min_score)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_dev_assets(task_id: str = "", min_score: int = 0, size: int = 500) -> dict[str, Any]:
    """Return likely dev/test/uat/stage/beta/pre/sandbox assets."""
    items = _filter_by_tags(_fetch_all_sites(task_id=task_id, size=size), {"dev_asset"}, min_score)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_find_ops_assets(task_id: str = "", min_score: int = 0, size: int = 500) -> dict[str, Any]:
    """Return likely exposed ops middleware and engineering platforms."""
    items = _filter_by_tags(_fetch_all_sites(task_id=task_id, size=size), {"ops_middleware"}, min_score)
    return {"count": len(items), "items": items}


@mcp.tool()
def arl_export_urls(task_id: str = "", min_score: int = 0, size: int = 1000, only_interesting: bool = False) -> dict[str, Any]:
    """Export deduplicated URLs from ARL assets for browser replay, xray proxy mode, or manual validation."""
    items = _fetch_all_sites(task_id=task_id, size=size)
    if only_interesting:
        items = [item for item in items if item["score"] >= max(20, int(min_score))]
    else:
        items = [item for item in items if item["score"] >= int(min_score)]
    items.sort(key=lambda row: row["score"], reverse=True)
    urls = [item["url"] for item in items if item.get("url")]
    return {
        "count": len(urls),
        "urls": urls,
        "lines": "\n".join(urls),
        "items": items,
    }


@mcp.tool()
def arl_snapshot_sites(snapshot_name: str = "default", task_id: str = "", size: int = 1000) -> dict[str, Any]:
    """Save current ARL site assets into a local snapshot under ARL_DATA_DIR."""
    items = _fetch_all_sites(task_id=task_id, size=size)
    items.sort(key=lambda row: row["score"], reverse=True)
    return _save_snapshot(snapshot_name, items, {"task_id": task_id, "size": size})


@mcp.tool()
def arl_diff_sites(snapshot_name: str = "default", task_id: str = "", size: int = 1000, update_baseline: bool = False) -> dict[str, Any]:
    """Compare current ARL site assets with a saved snapshot and optionally update the baseline."""
    old = _load_snapshot(snapshot_name)
    current_items = _fetch_all_sites(task_id=task_id, size=size)
    current_map = _map_by_url(current_items)

    if not old:
        saved = _save_snapshot(snapshot_name, current_items, {"task_id": task_id, "size": size, "auto_created": True})
        return {
            "ok": True,
            "baseline_created": True,
            "message": "baseline did not exist; created it",
            "snapshot": saved,
            "current_count": len(current_items),
        }

    old_items = old.get("items", [])
    old_map = _map_by_url(old_items)

    added_keys = sorted(set(current_map) - set(old_map))
    removed_keys = sorted(set(old_map) - set(current_map))
    changed: list[dict[str, Any]] = []

    for key in sorted(set(current_map).intersection(old_map)):
        before = old_map[key]
        after = current_map[key]
        watched = ("title", "status", "fingerprint", "port", "score", "tags")
        delta = {field: {"before": before.get(field), "after": after.get(field)} for field in watched if before.get(field) != after.get(field)}
        if delta:
            changed.append({"key": key, "changes": delta, "before": before, "after": after})

    added = [current_map[key] for key in added_keys]
    removed = [old_map[key] for key in removed_keys]

    if update_baseline:
        _save_snapshot(snapshot_name, current_items, {"task_id": task_id, "size": size, "updated_from_diff": True})

    return {
        "ok": True,
        "snapshot": snapshot_name,
        "baseline_created_at": old.get("created_at"),
        "current_at": _now(),
        "old_count": len(old_items),
        "current_count": len(current_items),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "baseline_updated": bool(update_baseline),
    }


@mcp.tool()
def arl_build_followup_plan(task_id: str = "", size: int = 500) -> dict[str, Any]:
    """Build a structured follow-up validation plan from ARL assets."""
    items = _fetch_all_sites(task_id=task_id, size=size)
    items.sort(key=lambda row: row["score"], reverse=True)

    buckets = {
        "auth_and_login": _filter_by_tags(items, {"login_panel"}, 0)[:30],
        "api_and_permission": _filter_by_tags(items, {"api_asset", "swagger_asset", "business_core"}, 0)[:30],
        "dev_test_exposure": _filter_by_tags(items, {"dev_asset"}, 0)[:30],
        "ops_middleware": _filter_by_tags(items, {"ops_middleware"}, 0)[:30],
        "storage_upload": _filter_by_tags(items, {"storage_asset"}, 0)[:30],
        "top_priority": [item for item in items if item["score"] >= 50][:50],
    }

    plan = [
        {
            "name": "登录入口与权限矩阵",
            "asset_bucket": "auth_and_login",
            "goal": "确认登录态、角色边界、越权入口和未授权访问风险",
            "checks": [
                "区分未登录、低权限、高权限账号的可访问页面和接口",
                "检查前端路由鉴权与后端接口鉴权是否一致",
                "抓取登录后 API，重点看 userId、tenantId、roleId、orgId 参数",
            ],
        },
        {
            "name": "API / Swagger / 网关验证",
            "asset_bucket": "api_and_permission",
            "goal": "找高价值接口、权限绕过、越权读取/修改、调试接口暴露",
            "checks": [
                "收集 OpenAPI/Swagger/Knife4j 文档和接口分组",
                "按资源对象建立权限矩阵，不做破坏性写入",
                "重点验证 IDOR、租户隔离、批量查询、导出接口",
            ],
        },
        {
            "name": "测试环境暴露",
            "asset_bucket": "dev_test_exposure",
            "goal": "识别测试环境、预发环境、弱隔离资产和调试配置",
            "checks": [
                "确认是否复用生产 SSO、生产数据、生产回调",
                "检查调试页面、默认账号提示、测试接口、错误堆栈",
            ],
        },
        {
            "name": "运维中间件暴露",
            "asset_bucket": "ops_middleware",
            "goal": "确认运维平台、监控平台、制品库、配置中心的暴露面",
            "checks": [
                "确认访问控制、匿名访问、只读信息泄露",
                "记录版本和暴露路径，避免爆破和破坏性操作",
            ],
        },
        {
            "name": "上传/对象存储/CDN",
            "asset_bucket": "storage_upload",
            "goal": "确认上传链路、对象桶权限、静态资源泄露",
            "checks": [
                "检查公开对象、目录索引、任意文件类型上传入口",
                "确认签名 URL、权限边界和跨租户访问",
            ],
        },
    ]

    return {
        "generated_at": _now(),
        "total_assets": len(items),
        "bucket_counts": {name: len(value) for name, value in buckets.items()},
        "buckets": buckets,
        "plan": plan,
    }


@mcp.tool()
def arl_make_xray_targets(task_id: str = "", min_score: int = 20, size: int = 500) -> dict[str, Any]:
    """Generate xray target URLs and safe runbook snippets. This does not execute xray."""
    exported = arl_export_urls(task_id=task_id, min_score=min_score, size=size, only_interesting=True)
    urls = exported["urls"]

    return {
        "count": len(urls),
        "urls": urls,
        "proxy_mode": {
            "description": "推荐登录后扫描：启动 xray 代理，让浏览器或 Playwright 带登录态访问这些 URL。",
            "start_xray": "xray webscan --listen 127.0.0.1:7777 --html-output /tmp/xray-auth.html --json-output /tmp/xray-auth.json",
            "browser_proxy": "http://127.0.0.1:7777",
            "target_file_content": "\n".join(urls),
        },
        "basic_crawler_commands": [
            f"xray webscan --basic-crawler {url} --html-output xray-{idx}.html --json-output xray-{idx}.json"
            for idx, url in enumerate(urls[:20], 1)
        ],
    }


@mcp.tool()
def arl_report(task_id: str = "", size: int = 1000) -> dict[str, Any]:
    """Return a compact asset intelligence report for AI routing and human review."""
    items = _fetch_all_sites(task_id=task_id, size=size)
    items.sort(key=lambda row: row["score"], reverse=True)

    tag_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for item in items:
        for tag in item.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        status = str(item.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "generated_at": _now(),
        "task_id": task_id,
        "total_sites": len(items),
        "status_counts": dict(sorted(status_counts.items(), key=lambda kv: kv[0])),
        "tag_counts": dict(sorted(tag_counts.items(), key=lambda kv: kv[1], reverse=True)),
        "top_20": items[:20],
        "recommended_next_step": [
            "先用 arl_find_interesting_sites 找高分入口",
            "再用 arl_build_followup_plan 拆分登录态、API、测试环境和中间件任务",
            "需要登录后扫描时用 arl_make_xray_targets 生成目标清单，再走 xray 代理模式",
            "每天或每轮扫描后用 arl_diff_sites 做新增资产和变化资产跟踪",
        ],
    }


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse").strip().lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse")
