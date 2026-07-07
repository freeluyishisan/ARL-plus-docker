from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


AUTH_KEYWORDS = [
    "admin", "administrator", "login", "signin", "sign-in", "sso", "auth", "oauth", "cas", "idp",
    "account", "passport", "console", "dashboard", "manage", "manager", "后台", "登录", "管理", "统一认证",
]
API_KEYWORDS = [
    "api", "gateway", "openapi", "swagger", "graphql", "rest", "rpc", "doc.html", "knife4j",
    "接口", "网关",
]
ENV_KEYWORDS = [
    "dev", "test", "uat", "stage", "staging", "beta", "pre", "preview", "sandbox", "qa", "gray",
    "trial", "demo", "debug", "mock", "sit", "perf", "压测", "测试", "预发", "灰度",
]
OPS_KEYWORDS = [
    "jenkins", "gitlab", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "etcd",
    "rabbitmq", "redis", "mongo", "mongodb", "elasticsearch", "solr", "xxl-job", "apollo", "nacos",
    "dubbo", "skywalking", "sonarqube", "zabbix", "minio", "portainer", "rancher", "kubernetes",
]
STORAGE_KEYWORDS = ["oss", "cos", "s3", "bucket", "minio", "storage", "blob", "cdn", "static", "upload", "download"]
DOC_KEYWORDS = ["docs", "doc", "document", "wiki", "help", "manual", "developer", "开发者", "文档"]
BUSINESS_KEYWORDS = [
    "order", "pay", "payment", "billing", "invoice", "wallet", "trade", "coupon", "member", "user", "profile",
    "tenant", "org", "organization", "role", "permission", "rbac", "订单", "支付", "钱包", "用户", "会员", "租户", "权限", "角色",
]
NOISE_KEYWORDS = [
    "www", "static", "cdn", "img", "image", "assets", "font", "css", "js", "download", "mirror", "status",
    "health", "monitor", "备案", "官网首页",
]

CATEGORY_RULES: list[tuple[str, int, list[str]]] = [
    ("auth_surface", 40, AUTH_KEYWORDS),
    ("api_surface", 35, API_KEYWORDS),
    ("test_env", 30, ENV_KEYWORDS),
    ("ops_middleware", 30, OPS_KEYWORDS),
    ("business_surface", 25, BUSINESS_KEYWORDS),
    ("storage_surface", 18, STORAGE_KEYWORDS),
    ("doc_surface", 12, DOC_KEYWORDS),
]

RISKY_PORTS = {
    "21", "22", "23", "25", "53", "110", "143", "389", "445", "873", "1433", "1521", "2049", "2375", "2376",
    "3000", "3306", "5000", "5001", "5432", "5601", "5672", "5900", "5984", "6379", "7001", "8000", "8001",
    "8080", "8081", "8088", "8089", "8090", "8161", "8443", "8848", "8888", "9000", "9090", "9200", "9300",
    "10000", "11211", "15672", "27017", "50070",
}

STATIC_EXT_RE = re.compile(r"\.(?:jpg|jpeg|png|gif|webp|svg|ico|css|woff2?|ttf|map)(?:$|[?#])", re.I)
JS_EXT_RE = re.compile(r"\.js(?:$|[?#])", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "data", "result", "results", "rows"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = normalize_items(value)
            if nested:
                return nested
    return []


def first_value(item: dict[str, Any], keys: list[str], default: str = "") -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def extract_url(item: dict[str, Any]) -> str:
    direct = first_value(item, ["site", "url", "link", "addr"])
    if direct:
        if direct.startswith(("http://", "https://")):
            return direct
        host = direct.split("/", 1)[0]
        port = first_value(item, ["port"])
        scheme = "https" if port in {"443", "8443"} else "http"
        if port and ":" not in host:
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{direct}"

    host = first_value(item, ["host", "domain", "ip", "ip_str"])
    if not host:
        return ""
    port = first_value(item, ["port"])
    scheme = "https" if port in {"443", "8443"} else "http"
    if port and ":" not in host:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def extract_host(url_or_host: str) -> str:
    if not url_or_host:
        return ""
    text = url_or_host.strip()
    if text.startswith(("http://", "https://")):
        return (urlparse(text).hostname or "").lower()
    return text.split("/", 1)[0].split(":", 1)[0].lower().strip(".")


def asset_key(item: dict[str, Any]) -> str:
    url = extract_url(item)
    if url:
        return hashlib.sha1(url.lower().encode("utf-8")).hexdigest()[:16]
    raw = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def item_blob(item: dict[str, Any]) -> str:
    url = extract_url(item)
    fields = [url]
    for key in ("title", "site_title", "host", "domain", "ip", "port", "status", "status_code", "finger", "fingerprint", "app", "server", "banner"):
        value = item.get(key)
        if value is not None:
            fields.append(str(value))
    return " ".join(fields).lower()


def keyword_hits(blob: str, keywords: list[str]) -> list[str]:
    return sorted({kw for kw in keywords if kw.lower() in blob})


def detect_categories(item: dict[str, Any]) -> tuple[list[str], list[str], int]:
    blob = item_blob(item)
    categories: list[str] = []
    reasons: list[str] = []
    score = 0

    for category, weight, keywords in CATEGORY_RULES:
        hits = keyword_hits(blob, keywords)
        if hits:
            categories.append(category)
            score += weight
            reasons.append(f"{category}:{','.join(hits[:5])}")

    port = first_value(item, ["port"])
    if port and port not in {"80", "443"}:
        score += 10
        categories.append("non_standard_port")
        reasons.append(f"non_standard_port:{port}")
        if port in RISKY_PORTS:
            score += 15
            categories.append("risky_port")
            reasons.append(f"risky_port:{port}")

    status = first_value(item, ["status", "status_code"])
    if status.startswith(("2", "3")):
        score += 8
        categories.append("alive")
        reasons.append(f"alive:{status}")
    elif status.startswith(("401", "403")):
        score += 14
        categories.append("protected_surface")
        reasons.append(f"protected:{status}")

    url = extract_url(item).lower()
    if STATIC_EXT_RE.search(url):
        score -= 25
        categories.append("static_noise")
        reasons.append("static_file")
    elif JS_EXT_RE.search(url):
        score += 15
        categories.append("js_asset")
        reasons.append("js_asset")

    noise_hits = keyword_hits(blob, NOISE_KEYWORDS)
    if noise_hits and not any(cat in categories for cat in ["auth_surface", "api_surface", "ops_middleware", "business_surface"]):
        score -= min(18, 6 * len(noise_hits))
        categories.append("possible_noise")
        reasons.append(f"noise:{','.join(noise_hits[:5])}")

    if not categories:
        categories.append("ordinary_site")

    # Keep score readable for LLM ranking.
    score = max(0, min(score, 150))
    return sorted(set(categories)), reasons, score


def score_asset(item: dict[str, Any]) -> dict[str, Any]:
    categories, reasons, score = detect_categories(item)
    url = extract_url(item)
    host = extract_host(url or first_value(item, ["host", "domain", "ip"]))
    return {
        "id": asset_key(item),
        "score": score,
        "categories": categories,
        "reasons": reasons,
        "url": url,
        "host": host,
        "port": first_value(item, ["port"]),
        "title": first_value(item, ["title", "site_title"]),
        "status": first_value(item, ["status", "status_code"]),
        "fingerprint": first_value(item, ["finger", "fingerprint", "app", "server", "banner"]),
        "raw": item,
    }


def score_assets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = [score_asset(item) for item in items]
    scored.sort(key=lambda row: (int(row.get("score", 0)), row.get("url", "")), reverse=True)
    return scored


def summarize_scored(scored: list[dict[str, Any]], top: int = 20) -> dict[str, Any]:
    category_counter: Counter[str] = Counter()
    host_counter: Counter[str] = Counter()
    fingerprint_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()

    for item in scored:
        category_counter.update(item.get("categories", []))
        if item.get("host"):
            host_counter[item["host"]] += 1
        if item.get("fingerprint"):
            fingerprint_counter[item["fingerprint"]] += 1
        if item.get("status"):
            status_counter[item["status"]] += 1

    buckets = {
        "critical_followup": [x for x in scored if int(x.get("score", 0)) >= 80],
        "high_followup": [x for x in scored if 50 <= int(x.get("score", 0)) < 80],
        "medium_followup": [x for x in scored if 25 <= int(x.get("score", 0)) < 50],
        "low_or_noise": [x for x in scored if int(x.get("score", 0)) < 25],
    }

    return {
        "generated_at": utc_now(),
        "total": len(scored),
        "buckets": {k: len(v) for k, v in buckets.items()},
        "categories": category_counter.most_common(),
        "top_hosts": host_counter.most_common(20),
        "top_fingerprints": fingerprint_counter.most_common(20),
        "status_codes": status_counter.most_common(),
        "top_assets": scored[:top],
    }


def filter_scored(scored: list[dict[str, Any]], min_score: int = 20, categories: list[str] | None = None, limit: int = 200) -> list[dict[str, Any]]:
    wanted = set(categories or [])
    out: list[dict[str, Any]] = []
    for item in scored:
        if int(item.get("score", 0)) < int(min_score):
            continue
        if wanted and not (wanted & set(item.get("categories", []))):
            continue
        out.append(item)
        if len(out) >= limit:
            break
    return out


def export_urls(scored: list[dict[str, Any]], min_score: int = 20, categories: list[str] | None = None, limit: int = 300) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for item in filter_scored(scored, min_score=min_score, categories=categories, limit=limit * 2):
        url = item.get("url") or ""
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= limit:
            break
    return urls


def make_markdown_report(scored: list[dict[str, Any]], title: str = "ARL AI Asset Report", limit: int = 50) -> str:
    summary = summarize_scored(scored, top=min(limit, 20))
    lines = [
        f"# {title}",
        "",
        f"生成时间：{summary['generated_at']}",
        f"资产总数：{summary['total']}",
        "",
        "## 分层统计",
    ]
    for key, value in summary["buckets"].items():
        lines.append(f"- {key}: {value}")

    lines.extend(["", "## 主要分类"])
    for name, count in summary["categories"][:20]:
        lines.append(f"- {name}: {count}")

    lines.extend(["", "## 高价值资产"])
    for idx, item in enumerate(scored[:limit], 1):
        lines.append(f"### {idx}. {item.get('url') or item.get('host') or item.get('id')}")
        lines.append(f"- score: {item.get('score')}")
        lines.append(f"- categories: {', '.join(item.get('categories', []))}")
        if item.get("title"):
            lines.append(f"- title: {item.get('title')}")
        if item.get("status"):
            lines.append(f"- status: {item.get('status')}")
        if item.get("fingerprint"):
            lines.append(f"- fingerprint: {item.get('fingerprint')}")
        if item.get("reasons"):
            lines.append(f"- reasons: {'; '.join(item.get('reasons', [])[:6])}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def build_snapshot(scored: list[dict[str, Any]]) -> dict[str, Any]:
    compact = []
    for item in scored:
        compact.append({
            "id": item.get("id"),
            "url": item.get("url"),
            "host": item.get("host"),
            "port": item.get("port"),
            "score": item.get("score"),
            "categories": item.get("categories", []),
            "title": item.get("title"),
            "status": item.get("status"),
            "fingerprint": item.get("fingerprint"),
        })
    return {"generated_at": utc_now(), "count": len(compact), "items": compact}


def diff_snapshots(old_snapshot: dict[str, Any], new_snapshot: dict[str, Any]) -> dict[str, Any]:
    old_items = {str(item.get("id")): item for item in old_snapshot.get("items", []) if isinstance(item, dict) and item.get("id")}
    new_items = {str(item.get("id")): item for item in new_snapshot.get("items", []) if isinstance(item, dict) and item.get("id")}

    added_ids = sorted(set(new_items) - set(old_items))
    removed_ids = sorted(set(old_items) - set(new_items))
    common_ids = sorted(set(old_items) & set(new_items))

    changed = []
    for item_id in common_ids:
        old = old_items[item_id]
        new = new_items[item_id]
        changes: dict[str, Any] = {}
        for key in ("score", "categories", "title", "status", "fingerprint", "url", "host", "port"):
            if old.get(key) != new.get(key):
                changes[key] = {"old": old.get(key), "new": new.get(key)}
        if changes:
            changed.append({"id": item_id, "url": new.get("url") or old.get("url"), "changes": changes})

    added = [new_items[item_id] for item_id in added_ids]
    removed = [old_items[item_id] for item_id in removed_ids]
    added.sort(key=lambda row: int(row.get("score", 0)), reverse=True)

    return {
        "generated_at": utc_now(),
        "old_count": len(old_items),
        "new_count": len(new_items),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def followup_plan(scored: list[dict[str, Any]], limit: int = 30) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in scored:
        for category in item.get("categories", []):
            grouped[category].append(item)

    templates = {
        "auth_surface": "验证登录态、会话失效、权限切换、未授权访问、账号角色边界。",
        "api_surface": "枚举接口文档和前端 API，验证鉴权缺失、越权、租户隔离和参数边界。",
        "business_surface": "围绕订单、支付、用户、租户、角色做业务流和权限矩阵验证。",
        "test_env": "确认是否测试/预发环境暴露，检查调试开关、弱鉴权、真实数据隔离和回调地址。",
        "ops_middleware": "确认中间件是否暴露管理面，验证访问控制、默认配置、版本风险和信息泄露。",
        "storage_surface": "确认对象存储、上传下载、目录枚举、跨租户访问和敏感文件暴露。",
        "doc_surface": "提取接口、参数、认证方式、环境地址，转成后续 API 验证任务。",
        "js_asset": "下载并解析 JS，提取 API 路径、SourceMap、云桶、内部域名和敏感配置。",
        "risky_port": "复核高风险端口服务边界、访问控制、版本和暴露面。",
    }

    for category, description in templates.items():
        assets = grouped.get(category, [])[:10]
        if not assets:
            continue
        tasks.append({
            "category": category,
            "priority": "high" if category in {"auth_surface", "api_surface", "business_surface", "ops_middleware", "test_env"} else "medium",
            "description": description,
            "assets": [
                {
                    "url": item.get("url"),
                    "score": item.get("score"),
                    "title": item.get("title"),
                    "fingerprint": item.get("fingerprint"),
                    "reasons": item.get("reasons", [])[:4],
                }
                for item in assets
            ],
        })
        if len(tasks) >= limit:
            break

    return tasks
