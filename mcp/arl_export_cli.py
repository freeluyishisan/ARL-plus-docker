#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests

ARL_BASE_URL = os.getenv("ARL_BASE_URL", "https://127.0.0.1:5003").rstrip("/")
ARL_TOKEN = os.getenv("ARL_TOKEN", "")
ARL_VERIFY_TLS = os.getenv("ARL_VERIFY_TLS", "false").lower() in {"1", "true", "yes", "on"}
ARL_TIMEOUT = float(os.getenv("ARL_TIMEOUT", "30"))

RULES = [
    ("login_panel", 35, ["admin", "login", "signin", "sso", "auth", "oauth", "cas", "console", "dashboard", "manage", "后台", "登录", "管理"]),
    ("api_asset", 30, ["api", "gateway", "openapi", "swagger", "graphql", "knife4j", "接口"]),
    ("dev_test_asset", 25, ["dev", "test", "uat", "stage", "staging", "beta", "pre", "sandbox", "qa", "sit"]),
    ("ops_middleware", 25, ["jenkins", "gitlab", "nacos", "nexus", "harbor", "grafana", "kibana", "prometheus", "consul", "rabbitmq", "redis", "mongo", "elasticsearch"]),
    ("storage_cdn", 15, ["oss", "cos", "s3", "bucket", "minio", "cdn", "upload", "file"]),
    ("doc_portal", 10, ["docs", "doc", "portal", "wiki", "help", "manual"]),
    ("business", 10, ["pay", "payment", "order", "trade", "invoice", "wallet", "user", "tenant", "role"]),
]


def headers() -> dict[str, str]:
    out = {"Content-Type": "application/json", "User-Agent": "arl-export-cli/0.1"}
    if ARL_TOKEN:
        out["token"] = ARL_TOKEN
    return out


def normalize_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("items", "data", "result", "results", "rows", "records"):
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            nested = normalize_items(value)
            if nested:
                return nested
    return []


def arl_get(path: str, params: dict[str, Any]) -> Any:
    resp = requests.get(
        f"{ARL_BASE_URL}{path}",
        params=params,
        headers=headers(),
        verify=ARL_VERIFY_TLS,
        timeout=ARL_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_sites(task_id: str, pages: int, size: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in range(1, pages + 1):
        params: dict[str, Any] = {"page": page, "size": size}
        if task_id:
            params["task_id"] = task_id
        batch = normalize_items(arl_get("/api/site/", params))
        if not batch:
            break
        for item in batch:
            raw = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
            if raw not in seen:
                out.append(item)
                seen.add(raw)
        if len(batch) < size:
            break
    return out


def get_value(item: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def get_url(item: dict[str, Any]) -> str:
    value = get_value(item, ["site", "url", "link", "addr", "host", "domain"])
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    port = get_value(item, ["port"])
    scheme = "https" if port in {"443", "8443"} else "http"
    if port and ":" not in value:
        return f"{scheme}://{value}:{port}"
    return f"{scheme}://{value}"


def score(item: dict[str, Any]) -> dict[str, Any]:
    url = get_url(item)
    blob = " ".join([url] + [str(v) for v in item.values() if v is not None]).lower()
    categories: list[str] = []
    reasons: list[str] = []
    total = 0
    for category, weight, words in RULES:
        hits = [word for word in words if word in blob]
        if hits:
            categories.append(category)
            reasons.append(f"{category}:{','.join(hits[:5])}")
            total += weight
    port = get_value(item, ["port"])
    if port and port not in {"80", "443"}:
        categories.append("non_standard_port")
        reasons.append(f"port:{port}")
        total += 10
    status = get_value(item, ["status", "status_code", "code"])
    if status.startswith(("2", "3")):
        total += 5
    return {
        "score": total,
        "url": url,
        "title": get_value(item, ["title", "site_title", "web_title"]),
        "status": status,
        "categories": categories or ["normal_web"],
        "reasons": reasons,
        "raw": item,
    }


def ranked_sites(args: argparse.Namespace) -> list[dict[str, Any]]:
    ranked = [score(item) for item in fetch_sites(args.task_id, args.pages, args.size)]
    ranked.sort(key=lambda x: (x["score"], x["url"]), reverse=True)
    return ranked


def write(path: str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def cmd_urls(args: argparse.Namespace) -> None:
    urls = []
    for item in ranked_sites(args):
        if item["score"] < args.min_score or not item["url"]:
            continue
        if args.category and args.category not in item["categories"]:
            continue
        urls.append(item["url"])
    text = "\n".join(dict.fromkeys(urls)) + ("\n" if urls else "")
    if args.output:
        write(args.output, text)
        print(f"[+] wrote {len(urls)} urls to {args.output}")
    else:
        print(text, end="")


def cmd_json(args: argparse.Namespace) -> None:
    data = [item for item in ranked_sites(args) if item["score"] >= args.min_score]
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        write(args.output, text)
        print(f"[+] wrote {len(data)} assets to {args.output}")
    else:
        print(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export ranked ARL site assets")
    parser.add_argument("mode", choices=["urls", "json"])
    parser.add_argument("--task-id", default="")
    parser.add_argument("--pages", type=int, default=10)
    parser.add_argument("--size", type=int, default=500)
    parser.add_argument("--min-score", type=int, default=20)
    parser.add_argument("--category", default="")
    parser.add_argument("-o", "--output", default="")
    args = parser.parse_args()
    if args.mode == "urls":
        cmd_urls(args)
    else:
        cmd_json(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        print(f"[!] request error: {exc}", file=sys.stderr)
        raise SystemExit(2)
