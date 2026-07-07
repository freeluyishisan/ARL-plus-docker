#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import requests

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

ARL_BASE_URL = os.getenv("ARL_BASE_URL", "https://127.0.0.1:5003").rstrip("/")
ARL_TOKEN = os.getenv("ARL_TOKEN", "")
ARL_VERIFY_TLS = os.getenv("ARL_VERIFY_TLS", "false").strip().lower() in {"1", "true", "yes", "on"}
ARL_TIMEOUT = float(os.getenv("ARL_TIMEOUT", "30"))


def headers() -> dict[str, str]:
    out = {"Content-Type": "application/json", "User-Agent": "arl-boost-cli/0.1"}
    if ARL_TOKEN:
        out["token"] = ARL_TOKEN
    return out


def arl_get(path: str, params: dict[str, Any]) -> Any:
    if not path.startswith("/"):
        path = "/" + path
    resp = requests.get(
        f"{ARL_BASE_URL}{path}",
        params=params,
        headers=headers(),
        verify=ARL_VERIFY_TLS,
        timeout=ARL_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_sites(task_id: str = "", pages: int = 5, size: int = 200) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in range(1, pages + 1):
        params: dict[str, Any] = {"page": page, "size": size}
        if task_id:
            params["task_id"] = task_id
        payload = arl_get("/api/site/", params=params)
        batch = normalize_items(payload)
        if not batch:
            break
        items.extend(batch)
    return items


def write_text(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def write_json(path: str, data: Any) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_report(args: argparse.Namespace) -> None:
    scored = score_assets(fetch_sites(task_id=args.task_id, pages=args.pages, size=args.size))
    report = make_markdown_report(scored, title=args.title, limit=args.limit)
    if args.output:
        write_text(args.output, report)
        print(f"[+] report written: {args.output}")
    else:
        print(report)


def cmd_summary(args: argparse.Namespace) -> None:
    scored = score_assets(fetch_sites(task_id=args.task_id, pages=args.pages, size=args.size))
    summary = summarize_scored(scored, top=args.limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def cmd_urls(args: argparse.Namespace) -> None:
    scored = score_assets(fetch_sites(task_id=args.task_id, pages=args.pages, size=args.size))
    categories = [x.strip() for x in args.categories.split(",") if x.strip()] if args.categories else None
    urls = export_urls(scored, min_score=args.min_score, categories=categories, limit=args.limit)
    output = "\n".join(urls) + ("\n" if urls else "")
    if args.output:
        write_text(args.output, output)
        print(f"[+] urls written: {args.output} count={len(urls)}")
    else:
        print(output, end="")


def cmd_snapshot(args: argparse.Namespace) -> None:
    scored = score_assets(fetch_sites(task_id=args.task_id, pages=args.pages, size=args.size))
    snapshot = build_snapshot(scored)
    if args.output:
        write_json(args.output, snapshot)
        print(f"[+] snapshot written: {args.output} count={snapshot['count']}")
    else:
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))


def cmd_diff(args: argparse.Namespace) -> None:
    diff = diff_snapshots(load_json(args.old), load_json(args.new))
    if args.output:
        write_json(args.output, diff)
        print(f"[+] diff written: {args.output}")
    else:
        print(json.dumps(diff, ensure_ascii=False, indent=2))


def cmd_plan(args: argparse.Namespace) -> None:
    scored = score_assets(fetch_sites(task_id=args.task_id, pages=args.pages, size=args.size))
    plan = followup_plan(scored, limit=args.limit)
    if args.output:
        write_json(args.output, plan)
        print(f"[+] plan written: {args.output} tasks={len(plan)}")
    else:
        print(json.dumps(plan, ensure_ascii=False, indent=2))


def add_fetch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-id", default="")
    parser.add_argument("--pages", type=int, default=5)
    parser.add_argument("--size", type=int, default=200)


def main(argv: list[str] | None = None) -> int:
    root = argparse.ArgumentParser(description="ARL asset intelligence CLI")
    sub = root.add_subparsers(dest="command", required=True)

    p = sub.add_parser("report")
    add_fetch_args(p)
    p.add_argument("--title", default="ARL AI Asset Report")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("summary")
    add_fetch_args(p)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("urls")
    add_fetch_args(p)
    p.add_argument("--min-score", type=int, default=20)
    p.add_argument("--categories", default="")
    p.add_argument("--limit", type=int, default=300)
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_urls)

    p = sub.add_parser("snapshot")
    add_fetch_args(p)
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("diff")
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("plan")
    add_fetch_args(p)
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("-o", "--output", default="")
    p.set_defaults(func=cmd_plan)

    args = root.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.HTTPError as exc:
        print(f"[!] ARL HTTP error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except requests.RequestException as exc:
        print(f"[!] ARL request error: {exc}", file=sys.stderr)
        raise SystemExit(2)
