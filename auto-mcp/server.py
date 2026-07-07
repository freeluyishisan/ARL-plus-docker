import os
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP


AUTO_TOOLS_BASE_URL = os.getenv("AUTO_TOOLS_BASE_URL", "http://arl-auto-tools:8770").rstrip("/")
AUTO_MCP_NAME = os.getenv("AUTO_MCP_NAME", "arl-auto-tools-mcp")
AUTO_MCP_HOST = os.getenv("AUTO_MCP_HOST", "0.0.0.0")
AUTO_MCP_PORT = int(os.getenv("AUTO_MCP_PORT", "8766"))
AUTO_MCP_TIMEOUT = float(os.getenv("AUTO_MCP_TIMEOUT", "3600"))

mcp = FastMCP(AUTO_MCP_NAME, host=AUTO_MCP_HOST, port=AUTO_MCP_PORT)


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        resp = requests.post(
            f"{AUTO_TOOLS_BASE_URL}{path}",
            json=payload,
            timeout=AUTO_MCP_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc), "base_url": AUTO_TOOLS_BASE_URL}

    try:
        body = resp.json()
    except ValueError:
        body = {"text": resp.text[:2000]}

    if resp.status_code >= 400:
        return {"ok": False, "status_code": resp.status_code, "body": body}

    if isinstance(body, dict):
        body.setdefault("ok", True)
        return body
    return {"ok": True, "body": body}


def _get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        resp = requests.get(f"{AUTO_TOOLS_BASE_URL}{path}", params=params or {}, timeout=AUTO_MCP_TIMEOUT)
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc), "base_url": AUTO_TOOLS_BASE_URL}

    try:
        body = resp.json()
    except ValueError:
        body = {"text": resp.text[:2000]}

    if resp.status_code >= 400:
        return {"ok": False, "status_code": resp.status_code, "body": body}

    if isinstance(body, dict):
        body.setdefault("ok", True)
        return body
    return {"ok": True, "body": body}


@mcp.tool()
def auto_tools_config() -> dict[str, Any]:
    """Return auto-tools MCP bridge config."""
    return {
        "auto_tools_base_url": AUTO_TOOLS_BASE_URL,
        "auto_mcp_name": AUTO_MCP_NAME,
        "auto_mcp_host": AUTO_MCP_HOST,
        "auto_mcp_port": AUTO_MCP_PORT,
    }


@mcp.tool()
def auto_tools_health() -> dict[str, Any]:
    """Check whether the auto-tools runner is reachable."""
    return _get("/health")


@mcp.tool()
def auto_httpx(name: str, urls: list[str] | None = None, lines: str = "", follow_redirects: bool = True) -> dict[str, Any]:
    """Run httpx on scoped URLs for alive probing, status code, title, and technology detection."""
    return _post("/run/httpx", {
        "name": name,
        "urls": urls or [],
        "lines": lines,
        "follow_redirects": follow_redirects,
    })


@mcp.tool()
def auto_katana(name: str, urls: list[str] | None = None, lines: str = "", depth: int = 2, js_crawl: bool = True) -> dict[str, Any]:
    """Run katana on scoped URLs for crawl URL and JavaScript URL discovery."""
    return _post("/run/katana", {
        "name": name,
        "urls": urls or [],
        "lines": lines,
        "depth": depth,
        "js_crawl": js_crawl,
    })


@mcp.tool()
def auto_nuclei(name: str, urls: list[str] | None = None, lines: str = "", severity: str = "low,medium,high,critical", rate_limit: int = 20, concurrency: int = 10) -> dict[str, Any]:
    """Run nuclei on scoped URLs with controlled severity, rate limit, and concurrency."""
    return _post("/run/nuclei", {
        "name": name,
        "urls": urls or [],
        "lines": lines,
        "severity": severity,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
    })


@mcp.tool()
def auto_subfinder(name: str, domain: str) -> dict[str, Any]:
    """Run subfinder for one scoped root domain."""
    return _post("/run/subfinder", {"name": name, "domain": domain})


@mcp.tool()
def auto_dnsx(name: str, urls: list[str] | None = None, lines: str = "") -> dict[str, Any]:
    """Run dnsx on scoped hosts extracted from URLs."""
    return _post("/run/dnsx", {"name": name, "urls": urls or [], "lines": lines})


@mcp.tool()
def auto_runs(limit: int = 50) -> dict[str, Any]:
    """List auto-tools run output directories and command metadata."""
    return _get("/runs", {"limit": limit})


@mcp.tool()
def auto_recon_pipeline(name: str, urls: list[str] | None = None, lines: str = "", run_katana: bool = True, run_nuclei: bool = False) -> dict[str, Any]:
    """Run a safe staged workflow: httpx first, optionally katana, optionally nuclei."""
    results: dict[str, Any] = {"name": name, "steps": []}

    httpx_result = auto_httpx(name=f"{name}-httpx", urls=urls or [], lines=lines)
    results["steps"].append({"tool": "httpx", "result": httpx_result})

    if run_katana:
        katana_result = auto_katana(name=f"{name}-katana", urls=urls or [], lines=lines, depth=2, js_crawl=True)
        results["steps"].append({"tool": "katana", "result": katana_result})

    if run_nuclei:
        nuclei_result = auto_nuclei(
            name=f"{name}-nuclei",
            urls=urls or [],
            lines=lines,
            severity="low,medium,high,critical",
            rate_limit=20,
            concurrency=10,
        )
        results["steps"].append({"tool": "nuclei", "result": nuclei_result})

    results["ok"] = all(step["result"].get("ok") for step in results["steps"])
    return results


if __name__ == "__main__":
    transport = os.getenv("AUTO_MCP_TRANSPORT", "sse").strip().lower()
    if transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport="sse")
