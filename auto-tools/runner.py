import hashlib
import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


DATA_DIR = Path(os.getenv("AUTO_TOOLS_DATA_DIR", "/data/auto-tools")).resolve()
RUNS_DIR = DATA_DIR / "runs"
ALLOWED_SUFFIXES = [
    item.strip().lower()
    for item in os.getenv("AUTO_TOOLS_ALLOWED_SUFFIXES", os.getenv("ARL_ALLOWED_SUFFIXES", "")).split(",")
    if item.strip()
]
MAX_URLS = int(os.getenv("AUTO_TOOLS_MAX_URLS", "1000"))
TIMEOUT = int(os.getenv("AUTO_TOOLS_TIMEOUT", "1800"))
HTTPX_RATE_LIMIT = int(os.getenv("AUTO_TOOLS_HTTPX_RATE_LIMIT", "50"))
NUCLEI_RATE_LIMIT = int(os.getenv("AUTO_TOOLS_NUCLEI_RATE_LIMIT", "20"))
NUCLEI_CONCURRENCY = int(os.getenv("AUTO_TOOLS_NUCLEI_CONCURRENCY", "10"))
KATANA_DEPTH = int(os.getenv("AUTO_TOOLS_KATANA_DEPTH", "2"))

app = FastAPI(title="ARL Auto Tools Runner", version="0.1.0")


class UrlJob(BaseModel):
    name: str = Field(default="arl-job", max_length=80)
    urls: list[str] = Field(default_factory=list, max_length=5000)
    lines: str = ""


class HttpxJob(UrlJob):
    follow_redirects: bool = True


class KatanaJob(UrlJob):
    depth: int = Field(default=KATANA_DEPTH, ge=1, le=5)
    js_crawl: bool = True


class NucleiJob(UrlJob):
    severity: str = "low,medium,high,critical"
    rate_limit: int = Field(default=NUCLEI_RATE_LIMIT, ge=1, le=200)
    concurrency: int = Field(default=NUCLEI_CONCURRENCY, ge=1, le=50)


class DomainJob(BaseModel):
    name: str = Field(default="arl-domain-job", max_length=80)
    domain: str = Field(..., max_length=253)


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_name(value: str) -> str:
    value = (value or "job").strip().lower()
    out = []
    for ch in value:
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-._")[:80] or "job"


def ensure_dirs() -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)


def host_in_scope(host: str) -> bool:
    host = (host or "").lower().strip(".")
    if not host:
        return False
    if "*" in ALLOWED_SUFFIXES:
        return True
    for allowed in ALLOWED_SUFFIXES:
        allowed = allowed.lstrip("*.").strip(".")
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    if not parsed.hostname or not host_in_scope(parsed.hostname):
        return ""
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/")


def collect_urls(job: UrlJob) -> list[str]:
    raw = list(job.urls)
    raw.extend(line.strip() for line in job.lines.splitlines() if line.strip())
    deduped = []
    seen = set()
    for item in raw:
        url = normalize_url(item)
        if not url or url in seen:
            continue
        seen.add(url)
        deduped.append(url)
        if len(deduped) >= MAX_URLS:
            break
    if not deduped:
        raise HTTPException(status_code=400, detail="no in-scope urls")
    return deduped


def validate_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().strip(".")
    if not domain or "/" in domain or ":" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="invalid domain")
    if not host_in_scope(domain):
        raise HTTPException(status_code=400, detail="domain is out of scope")
    return domain


def job_dir(name: str) -> Path:
    ensure_dirs()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = hashlib.sha1(f"{name}-{stamp}".encode()).hexdigest()[:8]
    path = RUNS_DIR / f"{stamp}-{safe_name(name)}-{suffix}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def run_command(command: list[str], cwd: Path) -> dict:
    started = now()
    log_file = cwd / "command.log"
    stdout_file = cwd / "stdout.txt"
    stderr_file = cwd / "stderr.txt"

    with stdout_file.open("wb") as stdout, stderr_file.open("wb") as stderr:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            stdout=stdout,
            stderr=stderr,
            timeout=TIMEOUT,
            check=False,
        )

    log_file.write_text(
        json.dumps({
            "started_at": started,
            "finished_at": now(),
            "returncode": proc.returncode,
            "command": " ".join(shlex.quote(part) for part in command),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "command": command,
        "workdir": str(cwd),
        "stdout": str(stdout_file),
        "stderr": str(stderr_file),
        "log": str(log_file),
    }


@app.get("/health")
def health() -> dict:
    return {
        "ok": True,
        "time": now(),
        "allowed_suffixes": ALLOWED_SUFFIXES,
        "data_dir": str(DATA_DIR),
        "max_urls": MAX_URLS,
    }


@app.post("/run/httpx")
def run_httpx(job: HttpxJob) -> dict:
    urls = collect_urls(job)
    wd = job_dir(f"httpx-{job.name}")
    input_file = wd / "input_urls.txt"
    output_file = wd / "httpx.jsonl"
    write_lines(input_file, urls)

    command = [
        "httpx",
        "-l", str(input_file),
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
        "-silent",
        "-rl", str(HTTPX_RATE_LIMIT),
        "-o", str(output_file),
    ]
    if job.follow_redirects:
        command.append("-follow-redirects")

    result = run_command(command, wd)
    result.update({"tool": "httpx", "input_count": len(urls), "output": str(output_file)})
    return result


@app.post("/run/katana")
def run_katana(job: KatanaJob) -> dict:
    urls = collect_urls(job)
    wd = job_dir(f"katana-{job.name}")
    input_file = wd / "input_urls.txt"
    output_file = wd / "katana_urls.txt"
    write_lines(input_file, urls)

    command = [
        "katana",
        "-list", str(input_file),
        "-d", str(job.depth),
        "-silent",
        "-o", str(output_file),
    ]
    if job.js_crawl:
        command.append("-jc")

    result = run_command(command, wd)
    result.update({"tool": "katana", "input_count": len(urls), "output": str(output_file)})
    return result


@app.post("/run/nuclei")
def run_nuclei(job: NucleiJob) -> dict:
    urls = collect_urls(job)
    wd = job_dir(f"nuclei-{job.name}")
    input_file = wd / "input_urls.txt"
    output_file = wd / "nuclei.jsonl"
    write_lines(input_file, urls)

    severity = ",".join(
        item for item in job.severity.replace(" ", "").split(",")
        if item in {"info", "low", "medium", "high", "critical"}
    ) or "low,medium,high,critical"

    command = [
        "nuclei",
        "-l", str(input_file),
        "-jsonl",
        "-severity", severity,
        "-rl", str(job.rate_limit),
        "-c", str(job.concurrency),
        "-o", str(output_file),
    ]

    result = run_command(command, wd)
    result.update({"tool": "nuclei", "input_count": len(urls), "output": str(output_file), "severity": severity})
    return result


@app.post("/run/subfinder")
def run_subfinder(job: DomainJob) -> dict:
    domain = validate_domain(job.domain)
    wd = job_dir(f"subfinder-{job.name}-{domain}")
    output_file = wd / "subdomains.txt"
    command = ["subfinder", "-d", domain, "-silent", "-o", str(output_file)]
    result = run_command(command, wd)
    result.update({"tool": "subfinder", "domain": domain, "output": str(output_file)})
    return result


@app.post("/run/dnsx")
def run_dnsx(job: UrlJob) -> dict:
    urls = collect_urls(job)
    hosts = sorted({urlparse(url).hostname or "" for url in urls if urlparse(url).hostname})
    wd = job_dir(f"dnsx-{job.name}")
    input_file = wd / "input_hosts.txt"
    output_file = wd / "dnsx.jsonl"
    write_lines(input_file, hosts)

    command = ["dnsx", "-l", str(input_file), "-json", "-silent", "-o", str(output_file)]
    result = run_command(command, wd)
    result.update({"tool": "dnsx", "input_count": len(hosts), "output": str(output_file)})
    return result


@app.get("/runs")
def list_runs(limit: int = 50) -> dict:
    ensure_dirs()
    dirs = sorted([p for p in RUNS_DIR.iterdir() if p.is_dir()], reverse=True)[: max(1, min(limit, 200))]
    items = []
    for path in dirs:
        log = path / "command.log"
        meta = {}
        if log.exists():
            try:
                meta = json.loads(log.read_text(encoding="utf-8"))
            except Exception:
                meta = {}
        items.append({"path": str(path), "name": path.name, "meta": meta})
    return {"count": len(items), "items": items}
