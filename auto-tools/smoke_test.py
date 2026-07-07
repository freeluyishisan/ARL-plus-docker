import ast
from pathlib import Path

runner = Path(__file__).with_name("runner.py")
source = runner.read_text(encoding="utf-8")
ast.parse(source)

required_routes = [
    "def health(",
    "def run_httpx(",
    "def run_katana(",
    "def run_nuclei(",
    "def run_subfinder(",
    "def run_dnsx(",
    "def list_runs(",
]

missing = [item for item in required_routes if item not in source]
if missing:
    raise SystemExit(f"missing route handlers: {missing}")

print("ok: auto-tools runner syntax and routes look valid")
