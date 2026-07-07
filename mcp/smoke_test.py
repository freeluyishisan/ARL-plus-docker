import ast
from pathlib import Path

server = Path(__file__).with_name("server.py")
source = server.read_text(encoding="utf-8")
ast.parse(source)

required_tools = [
    "arl_mcp_config",
    "arl_health",
    "arl_create_task",
    "arl_list_tasks",
    "arl_get_sites",
    "arl_get_domains",
    "arl_get_ports",
    "arl_score_sites",
    "arl_find_interesting_sites",
    "arl_find_login_panels",
    "arl_find_api_assets",
    "arl_find_dev_assets",
    "arl_find_ops_assets",
    "arl_export_urls",
    "arl_snapshot_sites",
    "arl_list_snapshots",
    "arl_diff_snapshots",
    "arl_diff_latest_sites",
    "arl_attack_surface_report",
    "arl_build_followup_plan",
]

missing = [name for name in required_tools if f"def {name}(" not in source]
if missing:
    raise SystemExit(f"missing tool functions: {missing}")

print("ok: server.py syntax and MCP tool names look valid")
