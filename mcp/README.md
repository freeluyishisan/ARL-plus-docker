# ARL-plus MCP

这个目录给 ARL-plus-docker 增加一个独立 MCP sidecar。它不会修改 ARL 主镜像，只通过 ARL Web API 读取任务、资产，并按规则筛选高价值入口。

第二版把 MCP 从“读资产”升级成“资产情报中枢”：支持分页拉取、去重归一化、分类评分、快照、差异分析、URL 导出、Markdown 报告和后续验证计划。

## 功能

已暴露 MCP 工具：

- `arl_mcp_config`：查看 MCP/ARL 连接配置，不泄露 token。
- `arl_health`：检查 ARL API 是否可用。
- `arl_create_task`：创建受 allowlist 限制的 ARL 资产发现任务。
- `arl_list_tasks`：查看任务列表。
- `arl_get_sites`：读取站点资产。
- `arl_get_domains`：读取域名资产。
- `arl_get_ports`：读取端口资产。如果当前 ARL 版本没有 `/api/port/`，会返回 ARL API 错误。
- `arl_score_sites`：按后台、API、Swagger、测试环境、中间件、非标端口、业务系统等维度打分。
- `arl_find_interesting_sites`：只返回高价值资产。
- `arl_find_login_panels`：筛登录、后台、SSO、Console。
- `arl_find_api_assets`：筛 API、Gateway、Swagger、OpenAPI、GraphQL、接口文档。
- `arl_find_dev_assets`：筛 dev、test、uat、stage、beta 等环境。
- `arl_find_ops_assets`：筛 Jenkins、GitLab、Grafana、Kibana、Nexus、Harbor 等运维中间件。
- `arl_export_urls`：把 URL 导出为 txt/json/markdown，方便接 xray、浏览器、Hermes worker。
- `arl_snapshot_sites`：保存当前站点资产快照。
- `arl_list_snapshots`：列出已有快照。
- `arl_diff_snapshots`：比较两个快照。
- `arl_diff_latest_sites`：创建新快照，并和同名上一个快照对比。
- `arl_attack_surface_report`：生成 Markdown 攻击面报告。
- `arl_build_followup_plan`：按 ider/worker/heier 分工生成后续验证计划。

## 启动

先准备 ARL API token 和允许扫描范围：

```bash
export ARL_TOKEN="你的_ARL_API_KEY"
export ARL_ALLOWED_SUFFIXES="example.com,example.cn"
```

启动 ARL 与 MCP：

```bash
docker compose --profile mcp up -d --build
```

MCP SSE 地址：

```text
http://127.0.0.1:8765/sse
```

## 启动增强版持久化

默认 MCP 可以直接用。如果要保存快照、导出 URL、保存报告，推荐叠加 override：

```bash
docker compose -f docker-compose.yml -f docker-compose.mcp-intel.yml --profile mcp up -d --build
```

输出目录：

```text
./mcp-data/
├── snapshots/
├── exports/
└── reports/
```

## 只启动 MCP

如果 ARL 已经在运行：

```bash
docker compose --profile mcp up -d --build arl-mcp
```

如果要持久化：

```bash
docker compose -f docker-compose.yml -f docker-compose.mcp-intel.yml --profile mcp up -d --build arl-mcp
```

## 客户端配置示例

适用于支持 MCP SSE 的客户端：

```json
{
  "mcpServers": {
    "arl-plus": {
      "url": "http://127.0.0.1:8765/sse"
    }
  }
}
```

如果你的客户端只支持 stdio，可以在本机直接跑：

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ARL_BASE_URL=https://127.0.0.1:5003 \
ARL_TOKEN="你的_ARL_API_KEY" \
ARL_ALLOWED_SUFFIXES="example.com" \
MCP_DATA_DIR=../mcp-data \
MCP_TRANSPORT=stdio \
python server.py
```

stdio 客户端配置示例：

```json
{
  "mcpServers": {
    "arl-plus": {
      "command": "/absolute/path/to/mcp/.venv/bin/python",
      "args": ["/absolute/path/to/mcp/server.py"],
      "env": {
        "ARL_BASE_URL": "https://127.0.0.1:5003",
        "ARL_TOKEN": "你的_ARL_API_KEY",
        "ARL_ALLOWED_SUFFIXES": "example.com",
        "MCP_DATA_DIR": "/absolute/path/to/mcp-data",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

## 推荐使用流程

### 1. 健康检查

```text
调用 arl_health
```

### 2. 创建任务

```text
调用 arl_create_task(name="example", target="example.com")
```

### 3. 任务完成后筛高价值入口

```text
调用 arl_find_interesting_sites(min_score=20)
```

### 4. 生成分类资产

```text
调用 arl_find_login_panels
调用 arl_find_api_assets
调用 arl_find_dev_assets
调用 arl_find_ops_assets
```

### 5. 保存快照

```text
调用 arl_snapshot_sites(name="example")
```

### 6. 下次扫描后做差异

```text
调用 arl_diff_latest_sites(name="example")
```

### 7. 导出 URL 给后续工具

```text
调用 arl_export_urls(category="api_asset", output_format="text")
```

### 8. 生成报告和任务计划

```text
调用 arl_attack_surface_report
调用 arl_build_followup_plan
```

## 评分分类

当前分类：

```text
login_panel       后台、登录、SSO、Console
api_asset         API、Gateway、Swagger、OpenAPI、GraphQL
dev_test_asset    dev、test、uat、stage、beta
ops_middleware    Jenkins、GitLab、Grafana、Kibana、Nexus、Harbor 等
storage_cdn       OSS、COS、S3、MinIO、CDN、上传/文件服务
doc_portal        docs、wiki、portal、manual
payment_business  pay、order、trade、wallet 等业务系统
non_standard_port 非 80/443 端口
alive             2xx/3xx 存活资产
normal_web        普通 Web
```

## 安全边界

`arl_create_task` 默认要求配置 `ARL_ALLOWED_SUFFIXES`，否则拒绝创建扫描任务。读取类工具不受这个限制。

允许全部目标可设置：

```bash
export ARL_ALLOWED_SUFFIXES="*"
```

不建议这么做。推荐每次只放授权域名或授权网段。

## 常见问题

### 1. arl_health 失败

检查：

```bash
docker logs arl_mcp
docker logs arl_web
```

确认 `ARL_BASE_URL` 是否正确。Docker Compose 内部默认使用：

```text
https://web:443
```

宿主机 stdio 模式一般使用：

```text
https://127.0.0.1:5003
```

### 2. 证书报错

默认 `ARL_VERIFY_TLS=false`，会忽略 ARL 自签证书。如果你换成正式证书，可以设置：

```bash
export ARL_VERIFY_TLS=true
```

### 3. 创建任务被拒绝

检查目标是否命中：

```bash
echo $ARL_ALLOWED_SUFFIXES
```

例如：

```bash
export ARL_ALLOWED_SUFFIXES="example.com,10.0.0.0/8"
```

### 4. 没有报告文件

确认是否叠加了持久化 override：

```bash
docker compose -f docker-compose.yml -f docker-compose.mcp-intel.yml --profile mcp up -d --build
```
