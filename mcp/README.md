# ARL-plus MCP

这个目录给 ARL-plus-docker 增加一个独立 MCP sidecar。它不会修改 ARL 主镜像，只通过 ARL Web API 读取任务、资产，并按规则筛选高价值入口。

## 功能

已暴露 MCP 工具：

- `arl_mcp_config`：查看 MCP/ARL 连接配置，不泄露 token。
- `arl_health`：检查 ARL API 是否可用。
- `arl_create_task`：创建受 allowlist 限制的 ARL 资产发现任务。
- `arl_list_tasks`：查看任务列表。
- `arl_get_sites`：读取站点资产。
- `arl_get_domains`：读取域名资产。
- `arl_score_sites`：按后台、API、Swagger、测试环境、中间件、非标端口等维度打分。
- `arl_find_interesting_sites`：只返回高价值资产。

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

## 只启动 MCP

如果 ARL 已经在运行：

```bash
docker compose --profile mcp up -d --build arl-mcp
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
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
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
