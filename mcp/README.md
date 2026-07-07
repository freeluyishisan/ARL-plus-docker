# ARL-plus MCP

这个目录给 ARL-plus-docker 增加一个独立 MCP sidecar。它不改 ARL 主镜像，只通过 ARL Web API 读取任务、资产，并把原始资产升级成“AI 可调度的资产情报”。

## 这版增强了什么

- 多页拉取 ARL 站点资产，自动去重、归一化 URL。
- 对后台、登录、SSO、API、Swagger、GraphQL、测试环境、运维中间件、对象存储、核心业务系统打分。
- 一键筛选登录入口、API 入口、测试环境、运维中间件。
- 导出 URL 清单，方便给浏览器、Playwright、xray 代理扫描、Hermes worker 使用。
- 保存资产快照，下一轮扫描后做新增、消失、变化对比。
- 生成后续验证计划，把资产自动分成登录态、API 权限、测试环境、中间件、上传/对象存储等方向。
- 生成 xray 目标和运行建议，但不在 MCP 内直接执行 xray。
- 生成简版资产报告，方便 AI 路由和人工复核。

## 已暴露 MCP 工具

```text
arl_mcp_config
arl_health
arl_create_task
arl_list_tasks
arl_get_sites
arl_get_domains
arl_get_ports
arl_score_sites
arl_find_interesting_sites
arl_find_login_panels
arl_find_api_assets
arl_find_dev_assets
arl_find_ops_assets
arl_export_urls
arl_snapshot_sites
arl_diff_sites
arl_build_followup_plan
arl_make_xray_targets
arl_report
```

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

快照数据默认保存在：

```text
./mcp-data/snapshots/
```

## 只启动 MCP

如果 ARL 已经在运行：

```bash
docker compose --profile mcp up -d --build arl-mcp
```

## SSE 客户端配置示例

```json
{
  "mcpServers": {
    "arl-plus": {
      "url": "http://127.0.0.1:8765/sse"
    }
  }
}
```

## stdio 本地调试

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

ARL_BASE_URL=https://127.0.0.1:5003 \
ARL_TOKEN="你的_ARL_API_KEY" \
ARL_ALLOWED_SUFFIXES="example.com" \
ARL_DATA_DIR=../mcp-data \
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
        "ARL_DATA_DIR": "/absolute/path/to/mcp-data",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

## 推荐工作流

### 1. 健康检查

```text
arl_health
```

### 2. 创建 ARL 任务

```text
arl_create_task(name="example", target="example.com")
```

`arl_create_task` 会检查 `ARL_ALLOWED_SUFFIXES`。为空时拒绝创建任务。

### 3. 任务完成后生成报告

```text
arl_report(task_id="")
```

### 4. 筛高价值资产

```text
arl_find_interesting_sites(min_score=20)
arl_find_login_panels()
arl_find_api_assets()
arl_find_dev_assets()
arl_find_ops_assets()
```

### 5. 导出 URL

```text
arl_export_urls(min_score=20, only_interesting=true)
```

返回：

```text
urls   数组格式
lines  换行文本格式
items  带 score/tags/reasons 的结构化资产
```

### 6. 保存快照

```text
arl_snapshot_sites(snapshot_name="example")
```

### 7. 下次扫描后做差异

```text
arl_diff_sites(snapshot_name="example", update_baseline=false)
```

返回：

```text
added      新增资产
removed    消失资产
changed    标题、状态码、指纹、端口、评分、标签变化
```

确认这轮结果后可以更新基线：

```text
arl_diff_sites(snapshot_name="example", update_baseline=true)
```

### 8. 生成后续验证计划

```text
arl_build_followup_plan()
```

输出会按这些方向拆分：

```text
auth_and_login
api_and_permission
dev_test_exposure
ops_middleware
storage_upload
top_priority
```

### 9. 生成 xray 目标

```text
arl_make_xray_targets(min_score=20)
```

它只生成目标和命令，不直接执行 xray。登录后扫描推荐走代理模式：

```bash
xray webscan --listen 127.0.0.1:7777 \
  --html-output /tmp/xray-auth.html \
  --json-output /tmp/xray-auth.json
```

然后让浏览器或 Playwright 使用代理：

```text
http://127.0.0.1:7777
```

## 评分分类

核心标签：

```text
login_panel       后台、登录、SSO、Console
api_asset         API、Gateway、GraphQL、REST
swagger_asset     Swagger、OpenAPI、Knife4j、Apifox
dev_asset         dev、test、uat、stage、beta、pre、qa
ops_middleware    Jenkins、GitLab、Nexus、Harbor、Grafana、Kibana、Nacos 等
storage_asset     OSS、COS、S3、MinIO、上传/文件服务
business_core     order、pay、tenant、role、permission 等业务系统
non-standard-port 非 80/443 端口
alive             2xx/3xx 存活资产
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

### 4. 快照没有保存

确认 compose 已经包含：

```yaml
volumes:
  - ./mcp-data:/data
```

然后检查：

```bash
ls -lah mcp-data/snapshots/
```
