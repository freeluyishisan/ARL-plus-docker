# ARL AI Boost

本增强层把 ARL 的原始资产结果转成更适合 AI 调度的结构化情报。

## 新增 MCP 工具

```text
arl_asset_brief
arl_export_urls
arl_markdown_report
arl_asset_snapshot
arl_diff_snapshots
arl_followup_plan
```

## 分类

```text
auth_surface       登录、后台、SSO、认证面
api_surface        API、网关、Swagger、OpenAPI、GraphQL
business_surface   订单、支付、用户、租户、权限相关业务面
test_env           dev、test、uat、stage、beta 等环境
ops_middleware     Jenkins、GitLab、Nacos、Grafana、Kibana 等管理面
storage_surface    OSS、COS、S3、MinIO、上传下载、CDN
js_asset           JS 资产
risky_port         高关注端口
non_standard_port  非 80/443 端口
```

## CLI 用法

本地运行：

```bash
cd mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ARL_BASE_URL=https://127.0.0.1:5003
export ARL_TOKEN="你的_ARL_API_KEY"
```

生成摘要：

```bash
python arl_boost_cli.py summary --pages 5 --size 200
```

导出高价值 URL：

```bash
python arl_boost_cli.py urls --min-score 40 -o out/high-value-urls.txt
```

生成 Markdown 报告：

```bash
python arl_boost_cli.py report -o out/asset-report.md
```

生成资产快照：

```bash
python arl_boost_cli.py snapshot -o out/snapshot-1.json
```

对比两次快照：

```bash
python arl_boost_cli.py diff --old out/snapshot-1.json --new out/snapshot-2.json -o out/diff.json
```

生成后续任务计划：

```bash
python arl_boost_cli.py plan -o out/followup-plan.json
```

## 推荐流程

```text
ARL 跑任务
  ↓
arl_asset_brief 看总体资产质量
  ↓
arl_find_interesting_sites 挑高价值入口
  ↓
arl_export_urls 导出 URL
  ↓
arl_markdown_report 生成报告
  ↓
arl_asset_snapshot 每天留快照
  ↓
arl_diff_snapshots 只看新增和变化
```
