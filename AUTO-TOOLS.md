# ARL 自动化工具层

这层不是替代 ARL，而是给 ARL-plus 增加自动化执行能力：

```text
ARL 发现资产
  ↓
arl-mcp 评分、分类、导出 URL
  ↓
arl-auto-tools 自动跑工具
  ↓
mcp-data 保存结果
```

## 新增工具

`arl-auto-tools` 容器内置：

```text
httpx       存活探测、标题、状态码、技术栈识别
katana      轻量爬虫、JS URL 发现
nuclei      模板化风险检查
subfinder   子域名发现
dnsx        DNS 解析和存活确认
```

## 启动

复制配置：

```bash
cp .env.example .env
vim .env
```

至少配置：

```bash
COMPOSE_PROFILES=mcp
ARL_TOKEN=你的_ARL_API_KEY
ARL_ALLOWED_SUFFIXES=example.com,example.cn
AUTO_TOOLS_ALLOWED_SUFFIXES=example.com,example.cn
```

启动：

```bash
docker compose up -d --build
```

检查：

```bash
docker ps | grep arl_auto_tools
docker logs -f arl_auto_tools
curl -s http://127.0.0.1:8770/health | jq
```

## 输出目录

```text
./mcp-data/auto-tools/runs/
```

每次运行会生成一个独立目录：

```text
runs/YYYYMMDDTHHMMSSZ-tool-name-random/
├── input_urls.txt
├── command.log
├── stdout.txt
├── stderr.txt
└── 工具输出文件
```

## API 用法

### httpx 存活探测

```bash
curl -s http://127.0.0.1:8770/run/httpx \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"demo-httpx",
    "urls":["https://www.example.com"],
    "follow_redirects":true
  }' | jq
```

输出文件：

```text
httpx.jsonl
```

### katana 爬虫

```bash
curl -s http://127.0.0.1:8770/run/katana \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"demo-katana",
    "urls":["https://www.example.com"],
    "depth":2,
    "js_crawl":true
  }' | jq
```

输出文件：

```text
katana_urls.txt
```

### nuclei 检查

```bash
curl -s http://127.0.0.1:8770/run/nuclei \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"demo-nuclei",
    "urls":["https://www.example.com"],
    "severity":"low,medium,high,critical",
    "rate_limit":20,
    "concurrency":10
  }' | jq
```

输出文件：

```text
nuclei.jsonl
```

### subfinder 子域名发现

```bash
curl -s http://127.0.0.1:8770/run/subfinder \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"demo-subfinder",
    "domain":"example.com"
  }' | jq
```

输出文件：

```text
subdomains.txt
```

### dnsx 解析确认

```bash
curl -s http://127.0.0.1:8770/run/dnsx \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"demo-dnsx",
    "urls":["https://www.example.com"]
  }' | jq
```

输出文件：

```text
dnsx.jsonl
```

## 和 ARL MCP 联动

先让 MCP 导出 URL：

```text
调用 arl_export_urls(category="api_asset", output_format="text")
```

拿到导出文件或 URL 列表后，传给 `arl-auto-tools`：

```bash
curl -s http://127.0.0.1:8770/run/httpx \
  -H 'Content-Type: application/json' \
  -d @payload.json | jq
```

## 范围控制

工具层会读取：

```bash
AUTO_TOOLS_ALLOWED_SUFFIXES
```

如果没配置，会退回使用：

```bash
ARL_ALLOWED_SUFFIXES
```

不在范围内的 URL / domain 会被拒绝。

## 调参

```bash
AUTO_TOOLS_MAX_URLS=1000
AUTO_TOOLS_TIMEOUT=1800
AUTO_TOOLS_HTTPX_RATE_LIMIT=50
AUTO_TOOLS_NUCLEI_RATE_LIMIT=20
AUTO_TOOLS_NUCLEI_CONCURRENCY=10
AUTO_TOOLS_KATANA_DEPTH=2
```
