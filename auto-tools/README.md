# ARL Auto Tools Sidecar

这个 sidecar 给 ARL-plus-docker 增加自动化执行能力，不改 ARL 主镜像。

它适合做：

- httpx 存活探测、标题、状态码、指纹识别
- katana 轻量爬虫和 JS URL 收集
- nuclei 模板扫描，默认低速率、低并发
- subfinder 授权域名子域收集
- dnsx DNS 解析验证
- runs 结果归档

## 启动

复制 `.env.example` 为 `.env`：

```bash
cp .env.example .env
vim .env
```

至少配置：

```bash
COMPOSE_PROFILES=mcp
ARL_ALLOWED_SUFFIXES=example.com,example.cn
AUTO_TOOLS_ALLOWED_SUFFIXES=example.com,example.cn
```

启动：

```bash
docker compose up -d --build
```

服务地址：

```text
http://127.0.0.1:8770
```

数据目录：

```text
./mcp-data/auto-tools/runs/
```

## 健康检查

```bash
curl -s http://127.0.0.1:8770/health | jq
```

## 运行 httpx

```bash
curl -s http://127.0.0.1:8770/run/httpx \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-httpx",
    "urls": ["https://www.example.com"]
  }' | jq
```

## 运行 katana

```bash
curl -s http://127.0.0.1:8770/run/katana \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-katana",
    "urls": ["https://www.example.com"],
    "depth": 2,
    "js_crawl": true
  }' | jq
```

## 运行 nuclei

```bash
curl -s http://127.0.0.1:8770/run/nuclei \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-nuclei",
    "urls": ["https://www.example.com"],
    "severity": "low,medium,high,critical",
    "rate_limit": 20,
    "concurrency": 10
  }' | jq
```

## 运行 subfinder

```bash
curl -s http://127.0.0.1:8770/run/subfinder \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-subfinder",
    "domain": "example.com"
  }' | jq
```

## 运行 dnsx

```bash
curl -s http://127.0.0.1:8770/run/dnsx \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-dnsx",
    "urls": ["https://www.example.com"]
  }' | jq
```

## 查看历史任务

```bash
curl -s 'http://127.0.0.1:8770/runs?limit=20' | jq
```

## 安全边界

所有输入都会经过 allowlist 检查：

```bash
AUTO_TOOLS_ALLOWED_SUFFIXES=example.com,example.cn
```

未命中 allowlist 的 URL 或域名会被拒绝。

默认限制：

```bash
AUTO_TOOLS_MAX_URLS=1000
AUTO_TOOLS_TIMEOUT=1800
AUTO_TOOLS_HTTPX_RATE_LIMIT=50
AUTO_TOOLS_NUCLEI_RATE_LIMIT=20
AUTO_TOOLS_NUCLEI_CONCURRENCY=10
AUTO_TOOLS_KATANA_DEPTH=2
```

如需加大强度，优先调整 allowlist 和速率，不要把 `AUTO_TOOLS_ALLOWED_SUFFIXES=*` 用在非隔离环境。
