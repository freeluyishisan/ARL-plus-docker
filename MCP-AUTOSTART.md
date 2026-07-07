# MCP 无感启动

目标：除了配置变量，不再要求命令里额外带 `--profile mcp` 或 `-f docker-compose.mcp-data.yml`。

## 用法

复制环境变量模板：

```bash
cp .env.example .env
```

编辑 `.env`：

```bash
COMPOSE_PROFILES=mcp
ARL_TOKEN=你的_ARL_API_KEY
ARL_ALLOWED_SUFFIXES=example.com,example.cn
```

然后正常启动：

```bash
docker compose up -d --build
```

MCP 会和 ARL 一起启动。

## 为什么这样可以

Docker Compose 会自动读取当前目录的 `.env`。

`.env` 里的：

```bash
COMPOSE_PROFILES=mcp
```

等价于每次命令都带：

```bash
--profile mcp
```

仓库里的 `docker-compose.override.yml` 会被 Docker Compose 自动叠加读取，用来给 `arl-mcp` 增加持久化目录和 MCP 数据参数。

## 数据目录

MCP 资产情报输出会保存到：

```text
./mcp-data/
├── snapshots/
├── exports/
└── reports/
```

## 检查

```bash
docker ps | grep arl_mcp
docker logs -f arl_mcp
```

MCP SSE 地址：

```text
http://127.0.0.1:8765/sse
```

## 关闭 MCP 自动启动

编辑 `.env`，删除或注释：

```bash
COMPOSE_PROFILES=mcp
```

然后重建：

```bash
docker compose down
docker compose up -d
```
