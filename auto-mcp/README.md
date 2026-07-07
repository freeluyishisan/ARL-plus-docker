# ARL Auto Tools MCP

这个 MCP bridge 把 `auto-tools` 的自动化能力暴露给 AI 客户端。

默认 SSE 地址：

```text
http://127.0.0.1:8766/sse
```

## MCP 工具

```text
auto_tools_config
auto_tools_health
auto_httpx
auto_katana
auto_nuclei
auto_subfinder
auto_dnsx
auto_runs
auto_recon_pipeline
```

## 客户端配置示例

```json
{
  "mcpServers": {
    "arl-auto-tools": {
      "url": "http://127.0.0.1:8766/sse"
    }
  }
}
```

## 推荐使用

先用原 ARL MCP：

```text
arl_find_interesting_sites
arl_export_urls
```

把导出的 URL 传给 Auto MCP：

```text
auto_httpx
auto_katana
auto_nuclei
```

快速流水线：

```text
auto_recon_pipeline(name="demo", lines="https://www.example.com", run_katana=true, run_nuclei=false)
```

默认建议先跑 `httpx` 和 `katana`，nuclei 只对筛选后的高价值入口运行。
