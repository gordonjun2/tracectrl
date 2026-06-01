# hermes-tracectrl

Security observability plugin for Hermes Agent that exports rich telemetry via OpenTelemetry. Captures message content, tool calls with arguments and results, model usage, session lifecycle, and security-relevant events.

Produces the same span names, metric names, and attribute keys as the [openclaw-tracectrl](../openclaw-tracectrl/) plugin so the TraceCtrl dashboard, topology views, and risk scoring work identically regardless of which agent framework is in use.

## What It Captures

| Hermes Hook | Span | Key Attributes |
|---|---|---|
| `on_session_start` | `tracectrl.request` (root) | channel, session key, direction, message.id |
| `pre_llm_call` | `tracectrl.agent.turn` | model, provider, message.from |
| `post_api_request` | `tracectrl.model.usage` | token usage, cost_usd, context window, duration |
| `pre_tool_call` | `tracectrl.tool.{name}` | tool name, call ID, input, security |
| `post_tool_call` | (closes tool span) | result, duration, errors |
| `post_llm_call` | (closes agent + root) | response preview, message.outcome |
| `on_session_end` | `tracectrl.session.{action}` | action (end/stopped/interrupted), session key |
| `on_session_finalize` | (flush) | — |
| `on_gateway_error` | `tracectrl.webhook.error` / `tracectrl.session.stuck` | error type, source, diagnostic |
| `pre_approval_request` | `tracectrl.security.approval` | command, description |
| `post_approval_response` | (closes approval span) | choice |

### Security Detection

The plugin automatically flags:

- **Dangerous tools** — bash, shell, exec, execute, run_command, terminal, execute_code, subprocess
- **Dangerous commands** — rm -rf, sudo, reverse shells, piped curl/wget
- **Sensitive file access** — .env, private keys, /etc/passwd, credentials
- **Prompt injection** — "ignore previous instructions", jailbreak patterns

Findings are recorded as span attributes (`tracectrl.security.*`) and counted via the `tracectrl.security.events` metric.

### Metrics

| Metric | Type | Description |
|---|---|---|
| `tracectrl.messages.received` | Counter | Inbound messages |
| `tracectrl.messages.sent` | Counter | Outbound messages |
| `tracectrl.tool.calls` | Counter | Tool invocations |
| `tracectrl.tool.errors` | Counter | Tool errors |
| `tracectrl.tokens.total` | Counter | Total tokens |
| `tracectrl.tokens.prompt` | Counter | Input tokens |
| `tracectrl.tokens.completion` | Counter | Output tokens |
| `tracectrl.security.events` | Counter | Security events |
| `tracectrl.session.resets` | Counter | Session reset events |
| `tracectrl.agent.turn.duration_ms` | Histogram | Agent turn duration |
| `tracectrl.tool.duration_ms` | Histogram | Tool call duration |

## Installation

### Quick Install

```bash
cd plugins/hermes-tracectrl
./install.sh --endpoint http://localhost:4318 --protocol http
hermes plugins enable observability/tracectrl
hermes restart
```

### Manual Install

```bash
# 1. Install Python dependencies (choose http or grpc)
pip install tracectrl opentelemetry-exporter-otlp-proto-http

# 2. Copy plugin to Hermes plugins directory
mkdir -p ~/.hermes/plugins/observability/tracectrl
cp __init__.py hooks.py config.py telemetry.py security.py plugin.yaml \
   ~/.hermes/plugins/observability/tracectrl/

# 3. Enable the plugin
hermes plugins enable observability/tracectrl

# 4. Restart Hermes
hermes restart
```

## Configuration

### Environment Variables (recommended)

Add to `~/.hermes/.env`:

```bash
TRACECTRL_ENDPOINT=http://localhost:4318
TRACECTRL_PROTOCOL=http
TRACECTRL_SERVICE_NAME=hermes-agent
TRACECTRL_API_KEY=your-api-key        # optional
TRACECTRL_CAPTURE_CONTENT=false        # set true to capture message/tool content
```

### Config Options

| Variable | Type | Default | Description |
|---|---|---|---|
| `TRACECTRL_ENDPOINT` | string | `http://localhost:4318` | OTLP collector endpoint |
| `TRACECTRL_PROTOCOL` | `"http"` \| `"grpc"` | `http` | OTLP transport protocol |
| `TRACECTRL_SERVICE_NAME` | string | `hermes-agent` | Service name for traces |
| `TRACECTRL_API_KEY` | string | _(none)_ | API key for collector auth |
| `TRACECTRL_CAPTURE_CONTENT` | boolean | `false` | Capture message text and tool I/O (privacy-sensitive) |
| `TRACECTRL_TRACES` | boolean | `true` | Enable trace export |
| `TRACECTRL_METRICS` | boolean | `true` | Enable metric export |
| `TRACECTRL_METRICS_INTERVAL_MS` | number | `30000` | Metric export interval |
| `TRACECTRL_FAIL_SILENTLY` | boolean | `true` | Suppress telemetry errors |

### Populated attributes (from Hermes Agent)

The following span attributes are populated by the Hermes Agent `post_api_request` hook:

| Attribute | Source | Description |
|---|---|---|
| `tracectrl.cost_usd` | `cost_result.amount_usd` | Per-API-call cost in USD (None if pricing unavailable) |
| `tracectrl.context.limit` | `context_compressor.context_length` | Model context window limit (tokens) |
| `tracectrl.context.used` | `context_compressor.last_prompt_tokens` | Context tokens used (tokens) |

## Architecture

```
plugins/hermes-tracectrl/
  __init__.py      — Plugin entry point (register(ctx)) + state management
  hooks.py         — All hook handlers (mirrors openclaw hooks.ts)
  config.py        — Configuration parsing from env vars
  telemetry.py     — OpenTelemetry provider setup (HTTP + gRPC support)
  security.py      — Security detection helpers
  plugin.yaml      — Hermes plugin manifest
  pyproject.toml   — Package definition
  install.sh       — Installation script
```

The plugin is strictly observational — all hooks return `None` to avoid modifying agent behavior. Every hook handler is wrapped in try/except so telemetry errors never crash the agent or gateway.

### Trace Hierarchy

```
tracectrl.request (root, per user turn)
├── tracectrl.agent.turn (per LLM call iteration)
│   ├── tracectrl.tool.{name} (per tool call)
│   └── tracectrl.tool.{name}
├── tracectrl.model.usage (per LLM API call — parity with openclaw)
├── tracectrl.agent.turn (next iteration)
│   └── ...
└── (root closed on final response)

tracectrl.session.{action} (on session end/stop/interrupt)
tracectrl.security.approval (on approval prompts)
tracectrl.gateway.startup (on plugin registration)
```

### Span Enrichment via tracectrl SDK

The `TraceCtrlSpanProcessor` from the tracectrl SDK automatically enriches spans with:

- `tracectrl.session_id` — session tracking
- `tracectrl.tool.category` — inferred tool category (code_execution, file_system, etc.)
- `tracectrl.tool.direction` — input/output/internal classification
- `tracectrl.agent.framework` — set to `"hermes"`
- `tracectrl.system_prompt_hash` — hashed system prompt
- `tracectrl.span_sequence` — monotonic sequence counter

## Development

```bash
cd plugins/hermes-tracectrl

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -q
```

## Parity with openclaw-tracectrl

| Feature | openclaw-tracectrl | hermes-tracectrl |
|---|---|---|
| Root span | `tracectrl.request` | Same |
| LLM usage span | `tracectrl.model.usage` | Same |
| Tool spans | `tracectrl.tool.{name}` | Same |
| Session action spans | `tracectrl.session.{action}` | Same |
| Gateway startup | `tracectrl.gateway.startup` | Same |
| Webhook error span | `tracectrl.webhook.error` | Same (via `on_gateway_error` platform errors) |
| Session stuck span | `tracectrl.session.stuck` | Same (via `on_gateway_error` timeout/stuck-loop) |
| Counter metrics (9) | Same names | Same names |
| Histogram metrics (2) | Same names | Same names |
| Security detection | 13 injection + 9 command + 13 file patterns | Identical patterns |
| OTLP protocol | HTTP (default) | HTTP (default) + gRPC option |
| Fail-open design | try/catch every hook | try/except every hook |
| Stale session cleanup | 5-min TTL, 60s interval | Same |
| Config surface | endpoint, serviceName, captureContent, protocol | Same via env vars |

Not applicable (framework differences):
- Dynamic SDK loader — Hermes exposes hooks directly, no workaround needed

## License

Apache-2.0
