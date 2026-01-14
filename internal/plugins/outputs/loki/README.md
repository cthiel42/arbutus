# Loki Output Plugin

The Loki output plugin sends logs to Grafana Loki for centralized log aggregation and querying.

## Configuration

```toml
[outputs.loki]
  domain = "http://yourdomain.com:3100"
  endpoint = "/loki/api/v1/push"  # Optional
  timeout = "10s"                  # Optional
  username = ""                    # Optional
  password = ""                    # Optional
```

### Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `domain` | string | Yes | - | Base URL of the Loki instance (e.g., `http://yourdomain.com:3100` or `https://logs.example.com`) |
| `endpoint` | string | No | `/loki/api/v1/push` | API endpoint path for pushing logs |
| `timeout` | string | No | `10s` | HTTP client timeout (e.g., `10s`, `30s`, `1m`) |
| `username` | string | No | - | Username for HTTP basic authentication |
| `password` | string | No | - | Password for HTTP basic authentication |
| `headers` | map | No | - | Custom HTTP headers to include in requests |

## Supported Telemetry Types

- **Logs**: Fully supported
- **Metrics**: Not supported (will be skipped)
- **Traces**: Not supported (will be skipped)

## How It Works

The plugin converts logs into Loki's stream format:
- Log attributes become Loki labels (indexed for querying)
- Log level is automatically added as a label
- Logs with the same labels are grouped into streams
- Invalid UTF-8 characters are automatically sanitized

## Usage Examples

### Basic Local Setup

```toml
[outputs.loki]
  domain = "http://localhost:3100"
```

### Remote Loki with Authentication

```toml
[outputs.loki]
  domain = "https://logs.example.com"
  username = "user"
  password = "secret"
  timeout = "30s"
```

### Grafana Cloud

```toml
[outputs.loki]
  domain = "https://logs-prod-us-central1.grafana.net"
  username = "123456"
  password = "your-grafana-cloud-api-key"
```

### Custom Headers

```toml
[outputs.loki]
  domain = "http://localhost:3100"

[outputs.loki.headers]
  X-Scope-OrgID = "tenant1"
```

### Multiple Loki Outputs

Send logs to multiple Loki instances:

```toml
[outputs.loki_local]
  domain = "http://localhost:3100"

[outputs.loki_prod]
  domain = "https://logs.example.com"
  username = "prod-user"
  password = "prod-password"
```

## Querying Logs in Loki

Once logs are sent to Loki, you can query them using LogQL:

### Basic Queries

```logql
# All logs
{level="error"}

# Filter by attributes
{input="memleak", hostname="server1"}

# Search message content
{level="warning"} |= "memory leak"

# Combine labels and text search
{hostname="server1"} |= "error" != "timeout"
```

### Advanced Queries

```logql
# Count error logs per minute
rate({level="error"}[1m])

# Filter by log message
{input="memleak"} |= "Memory leak detected"

# Parse and filter JSON fields
{level="error"} | json | bytes > 10000000
```

## Notes
- Logs are sent via HTTP POST to the Loki push API
- The plugin groups logs by labels into streams for efficient batching
- HTTP client supports environment proxy settings
- Responses with status codes outside 200-299 are treated as errors
- All log attributes are included as Loki labels
- UTF-8 validation ensures compatibility with Loki's requirements
- Thread-safe for concurrent writes