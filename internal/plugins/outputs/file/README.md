# File Output Plugin

The File output plugin writes logs and metrics to a local file in line-based format.

## Configuration

```toml
[outputs.file]
  filepath = "/var/log/arbutus/output.log"
```

### Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `filepath` | string | Yes | Absolute or relative path to the output file. File will be created if it doesn't exist. |

## Supported Telemetry Types

- **Logs**: Fully supported
- **Metrics**: Fully supported (InfluxDB line protocol)
- **Traces**: Not supported (will be skipped)

## Output Format

### Logs

Logs are written in human-readable format with optional JSON attributes:

```
2026-01-11T10:30:00Z [warning] Memory leak detected {"hostname":"server1","input":"memleak"}
2026-01-11T10:30:01Z [error] Connection failed {"service":"database"}
2026-01-11T10:30:02Z [info] Service started
```

**Format:** `<timestamp> [<level>] <message> <attributes_json>`

### Metrics

Metrics use Influx line protocol format:

```
cpu_usage,host=server1,region=us-west value=75.5,user=50.2,system=25.3 1736594401123456789
memory_usage,host=server1 value=8589934592 1736594402000000000
disk_io,device=sda value=1024 1736594403000000000
```

**Format:** `<metric_name>,<tag_key>=<tag_value> <field_key>=<field_value> <timestamp_nanoseconds>`

## Notes

- The file is opened in append mode, so existing content is preserved
- All writes are thread-safe using a mutex
- The file is synced and closed gracefully on shutdown
- Parent directories must exist; they are not created automatically
- File permissions are set to `0644` (rw-r--r--)
- Log attributes are encoded as JSON inline with the message