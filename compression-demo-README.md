# Compression Processor Demo

This demo shows how the OpenTelemetry Collector Compression Processor works to compress large attribute values.

## Overview

The compression processor compresses large string attribute values to reduce the size of telemetry data. This is particularly useful for attributes like SQL queries or other large text values that can consume significant bandwidth.

## How the Compression Processor is Built

The compression processor is included in the OpenTelemetry Collector Contrib build. However, you should verify it's actually built into your collector binary.

To verify the compression processor is available in your build:

```bash
# Check if the compression processor module is in the codebase
ls -la processor/compressionprocessor

# Check if compression processor is loaded in the collector
make otelcontribcol
strings ./bin/otelcontribcol_$(go env GOOS)_$(go env GOARCH) | grep -i compressionprocessor

# You can also use our built-in check tool
make check-compression-processor
```

If the compression processor is not found in your build, you can add it with:

```bash
# Add the compression processor to the builder config
bash add-compression-processor.sh

# Then rebuild the collector 
make docker-otelcontribcol
```

The script will add the following line to the processors section in `cmd/otelcontribcol/builder-config.yaml`:

```yaml
processors:
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/compressionprocessor
  # ...other processors
```

## Demo Components

The demo includes:
- **Jaeger**: For trace visualization
- **OpenTelemetry Collector**: With compression processor configured
- **Two telemetry generators**:
  - One sending traces with large SQL statements (to be compressed)
  - One sending traces with small SQL statements (below compression threshold)

## Configuration

The compression processor is configured in `test-config.yaml`:

```yaml
compressionprocessor:
  attributes:
    - db.statement        # Target the db.statement attribute
  compression: zstd       # Use zstd compression
  encoding: base64        # Use base64 encoding
  threshold_kb: 0.5       # Compress values larger than 0.5KB
  log_compression_ratio: true  # Log compression statistics
```

For this demo to work properly, the collector will attempt to load the compression processor at runtime. If you see an error like `"failed to create pipeline"` or `"error creating processor"`, it likely means the compression processor wasn't built into the binary.

## Running the Demo

```bash
# Start the demo
make run-compression-demo

# Or manually
make docker-otelcontribcol
docker compose up
```

## Viewing Results

1. Open Jaeger UI at http://localhost:16686
2. Search for traces from either service:
   - `large-statement-service` - Has compressed `db.statement` attribute
   - `small-statement-service` - Has uncompressed `db.statement` attribute

## Verifying Compression

Check the collector logs for messages like:
```
Attribute 'db.statement' was compressed by 35%
```

In the Jaeger UI, you'll notice that traces from the `large-statement-service` have a `db.statement` attribute that looks encoded (starting with a compression marker and then base64 text), while traces from the `small-statement-service` have the original SQL text.

## Troubleshooting

If you don't see compression happening:

1. Check that the attributes are larger than the threshold (0.5KB)
2. Ensure the compression processor is properly configured in the pipeline
3. Look for any errors in the collector logs

If no traces appear in Jaeger:
1. Check that all containers are running: `docker compose ps`
2. Verify the collector health: `docker compose exec otel-collector nc -z localhost 4317`
3. Check collector logs for any errors: `docker compose logs otel-collector`
