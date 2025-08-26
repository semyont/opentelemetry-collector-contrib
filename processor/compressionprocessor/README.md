# OpenTelemetry Collector Compression Processor

**Status:** `development`

| Signal | Status     | Stability    |
| ------ | ---------- | -------------- |
| traces | processing | `development` |

This processor (`compressionprocessor`) losslessly compresses specified large string attributes within trace spans and encodes the result before they are exported. This can significantly reduce telemetry payload size and associated network/storage costs, especially for attributes containing verbose data like SQL statements, HTTP bodies, or custom payloads.

## How It Works

1.  **Configuration:** You provide a list of attribute keys (`attributes`), the desired `compression` algorithm, and the `encoding` method.
2.  **Processing:** The processor intercepts trace data.
3.  **Scanning:** For each span, it checks if any attribute key matches the configured `attributes` list.
4.  **Type Check:** It verifies that the attribute's value is a string. Non-string attributes are skipped.
5.  **Compression:** The string value is compressed using the configured algorithm (`compression`, default: `lz4`). Algorithm-specific parameters like compression `level` can be optionally configured via `compression_params`.
6.  **Encoding:** The resulting compressed byte array is encoded into a string using the configured method (`encoding`, default: `base64`).
7.  **Attribute Replacement:**
    *   The original attribute (e.g., `db.statement`) is removed from the span.
    *   A new attribute is added with the suffix `_compressed` (e.g., `db.statement_compressed`) containing the encoded, compressed string.
8.  **Debugging:** If `debug` is enabled, the processor logs the original and compressed sizes (in bytes) and the chosen encoding type for each processed attribute.

**Example Transformation:**

*   **Input Span Attribute:**
    `db.statement`: `"SELECT user_id, user_name, email FROM users WHERE country = 'US' AND last_login > '2024-01-01' ORDER BY last_login DESC LIMIT 1000;"`
*   **Output Span Attributes (using `lz4` compression and `base64` encoding):**
    *   `db.statement`: *Removed*
    *   `db.statement_compressed`: `"<base64(lz4-compressed-bytes)>"` (Actual Base64 string will be here)
*   **Output Span Attributes (using `zstd` compression and `base85` encoding):**
    *   `db.statement`: *Removed*
    *   `db.statement_compressed`: `"<base85(zstd-compressed-bytes)>"` (Actual Base85 string will be here)

## Supported Compression Algorithms

The processor supports the following compression algorithms:

*   `lz4` (Default)
*   `zstd`
*   `snappy`
*   `gzip`
*   `zlib`
*   `deflate` (Handled by the `zlib` library)
*   `none` (Passes the value through without compression, useful for testing or conditional disabling)

## Supported Encodings

The processor supports encoding the compressed bytes using the following methods:

*   `base64` (Default): Standard Base64 encoding. Widely compatible.
*   `base85`: Ascii85 encoding. Typically more space-efficient than Base64 (approx. 4/5 the size).
*   `base91`: Base91 encoding. Often slightly more space-efficient than Base85, using a larger character set.

## Configuration

The following settings are available:

*   `attributes` (Required): A list of strings representing the attribute keys whose values should be compressed. At least one key must be provided.
*   `compression` (Optional): The compression algorithm to use. 
    *   Options: `lz4`, `zstd`, `snappy`, `gzip`, `zlib`, `deflate`, `none`.
    *   Default: `lz4`
*   `encoding` (Optional): The encoding method for the compressed bytes.
    *   Options: `base64`, `base85`, `base91`.
    *   Default: `base64`
*   `compression_params` (Optional):
    *   `level` (Optional): Configures the compression level. The interpretation and valid range depend on the `compression` algorithm:
        *   `gzip`, `zlib`, `deflate`: Valid levels typically range from `1` (BestSpeed) to `9` (BestCompression). `-1` (DefaultCompression) uses the library's default. `0` is often treated as default.
        *   `zstd`: Uses specific constants like `1` (SpeedFastest), `3` (SpeedDefault), `6` (SpeedBetterCompression), `11` (SpeedBestCompression). `-1` can also signify default. Other integer levels might be supported by the underlying library.
        *   `snappy`, `lz4`: Level configuration is not supported in this implementation; specifying a non-zero level will cause a validation error.
        *   `none`: Level is ignored.
    *   Default `level` if `compression_params` or `level` is unspecified generally depends on the chosen compression library (often a balance between speed and compression ratio).
*   `debug` (Optional): A boolean indicating whether to log original vs. compressed sizes and encoding type.
    *   Default: `false`

### Example Configuration

```yaml
processors:
  compressionprocessor:
    # Compress db.statement and http.request.body attributes
    attributes: ["db.statement", "http.request.body"]
    # Use zstd compression
    compression: zstd
    # Use Base85 encoding for slightly better space efficiency
    encoding: base85
    compression_params:
      # Use a higher compression level for zstd
      level: 11 # SpeedBestCompression
    # Enable debug logging
    debug: true

receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  otlp:
    endpoint: "example.com:4317"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [compressionprocessor] # Add processor to the pipeline
      exporters: [otlp]
```

## How to Use

1.  Include `compressionprocessor` in the `processors` section of your Collector configuration.
2.  Add `compressionprocessor` to the desired trace pipeline(s) in the `service::pipelines` section.
3.  Configure the `attributes` list and optionally the `compression` type, `encoding` type, `compression_params`, and `debug` flag.

## Decoding Attributes Manually (Example)

If you need to inspect the original value of a compressed attribute outside the Collector pipeline (e.g., during debugging or analysis), you can use standard command-line tools. The specific tools depend on the `encoding` and `compression` configuration used.

### Example: LZ4 Compression + Base64 Encoding

Assume a span has the attribute `db.statement_compressed` with the value `"BCJNGFNFTEVDVCBzb21lX2NvbHVtbnMgRlJPTSBzb21lX3RhYmxlO7AAAAA="` (this is an example, your actual value will differ).

You can decode and decompress it using `base64` and `lz4` (you might need to install `lz4` via your package manager, e.g., `brew install lz4` or `apt-get install liblz4-tool`):

```bash
# Replace with the actual attribute value
ENCODED_VALUE="BCJNGFNFTEVDVCBzb21lX2NvbHVtbnMgRlJPTSBzb21lX3RhYmxlO7AAAAA="

# Decode base64 and decompress lz4
echo "$ENCODED_VALUE" | base64 -d | lz4 -d

# Expected output for the example value above:
# SELECT some_columns FROM some_table;
```

**Note:** Adjust the commands based on the actual `encoding` (`base64`, `base85`, `base91` tools) and `compression` (`lz4`, `zstd`, `snappy`, `gzip`, `zlib`) used in your processor configuration.
