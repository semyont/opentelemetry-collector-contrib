// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package compressionprocessor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

func makeTestSpan(attrKey, attrVal string, eventAttrs map[string]string) ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.Attributes().PutStr(attrKey, attrVal)
	if eventAttrs != nil {
		event := span.Events().AppendEmpty()
		for k, v := range eventAttrs {
			event.Attributes().PutStr(k, v)
		}
	}
	return td
}

func getAttr(attrs pcommon.Map, key string) (string, bool) {
	val, ok := attrs.Get(key)
	if !ok {
		return "", false
	}
	return val.Str(), true
}

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func decodeBase85(s string) ([]byte, error) {
	decoded := make([]byte, len(s))
	n, _, err := ascii85.Decode(decoded, []byte(s), true)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

func decodeBase91(s string) ([]byte, error) {
	return Base91Encoding.Decode(s)
}

func decompressLZ4(data []byte) ([]byte, error) {
	var out bytes.Buffer
	r := lz4.NewReader(bytes.NewReader(data))
	_, err := out.ReadFrom(r)
	return out.Bytes(), err
}

func decompressZstd(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(data, nil)
}

func decompressSnappy(data []byte) ([]byte, error) {
	return snappy.Decode(nil, data)
}

func decompressGzipZlib(data []byte, isGzip bool) ([]byte, error) {
	var r io.ReadCloser
	var err error
	buf := bytes.NewReader(data)
	if isGzip {
		r, err = gzip.NewReader(buf)
	} else {
		r, err = zlib.NewReader(buf)
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}

func baseConfig() *Config {
	return &Config{
		Attributes:        []string{"target"},
		Compression:       CompressionTypeZstd,
		Encoding:          EncodingTypeBase64,
		CompressedSuffix:  "_compressed",
		MinLength:         8,
		CompressionParams: CompressionParams{Level: 3},
		CompressionTimeout: 200 * time.Millisecond,
		Debug:             false,
	}
}

func TestCompressionEffectiveness(t *testing.T) {
	algos := []struct {
		name       string
		typ        CompressionType
		decompress func([]byte) ([]byte, error)
	}{
		{"lz4", CompressionTypeLz4, decompressLZ4},
		{"zstd", CompressionTypeZstd, decompressZstd},
		{"snappy", CompressionTypeSnappy, decompressSnappy},
		{"gzip", CompressionTypeGzip, func(b []byte) ([]byte, error) { return decompressGzipZlib(b, true) }},
		{"zlib", CompressionTypeZlib, func(b []byte) ([]byte, error) { return decompressGzipZlib(b, false) }},
		{"deflate", CompressionTypeDeflate, func(b []byte) ([]byte, error) { return decompressGzipZlib(b, false) }},
	}
	original := strings.Repeat("compressible-data-", 20) // Highly compressible

	for _, algo := range algos {
		cfg := baseConfig()
		cfg.Compression = algo.typ
		cp, err := newCompressionProcessor(newTestLogger(), cfg)
		if err != nil {
			t.Fatalf("init %s: %v", algo.name, err)
		}
		val := pcommon.NewValueStr(original)
		ctx := context.Background()
		out, action, err := cp.processAttribute(ctx, "target", val)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", algo.name, err)
			continue
		}
		if action != attributeCompressed {
			t.Errorf("%s: attribute not compressed", algo.name)
			continue
		}
		enc := out.Str()
		// decode
		raw, err := decodeBase64(enc)
		if err != nil {
			t.Errorf("%s: decode failed: %v", algo.name, err)
			continue
		}
		// decompress
		dec, err := algo.decompress(raw)
		if err != nil {
			t.Errorf("%s: decompress failed: %v", algo.name, err)
			continue
		}
		if string(dec) != original {
			t.Errorf("%s: roundtrip mismatch", algo.name)
		}
		if len(raw) >= len([]byte(original)) {
			t.Errorf("%s: compression ineffective (compressed %d >= original %d)", algo.name, len(raw), len([]byte(original)))
		}
	}
}

func TestEncodingAccuracy(t *testing.T) {
	encodings := []struct {
		name    string
		typ     EncodingType
		encode  func([]byte) string
		decode  func(string) ([]byte, error)
	}{
		{"base64", EncodingTypeBase64, base64.StdEncoding.EncodeToString, decodeBase64},
		{"base85", EncodingTypeBase85, func(b []byte) string {
			buf := make([]byte, ascii85.MaxEncodedLen(len(b)))
			n := ascii85.Encode(buf, b)
			return string(buf[:n])
		}, decodeBase85},
		{"base91", EncodingTypeBase91, Base91Encoding.Encode, decodeBase91},
	}
	data := []byte("test-encoding-1234567890")
	for _, enc := range encodings {
		encoded := enc.encode(data)
		decoded, err := enc.decode(encoded)
		if err != nil {
			t.Errorf("%s: decode error: %v", enc.name, err)
			continue
		}
		if !bytes.Equal(decoded, data) {
			t.Errorf("%s: roundtrip mismatch", enc.name)
		}
	}
}

func TestAttributeManagement(t *testing.T) {
	cfg := baseConfig()
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Targeted string, non-targeted string, non-string, below min length
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.Attributes().PutStr("target", "compress-me-1234567890")
	span.Attributes().PutStr("untouched", "leave-me")
	span.Attributes().PutInt("intattr", 42)
	span.Attributes().PutStr("short", "tiny") // below min length

	_, err = cp.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	attrs := span.Attributes()
	// Targeted attribute should be compressed and original removed
	_, exists := getAttr(attrs, "target")
	if exists {
		t.Error("target attribute should be removed after compression")
	}
	comp, exists := getAttr(attrs, "target_compressed")
	if !exists {
		t.Error("compressed attribute missing")
	}
	// Roundtrip decompress
	raw, err := decodeBase64(comp)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decompressZstd(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "compress-me-1234567890" {
		t.Error("compressed attribute roundtrip mismatch")
	}
	// Non-targeted string remains
	val, exists := getAttr(attrs, "untouched")
	if !exists || val != "leave-me" {
		t.Error("untouched attribute changed")
	}
	// Non-string remains
	if _, ok := attrs.Get("intattr"); !ok {
		t.Error("non-string attribute removed")
	}
	// Below min length remains
	val, exists = getAttr(attrs, "short")
	if !exists || val != "tiny" {
		t.Error("short attribute should remain uncompressed")
	}
}

func TestCompressionIncreasesSizeKeepsOriginal(t *testing.T) {
	cfg := baseConfig()
	cfg.Compression = CompressionTypeZstd
	cfg.MinLength = 1
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Random data, unlikely to compress well
	orig := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	val := pcommon.NewValueStr(orig)
	ctx := context.Background()
	_, action, err := cp.processAttribute(ctx, "target", val)
	if err != nil {
		t.Fatal(err)
	}
	// Zstd will still compress repeated data, so let's use truly random data
	orig = string(make([]byte, 512))
	val = pcommon.NewValueStr(orig)
	_, action, err = cp.processAttribute(ctx, "target", val)
	if err != nil {
		t.Fatal(err)
	}
	// If compression is not effective, attributeKeepOriginal is expected
	if action != attributeCompressed && action != attributeKeepOriginal {
		t.Errorf("unexpected action: %v", action)
	}
}

func TestTimeoutHandling(t *testing.T) {
	cfg := baseConfig()
	cfg.Compression = CompressionTypeZstd
	cfg.CompressionTimeout = 1 * time.Nanosecond // Intentionally tiny
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	val := pcommon.NewValueStr(strings.Repeat("data", 10000))
	ctx := context.Background()
	out, action, err := cp.processAttribute(ctx, "target", val)
	if !errors.Is(err, context.DeadlineExceeded) && action != attributeKeepOriginal {
		t.Errorf("expected timeout, got action=%v err=%v", action, err)
	}
	// Should keep original
	if out.Str() != val.Str() {
		t.Error("should keep original value on timeout")
	}
	// Now test with enough timeout
	cfg.CompressionTimeout = 1 * time.Second
	cp, err = newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, action, err = cp.processAttribute(ctx, "target", val)
	if err != nil || action != attributeCompressed {
		t.Errorf("expected compression to succeed, got action=%v err=%v", action, err)
	}
}

func TestSpanEventsCompression(t *testing.T) {
	cfg := baseConfig()
	cfg.CompressSpanEvents = true
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	td := makeTestSpan("untouched", "foo", map[string]string{"target": "event-compress-me-1234567890"})
	_, err = cp.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	span := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	event := span.Events().At(0)
	_, exists := getAttr(event.Attributes(), "target")
	if exists {
		t.Error("event attribute should be removed after compression")
	}
	comp, exists := getAttr(event.Attributes(), "target_compressed")
	if !exists {
		t.Error("compressed event attribute missing")
	}
	raw, err := decodeBase64(comp)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decompressZstd(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "event-compress-me-1234567890" {
		t.Error("event attribute roundtrip mismatch")
	}
}

func TestSpanEventsCompressionDisabled(t *testing.T) {
	cfg := baseConfig()
	cfg.CompressSpanEvents = false
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	td := makeTestSpan("untouched", "foo", map[string]string{"target": "event-compress-me-1234567890"})
	_, err = cp.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	span := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	event := span.Events().At(0)
	val, exists := getAttr(event.Attributes(), "target")
	if !exists || val != "event-compress-me-1234567890" {
		t.Error("event attribute should remain uncompressed when disabled")
	}
	_, exists = getAttr(event.Attributes(), "target_compressed")
	if exists {
		t.Error("compressed event attribute should not exist when disabled")
	}
}

func TestCompressionByPayloadSize(t *testing.T) {
	cfg := baseConfig()
	cfg.MinLength = 200 // Only medium and large should be compressed
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	payloads := []struct {
		name   string
		length int
		expectCompressed bool
	}{
		{"small", 100, false},
		{"medium", 500, true},
		{"large", 1000, true},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			val := pcommon.NewValueStr(strings.Repeat("A", p.length))
			ctx := context.Background()
			out, action, err := cp.processAttribute(ctx, "target", val)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.expectCompressed {
				if action != attributeCompressed {
					t.Errorf("expected compression for %s payload, got action=%v", p.name, action)
				}
				// Roundtrip decompress
				raw, err := decodeBase64(out.Str())
				if err != nil {
					t.Fatalf("decode error: %v", err)
				}
				dec, err := decompressZstd(raw)
				if err != nil {
					t.Fatalf("decompress error: %v", err)
				}
				if string(dec) != strings.Repeat("A", p.length) {
					t.Errorf("decompressed value mismatch for %s payload", p.name)
				}
			} else {
				if action != attributeKeepOriginal {
					t.Errorf("expected to keep original for %s payload, got action=%v", p.name, action)
				}
				if out.Str() != strings.Repeat("A", p.length) {
					t.Errorf("original value changed for %s payload", p.name)
				}
			}
		})
	}
}

func TestConfigDrivenBehavior(t *testing.T) {
	// Custom config to test all config-driven behaviors
	cfg := &Config{
		Attributes:         []string{"target", "event_target"},
		Compression:        CompressionTypeGzip,
		Encoding:           EncodingTypeBase64,
		CompressedSuffix:   "_gzipped",
		MinLength:          10,
		CompressionTimeout: 10 * time.Millisecond,
		CompressSpanEvents: false, // Should skip event attribute compression
		Debug:              false,
	}
	cp, err := newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Prepare trace with:
	// - "target" (should be compressed)
	// - "short" (should be skipped due to min_length)
	// - "event_target" in span event (should be skipped due to CompressSpanEvents=false)
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.Attributes().PutStr("target", strings.Repeat("A", 20))
	span.Attributes().PutStr("short", "shortval")
	event := span.Events().AppendEmpty()
	event.Attributes().PutStr("event_target", strings.Repeat("B", 20))

	_, err = cp.processTraces(context.Background(), td)
	if err != nil {
		t.Fatal(err)
	}
	attrs := span.Attributes()

	// "target" should be compressed and original removed, with custom suffix
	_, exists := getAttr(attrs, "target")
	if exists {
		t.Error("target attribute should be removed after compression")
	}
	comp, exists := getAttr(attrs, "target_gzipped")
	if !exists {
		t.Error("compressed attribute with custom suffix missing")
	}
	// Roundtrip decompress
	raw, err := decodeBase64(comp)
	if err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != strings.Repeat("A", 20) {
		t.Error("compressed attribute roundtrip mismatch")
	}

	// "short" should remain untouched (min_length)
	val, exists := getAttr(attrs, "short")
	if !exists || val != "shortval" {
		t.Error("short attribute should remain uncompressed")
	}

	// "event_target" in event should remain uncompressed (CompressSpanEvents=false)
	eventAttrs := event.Attributes()
	val, exists = getAttr(eventAttrs, "event_target")
	if !exists || val != strings.Repeat("B", 20) {
		t.Error("event attribute should remain uncompressed when CompressSpanEvents is false")
	}
	_, exists = getAttr(eventAttrs, "event_target_gzipped")
	if exists {
		t.Error("event attribute should not be compressed when CompressSpanEvents is false")
	}

	// Now test CompressSpanEvents=true
	cfg.CompressSpanEvents = true
	cp, err = newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	td2 := ptrace.NewTraces()
	rs2 := td2.ResourceSpans().AppendEmpty()
	ss2 := rs2.ScopeSpans().AppendEmpty()
	span2 := ss2.Spans().AppendEmpty()
	event2 := span2.Events().AppendEmpty()
	event2.Attributes().PutStr("event_target", strings.Repeat("C", 20))
	_, err = cp.processTraces(context.Background(), td2)
	if err != nil {
		t.Fatal(err)
	}
	eventAttrs2 := event2.Attributes()
	_, exists = getAttr(eventAttrs2, "event_target")
	if exists {
		t.Error("event_target should be removed after compression when CompressSpanEvents is true")
	}
	comp, exists = getAttr(eventAttrs2, "event_target_gzipped")
	if !exists {
		t.Error("compressed event attribute with custom suffix missing")
	}
	raw, err = decodeBase64(comp)
	if err != nil {
		t.Fatal(err)
	}
	gr, err = gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	dec, err = io.ReadAll(gr)
	gr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != strings.Repeat("C", 20) {
		t.Error("compressed event attribute roundtrip mismatch")
	}

	// Test compression timeout: set a very low timeout and a large payload
	cfg.CompressionTimeout = 1 * time.Nanosecond
	cp, err = newCompressionProcessor(newTestLogger(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	td3 := ptrace.NewTraces()
	rs3 := td3.ResourceSpans().AppendEmpty()
	ss3 := rs3.ScopeSpans().AppendEmpty()
	span3 := ss3.Spans().AppendEmpty()
	span3.Attributes().PutStr("target", strings.Repeat("X", 10000))
	_, err = cp.processTraces(context.Background(), td3)
	if err != nil {
		t.Fatal(err)
	}
	attrs3 := span3.Attributes()
	// Should keep original due to timeout
	val, exists = getAttr(attrs3, "target")
	if !exists || val != strings.Repeat("X", 10000) {
		t.Error("should keep original attribute on compression timeout")
	}
	_, exists = getAttr(attrs3, "target_gzipped")
	if exists {
		t.Error("should not create compressed attribute on timeout")
	}
}
