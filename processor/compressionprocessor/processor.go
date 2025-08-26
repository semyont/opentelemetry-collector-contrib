// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compressionprocessor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/ascii85"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/eknkc/basex"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// Constants to indicate processing outcome
const (
	attributeCompressed   = iota // Compression successful, replace original
	attributeKeepOriginal        // Keep original (e.g., below minLength, overhead, timeout, error)
	attributeRemove              // Remove original (e.g., empty string)
)

// Base91Encoding defines the alphabet for base91 encoding
var Base91Encoding *basex.Encoding

func init() {
	var err error
	// Standard base91 alphabet
	Base91Encoding, err = basex.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
	if err != nil {
		// This should not happen with a valid alphabet, panic on init
		panic(fmt.Sprintf("Failed to initialize base91 encoding: %v", err))
	}
}

type compressionProcessor struct {
	logger *zap.Logger
	cfg    *Config
	// targetAttributes maps original attribute keys to their compressed counterparts (e.g., "db.statement" -> "db.statement_compressed").
	targetAttributes map[string]string
	// compressFn holds the function to perform the configured compression.
	compressFn func(ctx context.Context, data []byte) ([]byte, error)
	// compressorName stores the string name of the compressor for logging.
	compressorName string
	// encodeFn holds the function to encode compressed bytes to string.
	encodeFn func([]byte) string
	// zstdEncoder is stored for potential reuse if zstd is selected.
	zstdEncoder *zstd.Encoder
	// bufferPool is used to reuse bytes.Buffer objects for compression.
	bufferPool sync.Pool
}

// Helper function to prevent index out of range
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// newCompressionProcessor creates a new processor instance.
func newCompressionProcessor(logger *zap.Logger, cfg *Config) (*compressionProcessor, error) {
	// Use default suffix if config value is empty
	suffix := cfg.CompressedSuffix
	if suffix == "" {
		suffix = DefaultCompressedSuffix
	}
	// Validation should prevent the effective suffix from being empty, but double-check
	if suffix == "" {
		return nil, errors.New("internal error: effective compressed_suffix is empty after defaulting")
	}

	// --- Add validation call here ---
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	// --- End validation call ---

	targetAttributes := make(map[string]string, len(cfg.Attributes))
	for _, attrKey := range cfg.Attributes {
		if attrKey == "" {
			// This should theoretically be caught by config validation, but double-check.
			return nil, errors.New("attribute key cannot be empty")
		}
		// Use configured suffix
		targetAttributes[attrKey] = attrKey + suffix
	}

	cp := &compressionProcessor{
		logger:           logger,
		cfg:              cfg,
		targetAttributes: targetAttributes,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}

	// Initialize compression function based on config
	if err := cp.initializeCompressor(); err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	if err := cp.initializeEncoder(); err != nil {
		return nil, fmt.Errorf("failed to initialize encoder: %w", err)
	}

	return cp, nil
}

// initializeEncoder sets up the encodeFn based on the configuration.
func (cp *compressionProcessor) initializeEncoder() error {
	encodingType := cp.cfg.Encoding
	if encodingType == "" {
		encodingType = DefaultEncoding
	}

	switch encodingType {
	case EncodingTypeBase64:
		cp.encodeFn = base64.StdEncoding.EncodeToString
	case EncodingTypeBase85:
		cp.encodeFn = func(data []byte) string {
			// Estimate size needed for base85 encoding (approx 5/4 * len)
			maxEncodedLen := ascii85.MaxEncodedLen(len(data))
			encodedBuf := make([]byte, maxEncodedLen)
			n := ascii85.Encode(encodedBuf, data)
			return string(encodedBuf[:n])
		}
	case EncodingTypeBase91:
		cp.encodeFn = Base91Encoding.Encode
	default:
		// Should be caught by validation.
		return fmt.Errorf("unsupported encoding type %q encountered during initialization", encodingType)
	}
	return nil
}

// initializeCompressor sets up the compressFn based on the configuration.
func (cp *compressionProcessor) initializeCompressor() error {
	compressionType := cp.cfg.Compression
	if compressionType == "" {
		compressionType = DefaultCompression // Use default if empty
	}

	level := cp.cfg.CompressionParams.Level
	cp.compressorName = string(compressionType)

	switch compressionType {
	case CompressionTypeNone:
		cp.compressFn = func(_ context.Context, data []byte) ([]byte, error) {
			return data, nil // No-op
		}
	case CompressionTypeLz4:
		cp.compressFn = func(ctx context.Context, data []byte) ([]byte, error) {
			buf := cp.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer cp.bufferPool.Put(buf)

			writer := lz4.NewWriter(buf)
			_, err := writer.Write(data)
			if err != nil {
				_ = writer.Close() // Attempt to close even on write error
				return nil, fmt.Errorf("lz4 write error: %w", err)
			}
			err = writer.Close()
			if err != nil {
				return nil, fmt.Errorf("lz4 close error: %w", err)
			}
			// Check context after completion
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			compressedData := make([]byte, buf.Len())
			copy(compressedData, buf.Bytes())
			return compressedData, nil
		}
	case CompressionTypeZstd:
		zstdLevel := zstd.SpeedDefault
		if level != 0 {
			zstdLevel = zstd.EncoderLevelFromZstd(level)
		}
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstdLevel))
		if err != nil {
			return fmt.Errorf("failed to create zstd writer with level %s: %w", zstdLevel.String(), err)
		}
		cp.zstdEncoder = encoder // Store for reuse
		cp.compressFn = func(ctx context.Context, data []byte) ([]byte, error) {
			// Check context before starting
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Note: EncodeAll doesn't take context. Check after.
			result := cp.zstdEncoder.EncodeAll(data, nil)
			// Check context after completion
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return result, nil
		}
	case CompressionTypeSnappy:
		cp.compressFn = func(ctx context.Context, data []byte) ([]byte, error) {
			// Check context before starting
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			// Note: Snappy Encode doesn't take context. Check after.
			result := snappy.Encode(nil, data)
			// Check context after completion
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return result, nil
		}
	case CompressionTypeGzip:
		compressLevel := gzip.DefaultCompression
		if level != 0 {
			compressLevel = level // Use specified level if not 0
		}
		cp.compressFn = func(ctx context.Context, data []byte) ([]byte, error) {
			buf := cp.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer cp.bufferPool.Put(buf)

			writer, err := gzip.NewWriterLevel(buf, compressLevel)
			if err != nil {
				return nil, fmt.Errorf("failed to create gzip writer with level %d: %w", compressLevel, err)
			}
			_, err = writer.Write(data)
			if err != nil {
				_ = writer.Close()
				return nil, fmt.Errorf("gzip write error: %w", err)
			}
			err = writer.Close()
			if err != nil {
				return nil, fmt.Errorf("gzip close error: %w", err)
			}
			// Check context after completion
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			compressedData := make([]byte, buf.Len())
			copy(compressedData, buf.Bytes())
			return compressedData, nil
		}
	case CompressionTypeZlib, CompressionTypeDeflate: // Go's zlib handles both
		compressLevel := zlib.DefaultCompression
		if level != 0 {
			compressLevel = level
		}
		cp.compressFn = func(ctx context.Context, data []byte) ([]byte, error) {
			buf := cp.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer cp.bufferPool.Put(buf)

			writer, err := zlib.NewWriterLevel(buf, compressLevel)
			if err != nil {
				return nil, fmt.Errorf("failed to create zlib/deflate writer with level %d: %w", compressLevel, err)
			}
			_, err = writer.Write(data)
			if err != nil {
				_ = writer.Close()
				return nil, fmt.Errorf("zlib/deflate write error: %w", err)
			}
			err = writer.Close()
			if err != nil {
				return nil, fmt.Errorf("zlib/deflate close error: %w", err)
			}
			// Check context after completion
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			compressedData := make([]byte, buf.Len())
			copy(compressedData, buf.Bytes())
			return compressedData, nil
		}
	default:
		// Should be caught by validation, but defend against it.
		return fmt.Errorf("unsupported compression type %q encountered during initialization", compressionType)
	}

	return nil
}

// processAttribute processes a single attribute value.
// It returns the new value (if compressed), an integer indicating the action to take, and any error.
func (cp *compressionProcessor) processAttribute(ctx context.Context, key string, value pcommon.Value) (pcommon.Value, int, error) {
	originalStr := value.Str()
	originalBytes := []byte(originalStr) // Use bytes for length comparison

	// Skip and remove if attribute value is empty
	if len(originalBytes) == 0 {
		cp.logger.Debug("Removing attribute (empty string)", zap.String("attribute_key", key))
		return pcommon.NewValueEmpty(), attributeRemove, nil // Indicate removal
	}

	// Skip ifw attribute value length is below threshold
	if len(originalBytes) < cp.cfg.MinLength {
		cp.logger.Debug("Skipping attribute (below min_length)",
			zap.String("attribute_key", key), // Log the key
			zap.Int("attribute_len", len(originalBytes)),
			zap.Int("min_length", cp.cfg.MinLength))
		return value, attributeKeepOriginal, nil // Indicate keeping original
	}

	var compressedData []byte
	var err error

	// Apply timeout if configured
	if cp.cfg.CompressionTimeout > 0 {
		timeoutCtx, cancel := context.WithTimeout(ctx, cp.cfg.CompressionTimeout)
		defer cancel()
		compressedData, err = cp.compressFn(timeoutCtx, originalBytes)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				cp.logger.Warn("Compression timed out, keeping original", zap.String("attribute_key", key), zap.Duration("timeout", cp.cfg.CompressionTimeout))
				return value, attributeKeepOriginal, nil // Keep original on timeout
			}
			// Log other compression errors but still keep original
			cp.logger.Error("Failed to compress data, keeping original", zap.String("attribute_key", key), zap.Error(err))
			return value, attributeKeepOriginal, fmt.Errorf("failed to compress data: %w", err)
		}
	} else {
		compressedData, err = cp.compressFn(ctx, originalBytes)
		if err != nil {
			// Log compression errors but still keep original
			cp.logger.Error("Failed to compress data, keeping original", zap.String("attribute_key", key), zap.Error(err))
			return value, attributeKeepOriginal, fmt.Errorf("failed to compress data: %w", err)
		}
	}

	// Encode the compressed data
	encodedStr := cp.encodeFn(compressedData)

	if cp.cfg.Debug {
		// Apply default if empty for logging purposes
		encoding := cp.cfg.Encoding
		if encoding == "" {
			encoding = DefaultEncoding
		}
		compression := cp.cfg.Compression
		if compression == "" {
			compression = DefaultCompression
		}
		cp.logger.Debug("Compressed attribute",
			zap.String("attribute_key", key), // Log the key
			zap.Int("original_size", len(originalBytes)),
			zap.Int("compressed_size", len(compressedData)),
			zap.String("encoding", string(encoding)),
			zap.String("compression", string(compression)),
			zap.String("encoded_output", encodedStr),
		)
	}

	newValue := pcommon.NewValueStr(encodedStr)
	return newValue, attributeCompressed, nil // Indicate compression success
}

// processAttributesMap iterates through a pcommon.Map, identifies attributes configured for compression,
// processes them, and updates the map accordingly.
func (cp *compressionProcessor) processAttributesMap(ctx context.Context, attrs pcommon.Map, isEvent bool) {
	logPrefix := "attribute"
	if isEvent {
		logPrefix = "event attribute"
	}

	// Use a temporary slice to store keys to remove/update later, avoiding concurrent modification issues.
	keysToProcess := make([]string, 0, attrs.Len())
	attrs.Range(func(k string, v pcommon.Value) bool {
		keysToProcess = append(keysToProcess, k)
		return true
	})

	for _, k := range keysToProcess {
		v, exists := attrs.Get(k)
		if !exists {
			continue // Should not happen if iterating keys from the map, but safety check
		}

		shouldProcess := false
		for _, attrKey := range cp.cfg.Attributes {
			if k == attrKey {
				shouldProcess = true
				break
			}
		}

		if !shouldProcess {
			continue // Next key
		}

		if v.Type() != pcommon.ValueTypeStr {
			cp.logger.Debug(fmt.Sprintf("Skipping %s (not a string)", logPrefix), zap.String("attribute_key", k), zap.String("attribute_type", v.Type().String()))
			continue // Next key
		}

		newValue, action, err := cp.processAttribute(ctx, k, v) // Pass key for logging
		if err != nil {
			// Error already logged in processAttribute, continue with next attribute
			continue
		}

		switch action {
		case attributeCompressed:
			// Apply default suffix if empty
			suffix := cp.cfg.CompressedSuffix
			if suffix == "" {
				suffix = DefaultCompressedSuffix
			}
			compressedKey := k + suffix
			attrs.PutStr(compressedKey, newValue.Str())
			attrs.Remove(k) // Remove original only if successfully compressed and smaller
		case attributeRemove:
			attrs.Remove(k) // Remove the original attribute (empty string case)
			// Logged removal in processAttribute
		case attributeKeepOriginal:
			// Do nothing, original attribute remains
			// Logged reason for keeping in processAttribute
		}
	}
}

// processEventAttribute processes attributes within a single span event.
// It now primarily checks if event processing is enabled and calls the common helper.
func (cp *compressionProcessor) processEventAttribute(ctx context.Context, attrs pcommon.Map) {
	// Skip processing event attributes if disabled
	if !cp.cfg.CompressSpanEvents {
		return
	}
	cp.processAttributesMap(ctx, attrs, true) // Call helper, indicating it's for an event
}

// processTraces applies attribute compression and encoding to incoming traces.
func (cp *compressionProcessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	rs := td.ResourceSpans()
	for i := 0; i < rs.Len(); i++ {
		scopeSpans := rs.At(i).ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				// Process span attributes
				cp.processAttributesMap(ctx, span.Attributes(), false)

				// Process span event attributes if enabled
				if cp.cfg.CompressSpanEvents {
					events := span.Events()
					for l := 0; l < events.Len(); l++ {
						event := events.At(l)
						cp.processAttributesMap(ctx, event.Attributes(), true)
					}
				}
			}
		}
	}
	return td, nil
}

// Start is invoked during service startup.
func (cp *compressionProcessor) Start(_ context.Context, _ component.Host) error {
	// No specific start logic needed for this processor
	return nil
}

// Shutdown is invoked during service shutdown.
func (cp *compressionProcessor) Shutdown(_ context.Context) error {
	// Close reusable resources like the zstd encoder if it was initialized.
	if cp.zstdEncoder != nil {
		cp.zstdEncoder.Close()
	}
	return nil
}
