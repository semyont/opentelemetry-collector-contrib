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
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/component"
)

// CompressionType defines the available compression algorithms.
type CompressionType string

// EncodingType defines the available encoding methods for compressed data.
type EncodingType string

const (
	// Compression Types
	CompressionTypeGzip    CompressionType = "gzip"
	CompressionTypeZlib    CompressionType = "zlib"
	CompressionTypeDeflate CompressionType = "deflate" // Typically uses zlib format
	CompressionTypeSnappy  CompressionType = "snappy"
	CompressionTypeZstd    CompressionType = "zstd"
	CompressionTypeLz4     CompressionType = "lz4"
	CompressionTypeNone    CompressionType = "none" // Explicitly disable compression

	// Encoding Types
	EncodingTypeBase64 EncodingType = "base64" // Standard Base64
	EncodingTypeBase85 EncodingType = "base85" // Ascii85
	EncodingTypeBase91 EncodingType = "base91" // Base91 encoding (custom implementation needed)

	// Defaults
	DefaultCompression      = CompressionTypeZstd
	DefaultEncoding         = EncodingTypeBase64
	DefaultMinLength        = 1024                  // Default minimum length in bytes to trigger compression
	DefaultCompressedSuffix = "_compressed"         // Suffix for compressed attributes
	DefaultTimeout          = 50 * time.Millisecond // Default timeout for a single compression operation

	// Compression Levels (example values, specific meaning depends on compressor)
	LevelDefault          = 0 // Compressor's default level
	LevelZstdSpeedDefault = 1 // zstd default speed level
)

// CompressionParams holds parameters specific to the chosen compression algorithm.
type CompressionParams struct {
	// Level specifies the compression level. Interpretation depends on the algorithm.
	// 0 usually means default. Higher values might mean more compression but slower speed.
	Level int `mapstructure:"level"`
}

// Config defines the configuration for the compression processor.
type Config struct {
	// Attributes specifies the list of attribute keys whose string values should be compressed.
	// Supports span attributes and span event attributes (if CompressSpanEvents is true).
	Attributes []string `mapstructure:"attributes"`

	// Compression specifies the compression algorithm to use.
	// Options: "gzip", "zlib", "deflate", "snappy", "zstd", "lz4", "none".
	// Default: "zstd".
	Compression CompressionType `mapstructure:"compression"`

	// Encoding specifies how the compressed byte array should be encoded into a string.
	// Options: "base64", "base85", "base91".
	// Default: "base64".
	Encoding EncodingType `mapstructure:"encoding"`

	// CompressionParams allows setting algorithm-specific parameters like compression level.
	CompressionParams CompressionParams `mapstructure:"compression_params"`

	// MinLength specifies the minimum length (in bytes) of a string attribute value
	// required to trigger compression. Attributes shorter than this will be skipped.
	// Set to 0 to attempt compression regardless of length (overhead check still applies).
	// Default: 1024.
	MinLength int `mapstructure:"min_length"`

	// CompressedSuffix is the suffix appended to the original attribute key to form the
	// key for the new compressed attribute. The original attribute is removed if compression is successful.
	// Default: "_compressed".
	CompressedSuffix string `mapstructure:"compressed_suffix"`

	// CompressSpanEvents indicates whether to also process attributes within span events.
	// If true, attributes listed in `Attributes` found within span events will also be compressed.
	// Default: false.
	CompressSpanEvents bool `mapstructure:"compress_span_events"`

	// CompressionTimeout specifies the maximum time allowed for compressing a single attribute value.
	// If the timeout is exceeded, the original attribute is kept, and a warning is logged.
	// Set to 0 to disable the timeout.
	// Default: 50ms.
	CompressionTimeout time.Duration `mapstructure:"compression_timeout"`

	// Debug enables more verbose logging, including details about skipped attributes and compression results.
	// Default: false.
	Debug bool `mapstructure:"debug"`
}

// Validate checks if the configuration is valid.
func (cfg *Config) Validate() error {
	if len(cfg.Attributes) == 0 {
		return errors.New("at least one attribute key must be specified")
	}
	for _, key := range cfg.Attributes {
		if key == "" {
			// Ensure this matches the test expectation
			return errors.New("attribute key cannot be empty")
		}
	}

	switch cfg.Compression {
	case CompressionTypeGzip, CompressionTypeZlib, CompressionTypeDeflate, CompressionTypeSnappy, CompressionTypeZstd, CompressionTypeLz4, CompressionTypeNone, "":
		// Valid or default
	default:
		return fmt.Errorf("unsupported compression type: %s", cfg.Compression)
	}

	switch cfg.Encoding {
	case EncodingTypeBase64, EncodingTypeBase85, EncodingTypeBase91, "":
		// Valid or default
	default:
		return fmt.Errorf("unsupported encoding type: %s", cfg.Encoding)
	}

	if cfg.MinLength < 0 {
		return fmt.Errorf("min_length must be non-negative")
	}

	// Check for negative CompressionTimeout
	if cfg.CompressionTimeout < 0 {
		return errors.New("compression_timeout must be non-negative")
	}

	return nil
}

// createDefaultConfig creates the default configuration for the processor.
func createDefaultConfig() component.Config {
	return &Config{
		Compression:        DefaultCompression,
		Encoding:           DefaultEncoding,
		MinLength:          DefaultMinLength,
		CompressedSuffix:   DefaultCompressedSuffix,
		CompressSpanEvents: false,
		CompressionTimeout: DefaultTimeout,
		Debug:              false,
		// Attributes must be set by the user
	}
}
