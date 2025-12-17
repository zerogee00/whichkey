package aws

import (
	"net/http"
	"os"
	"testing"
)

func TestIsURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"http URL", "http://example.com/path", true},
		{"https URL", "https://example.com/path", true},
		{"s3 URL", "s3://bucket/key", false},
		{"local path", "/local/path/file.txt", false},
		{"relative path", "relative/path/file.txt", false},
		{"empty string", "", false},
		{"ftp URL", "ftp://example.com/file", false},
		{"https with port", "https://example.com:8080/path", true},
		{"http with query", "http://example.com/path?query=1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsURL(tt.input)
			if result != tt.expected {
				t.Errorf("IsURL(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsS3URL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid s3 URL", "s3://bucket/key", true},
		{"s3 URL with path", "s3://bucket/path/to/file.mpd", true},
		{"http URL", "http://example.com/path", false},
		{"https URL", "https://example.com/path", false},
		{"local path", "/local/path/file.txt", false},
		{"empty string", "", false},
		{"s3 prefix only", "s3://", true},
		{"s3 with bucket only", "s3://mybucket", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsS3URL(tt.input)
			if result != tt.expected {
				t.Errorf("IsS3URL(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseS3URL(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedBucket string
		expectedKey    string
		expectError    bool
	}{
		{
			name:           "simple s3 URL",
			input:          "s3://mybucket/mykey",
			expectedBucket: "mybucket",
			expectedKey:    "mykey",
			expectError:    false,
		},
		{
			name:           "s3 URL with path",
			input:          "s3://bucket-name/path/to/file.mpd",
			expectedBucket: "bucket-name",
			expectedKey:    "path/to/file.mpd",
			expectError:    false,
		},
		{
			name:           "s3 URL with complex path",
			input:          "s3://nonprd-hybrik-output/fmp/clip/pluto/abc123/dash/0-end/main.mpd",
			expectedBucket: "nonprd-hybrik-output",
			expectedKey:    "fmp/clip/pluto/abc123/dash/0-end/main.mpd",
			expectError:    false,
		},
		{
			name:           "s3 URL with special characters",
			input:          "s3://my-bucket/path/with spaces/file.mpd",
			expectedBucket: "my-bucket",
			expectedKey:    "path/with spaces/file.mpd",
			expectError:    false,
		},
		{
			name:        "not s3 URL",
			input:       "http://example.com/path",
			expectError: true,
		},
		{
			name:        "missing key",
			input:       "s3://bucket-only",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "just s3 prefix",
			input:       "s3://",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, err := ParseS3URL(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseS3URL(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseS3URL(%q) unexpected error: %v", tt.input, err)
				return
			}

			if bucket != tt.expectedBucket {
				t.Errorf("ParseS3URL(%q) bucket = %q, want %q", tt.input, bucket, tt.expectedBucket)
			}
			if key != tt.expectedKey {
				t.Errorf("ParseS3URL(%q) key = %q, want %q", tt.input, key, tt.expectedKey)
			}
		})
	}
}

func TestGetProfileForBucket(t *testing.T) {
	tests := []struct {
		name     string
		bucket   string
		expected string
	}{
		{"slio bucket", "slio-media-bucket", "main-tier4"},
		{"nonprd bucket", "nonprd-hybrik-output", "nonprod-tier3"},
		{"dev bucket", "dev-media-bucket", "nonprod-tier3"},
		{"preprd bucket", "preprd-hybrik-output", "preprod-tier3"},
		{"prd bucket", "prd-hybrik-output", "main-tier4"},
		{"case insensitive", "NONPRD-BUCKET", "nonprod-tier3"},
		{"unknown bucket", "random-bucket-name", ""},
		{"empty bucket", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetProfileForBucket(tt.bucket)
			if result != tt.expected {
				t.Errorf("GetProfileForBucket(%q) = %q, want %q", tt.bucket, result, tt.expected)
			}
		})
	}
}

func TestIsSubclipPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"0-end folder", "/path/dash/0-end/main.mpd", false},
		{"0-10 subclip", "/path/dash/0-10/main.mpd", true},
		{"10-20 subclip", "/path/dash/10-20/main.mpd", true},
		{"20-30 subclip", "/path/dash/20-30/main.mpd", true},
		{"30-40 subclip", "/path/hls/30-40/master.m3u8", true},
		{"40-50 subclip", "/path/hls/40-50/master.m3u8", true},
		{"50-60 subclip", "/path/hls/50-60/master.m3u8", true},
		{"0-5 subclip", "/path/hls/0-5/master.m3u8", true},
		{"5-10 subclip", "/path/hls/5-10/master.m3u8", true},
		{"no subclip pattern", "/path/dash/output/main.mpd", false},
		{"case insensitive", "/path/DASH/0-10/main.mpd", true},
		{"empty path", "", false},
		{"root path", "/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSubclipPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSubclipPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestAutoSetProfile(t *testing.T) {
	// Save original values
	originalOverride := ProfileOverride
	originalEnv := os.Getenv("AWS_PROFILE")
	defer func() {
		ProfileOverride = originalOverride
		os.Setenv("AWS_PROFILE", originalEnv)
		ResetS3Client()
	}()

	tests := []struct {
		name            string
		s3URL           string
		initialOverride string
		expectedProfile string
	}{
		{
			name:            "nonprd bucket sets profile",
			s3URL:           "s3://nonprd-bucket/path/file.mpd",
			initialOverride: "",
			expectedProfile: "nonprod-tier3",
		},
		{
			name:            "existing override prevents change",
			s3URL:           "s3://nonprd-bucket/path/file.mpd",
			initialOverride: "custom-profile",
			expectedProfile: "custom-profile",
		},
		{
			name:            "invalid URL does not change profile",
			s3URL:           "http://example.com/path",
			initialOverride: "",
			expectedProfile: "",
		},
		{
			name:            "slio bucket sets profile",
			s3URL:           "s3://slio-bucket/path/file.mpd",
			initialOverride: "",
			expectedProfile: "main-tier4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ProfileOverride = tt.initialOverride
			os.Unsetenv("AWS_PROFILE")
			ResetS3Client()

			AutoSetProfile(tt.s3URL)

			if ProfileOverride != tt.expectedProfile {
				t.Errorf("AutoSetProfile(%q) ProfileOverride = %q, want %q",
					tt.s3URL, ProfileOverride, tt.expectedProfile)
			}
		})
	}
}

func TestResetS3Client(t *testing.T) {
	// This just verifies ResetS3Client doesn't panic
	ResetS3Client()

	// Call it multiple times
	ResetS3Client()
	ResetS3Client()

	// Verify we can still get a client (may fail if no AWS creds, but shouldn't panic)
	_ = globalS3Client
}

func TestGlobalHTTPClient(t *testing.T) {
	// Verify global HTTP client is configured
	if GlobalHTTPClient == nil {
		t.Error("GlobalHTTPClient is nil")
	}

	if GlobalHTTPClient.Timeout == 0 {
		t.Error("GlobalHTTPClient timeout is not set")
	}

	transport, ok := GlobalHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Error("GlobalHTTPClient transport is not *http.Transport")
		return
	}

	if transport.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns = %d, want 100", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 100 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 100", transport.MaxIdleConnsPerHost)
	}
}

func TestVerbosityVariable(t *testing.T) {
	original := Verbosity
	defer func() { Verbosity = original }()

	Verbosity = 0
	if Verbosity != 0 {
		t.Errorf("Verbosity = %d, want 0", Verbosity)
	}

	Verbosity = 2
	if Verbosity != 2 {
		t.Errorf("Verbosity = %d, want 2", Verbosity)
	}
}
