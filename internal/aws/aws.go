// Package aws provides AWS S3 client and configuration utilities.
package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/roddd/whichkey/internal/config"
)

// GlobalHTTPClient with connection pooling for concurrent requests
var GlobalHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Global S3 client (initialized on first use)
var (
	globalS3Client *s3.Client
	s3ClientOnce   sync.Once
	s3ClientErr    error
)

// ProfileOverride holds the AWS profile override (set via flag)
var ProfileOverride string

// Verbosity level for logging
var Verbosity int

// IsURL checks if the given path is a URL
func IsURL(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// IsS3URL checks if the given path is an S3 URL
func IsS3URL(path string) bool {
	return strings.HasPrefix(path, "s3://")
}

// FetchURLContent fetches content from a URL and returns a reader
func FetchURLContent(url string) (io.Reader, error) {
	resp, err := GlobalHTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// ParseS3URL parses an S3 URL into bucket and key
func ParseS3URL(s3URL string) (bucket, key string, err error) {
	if !strings.HasPrefix(s3URL, "s3://") {
		return "", "", fmt.Errorf("invalid S3 URL format: %s", s3URL)
	}

	// Remove s3:// prefix
	path := strings.TrimPrefix(s3URL, "s3://")

	// Split into bucket and key
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid S3 URL format: must be s3://bucket/key")
	}

	return parts[0], parts[1], nil
}

// GetProfileForBucket determines the appropriate AWS profile based on bucket name
func GetProfileForBucket(bucket string) string {
	cfg := config.GetConfig()
	return cfg.GetAWSProfile(bucket)
}

// AutoSetProfile sets the AWS profile based on the S3 URL if not already set
func AutoSetProfile(s3URL string) {
	// Don't override if user explicitly specified a profile via flag
	if ProfileOverride != "" {
		return
	}

	// Parse bucket from URL
	bucket, _, err := ParseS3URL(s3URL)
	if err != nil {
		return
	}

	// Get appropriate profile for this bucket
	profile := GetProfileForBucket(bucket)
	if profile != "" {
		if Verbosity >= 1 {
			fmt.Printf("🔐 Auto-detected AWS profile: %s (based on bucket: %s)\n", profile, bucket)
		}
		// Set the global override so GetConfig uses it
		ProfileOverride = profile
		// Also set env var for any subprocesses
		os.Setenv("AWS_PROFILE", profile)
		// Reset the S3 client so it picks up the new profile
		ResetS3Client()
	}
}

// ResetS3Client resets the S3 client singleton so it picks up new configuration
func ResetS3Client() {
	s3ClientOnce = sync.Once{}
	globalS3Client = nil
	s3ClientErr = nil
}

// GetS3Client returns a shared S3 client (initialized once)
func GetS3Client() (*s3.Client, error) {
	s3ClientOnce.Do(func() {
		cfg, err := GetConfig()
		if err != nil {
			s3ClientErr = err
			return
		}
		// Create S3 client with custom HTTP client for higher concurrency
		globalS3Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.HTTPClient = GlobalHTTPClient
		})
	})
	return globalS3Client, s3ClientErr
}

// GetConfig loads AWS configuration respecting AWS_PROFILE and with shorter timeouts
func GetConfig() (aws.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Load config with options to handle profiles correctly
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion("us-east-1"), // Default region
		awsconfig.WithSharedConfigFiles([]string{
			filepath.Join(os.Getenv("HOME"), ".aws", "config"),
		}),
		awsconfig.WithSharedCredentialsFiles([]string{
			filepath.Join(os.Getenv("HOME"), ".aws", "credentials"),
		}),
	}

	// Determine profile to use (flag override > env var)
	profile := ProfileOverride
	if profile == "" {
		profile = os.Getenv("AWS_PROFILE")
	}
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}

	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
		if Verbosity >= 2 {
			fmt.Printf("🔐 Using AWS profile: %s\n", profile)
		}
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return cfg, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return cfg, nil
}

// FetchS3Content fetches content from an S3 URL using AWS SDK
func FetchS3Content(s3URL string) (io.Reader, error) {
	// Parse S3 URL
	bucket, key, err := ParseS3URL(s3URL)
	if err != nil {
		return nil, err
	}

	// Get shared S3 client
	client, err := GetS3Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 client: %w (make sure AWS credentials are configured)", err)
	}

	ctx := context.Background()

	// Get object from S3
	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch S3 object s3://%s/%s: %w", bucket, key, err)
	}
	defer result.Body.Close()

	// Read the entire body into memory
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, result.Body); err != nil {
		return nil, fmt.Errorf("failed to read S3 object body: %w", err)
	}

	return bytes.NewReader(buf.Bytes()), nil
}

// ListS3Manifests lists manifest files in an S3 path
func ListS3Manifests(s3URL string, includeSubclips bool) ([]string, error) {
	// Parse S3 URL
	bucket, prefix, err := ParseS3URL(s3URL)
	if err != nil {
		return nil, err
	}

	// Ensure prefix ends with / for folder listing
	if !strings.HasSuffix(prefix, "/") && !strings.Contains(prefix, ".") {
		prefix = prefix + "/"
	}

	// Get shared S3 client
	client, err := GetS3Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 client: %w", err)
	}

	ctx := context.Background()

	var manifests []string
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: &bucket,
		Prefix: &prefix,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := *obj.Key
			keyLower := strings.ToLower(key)

			// Skip subclip folders if not included
			if !includeSubclips && isSubclipPath(key) {
				continue
			}

			// Check for manifest files
			if strings.HasSuffix(keyLower, ".mpd") || strings.HasSuffix(keyLower, ".m3u8") {
				manifests = append(manifests, fmt.Sprintf("s3://%s/%s", bucket, key))
			}
		}
	}

	return manifests, nil
}

// isSubclipPath checks if a path is a subclip folder (not 0-end)
func isSubclipPath(path string) bool {
	pathLower := strings.ToLower(path)

	// List of subclip patterns to exclude
	subclipPatterns := []string{
		"/0-10/", "/10-20/", "/20-30/", "/30-40/", "/40-50/",
		"/50-60/", "/60-70/", "/70-80/", "/80-90/", "/90-100/",
		"/0-5/", "/5-10/", "/10-15/", "/15-20/", "/20-25/",
	}

	for _, pattern := range subclipPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	return false
}
