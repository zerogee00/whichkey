// Package interfaces defines interfaces for dependency injection and mocking.
package interfaces

import (
	"context"
	"io"

	"github.com/roddd/whichkey/internal/types"
)

// HTTPClient defines the interface for HTTP operations
type HTTPClient interface {
	Get(url string) (io.ReadCloser, error)
}

// S3Fetcher defines the interface for S3 operations
type S3Fetcher interface {
	FetchContent(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	ListManifests(ctx context.Context, bucket, prefix string, includeSubclips bool) ([]string, error)
}

// VaultClient defines the interface for Vault operations
type VaultClient interface {
	GetKeyInfo(keyID string, config types.EnvironmentConfig) (map[string]interface{}, error)
	CheckKey(keyID string, config types.EnvironmentConfig) (bool, error)
}

// KMSClient defines the interface for KMS operations
type KMSClient interface {
	CheckKeyExists(keyID string, config types.EnvironmentConfig) (bool, map[string]interface{}, error)
	GetDecryptionKey(keyID string, config types.EnvironmentConfig) ([]byte, error)
}

// K8sClient defines the interface for Kubernetes operations
type K8sClient interface {
	GetUtilityClipIDs(config types.EnvironmentConfig) ([]string, error)
	SetupContext(environment string) error
}

// ConfigProvider defines the interface for configuration
type ConfigProvider interface {
	GetEnvironment(name string) (types.EnvironmentConfig, bool)
	GetAWSProfile(bucket string) string
	GetKubectlContexts(env string) []string
	GetFallbackUtilityIDs() []string
}

// ManifestAnalyzer defines the interface for manifest analysis
type ManifestAnalyzer interface {
	AnalyzeHLS(path string, config types.EnvironmentConfig) (*types.MediaAnalysis, error)
	AnalyzeDASH(path string, config types.EnvironmentConfig) (*types.MediaAnalysis, error)
}

// OutputWriter defines the interface for output operations
type OutputWriter interface {
	PrintSummary(keyMap map[string]types.KeyDetail, renditions []types.RenditionSummary)
	CopyToClipboard(text string) error
}
