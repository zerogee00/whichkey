// Package types contains shared types used across the whichkey application.
package types

import "encoding/xml"

// EnvironmentConfig holds environment-specific configuration
type EnvironmentConfig struct {
	Name          string
	Namespace     string
	ConfigMapName string
	SecretName    string
	KMSEndpoint   string
	KMSToken      string
	VaultPath     string
	VaultServer   string
	VaultKey      string
}

// MediaAnalysis represents the unified analysis results
type MediaAnalysis struct {
	MediaType           string // "HLS" or "DASH"
	KeyURI              string
	KeyID               string
	AllKeyIDs           []string // All unique key IDs (for DASH multi-key manifests)
	ClipID              string
	KeyFileSize         int64
	IVLength            int
	EncryptionMethod    string
	KeyType             string
	IsUtilityClip       bool
	ReferencedManifests []string
	HLSStreams          []HLSStreamInfo // HLS variant streams with resolution/bandwidth info
	Representations     []RepresentationInfo
	PSSHData            string
	ProData             string
	// Vault integration
	KeyExistsInVault  bool
	VaultKeyInfo      map[string]interface{}            // For single key (HLS)
	AllVaultKeyInfo   map[string]map[string]interface{} // For multiple keys (DASH): keyID -> vaultInfo
	UtilityClipSource string                            // "kubectl", "fallback", or "unknown"
	// KMS integration
	KeyExistsInKMS bool
	KMSKeyInfo     map[string]interface{}
}

// RepresentationInfo holds DASH representation metadata
type RepresentationInfo struct {
	ID        string
	Bandwidth int
	Codecs    string
	Width     int
	Height    int
	KeyID     string
}

// HLSStreamInfo holds information about an HLS variant stream
type HLSStreamInfo struct {
	Path      string
	Bandwidth int
	Width     int
	Height    int
	Codecs    string
}

// KeyDetail represents metadata about a single encryption key
type KeyDetail struct {
	KID              string
	Labels           []string
	IV               int
	EncryptionMethod string
	InVault          bool
	InKMS            bool
}

// RenditionSummary represents a rendition and its associated key
type RenditionSummary struct {
	Description string // e.g., "1080p video", "720p video", "audio"
	KeyID       string
	ClipID      string // Source clip ID for grouping
}

// ManifestResult holds the results from analyzing a single manifest
type ManifestResult struct {
	ManifestPath     string
	Analysis         *MediaAnalysis
	Error            error
	KeyDetails       map[string]KeyDetail
	Renditions       []RenditionSummary
	TotalAnalyzed    int
	TotalEncrypted   int
	TotalFairPlay    int
	TotalWidevine    int
	TotalInVault     int
	TotalInKMS       int
	TotalMismatches  int
	TotalMissingKeys int
}

// AnalysisStats holds counters from manifest analysis
type AnalysisStats struct {
	Analyzed    int
	Encrypted   int
	FairPlay    int
	Widevine    int
	InVault     int
	InKMS       int
	Mismatches  int
	MissingKeys int
}

// DASH XML structures

// DASHManifest represents the DASH MPD structure
type DASHManifest struct {
	XMLName xml.Name `xml:"MPD"`
	Periods []Period `xml:"Period"`
}

// Period represents a DASH period
type Period struct {
	ID             string          `xml:"id,attr"`
	AdaptationSets []AdaptationSet `xml:"AdaptationSet"`
}

// AdaptationSet represents a DASH adaptation set
type AdaptationSet struct {
	ID                string              `xml:"id,attr"`
	ContentType       string              `xml:"contentType,attr"`
	ContentProtection []ContentProtection `xml:"ContentProtection"`
	Representations   []Representation    `xml:"Representation"`
}

// ContentProtection represents DRM content protection info
type ContentProtection struct {
	Value       string `xml:"value,attr"`
	SchemeIDURI string `xml:"schemeIdUri,attr"`
	DefaultKID  string `xml:"default_KID,attr"`
	PSSH        string `xml:"pssh"`
	Pro         string `xml:"pro"`
}

// Representation represents a DASH representation
type Representation struct {
	ID        string `xml:"id,attr"`
	Bandwidth int    `xml:"bandwidth,attr"`
	Codecs    string `xml:"codecs,attr"`
	MimeType  string `xml:"mimeType,attr"`
	Width     int    `xml:"width,attr"`
	Height    int    `xml:"height,attr"`
}
