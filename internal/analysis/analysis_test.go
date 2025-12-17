package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/roddd/whichkey/internal/types"
)

func TestVerbosityVariable(t *testing.T) {
	original := Verbosity
	defer func() { Verbosity = original }()

	Verbosity = 0
	if Verbosity != 0 {
		t.Errorf("Verbosity = %d, want 0", Verbosity)
	}

	Verbosity = 1
	if Verbosity != 1 {
		t.Errorf("Verbosity = %d, want 1", Verbosity)
	}

	Verbosity = 2
	if Verbosity != 2 {
		t.Errorf("Verbosity = %d, want 2", Verbosity)
	}
}

func TestParseKeyURI(t *testing.T) {
	tests := []struct {
		name          string
		uri           string
		expectedKeyID string
		expectedClip  string
	}{
		{
			name:          "standard key URI with key ID only",
			uri:           "skd://service-video-kms-use1-1.nonprd.pluto.tv/00000000-654b-bc98-c034-dae1f16995de",
			expectedKeyID: "00000000-654b-bc98-c034-dae1f16995de",
			expectedClip:  "",
		},
		{
			name:          "key URI with key ID and clip UUID",
			uri:           "skd://service.example.com/12345678-aaaa-bbbb-cccc-ddddeeeeeeee/00000000-1234-5678-9abc-def012345678",
			expectedKeyID: "00000000-1234-5678-9abc-def012345678",
			expectedClip:  "12345678-aaaa-bbbb-cccc-ddddeeeeeeee",
		},
		{
			name:          "key URI with hex clip ID in path",
			uri:           "https://example.com/key/622721e908d75d0007f44311/key.bin",
			expectedKeyID: "",
			expectedClip:  "622721e908d75d0007f44311",
		},
		{
			name:          "empty URI",
			uri:           "",
			expectedKeyID: "",
			expectedClip:  "",
		},
		{
			name:          "URI with multiple UUIDs - key ID and clip ID",
			uri:           "skd://host/a1234567-aaaa-bbbb-cccc-ddddeeeeeeee/00000000-aaaa-bbbb-cccc-111111111111",
			expectedKeyID: "00000000-aaaa-bbbb-cccc-111111111111",
			expectedClip:  "a1234567-aaaa-bbbb-cccc-ddddeeeeeeee",
		},
		{
			name:          "URI with no UUIDs",
			uri:           "https://example.com/path/to/key",
			expectedKeyID: "",
			expectedClip:  "",
		},
		{
			name:          "URI with only non-key UUIDs uses last as keyID",
			uri:           "https://example.com/a1234567-bbbb-cccc-dddd-eeeeeeeeeeee",
			expectedKeyID: "a1234567-bbbb-cccc-dddd-eeeeeeeeeeee",
			expectedClip:  "a1234567-bbbb-cccc-dddd-eeeeeeeeeeee",
		},
		{
			name:          "URI with uppercase UUIDs",
			uri:           "skd://host/00000000-AAAA-BBBB-CCCC-111111111111",
			expectedKeyID: "00000000-AAAA-BBBB-CCCC-111111111111",
			expectedClip:  "",
		},
		{
			name:          "URI with mixed case UUIDs",
			uri:           "skd://host/00000000-AaAa-BbBb-CcCc-111111111111",
			expectedKeyID: "00000000-AaAa-BbBb-CcCc-111111111111",
			expectedClip:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, clipID := ParseKeyURI(tt.uri)

			if keyID != tt.expectedKeyID {
				t.Errorf("ParseKeyURI(%q) keyID = %q, want %q", tt.uri, keyID, tt.expectedKeyID)
			}
			if clipID != tt.expectedClip {
				t.Errorf("ParseKeyURI(%q) clipID = %q, want %q", tt.uri, clipID, tt.expectedClip)
			}
		})
	}
}

func TestExtractClipIDFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "S3 path with clip folder",
			path:     "s3://bucket/fmp/clip/pluto/622721e908d75d0007f44311/dash/0-end/main.mpd",
			expected: "622721e908d75d0007f44311",
		},
		{
			name:     "HTTP URL with clip folder",
			path:     "https://cdn.example.com/fmp/clip/pluto/56244db86ffa1d5f58b77376/hls/master.m3u8",
			expected: "56244db86ffa1d5f58b77376",
		},
		{
			name:     "path with underscore suffix",
			path:     "/content/clip/622721e908d75d0007f44311_720p/manifest.mpd",
			expected: "622721e908d75d0007f44311",
		},
		{
			name:     "path with UUID format clip ID",
			path:     "/media/content/a1b2c3d4-e5f6-7890-abcd-ef1234567890/video.mpd",
			expected: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:     "path with 00000000 UUID (key ID, not clip)",
			path:     "/key/00000000-1234-5678-9abc-def012345678/stream.m3u8",
			expected: "unknown",
		},
		{
			name:     "path without recognizable clip ID",
			path:     "/media/stream/video.mpd",
			expected: "unknown",
		},
		{
			name:     "path with hex ID in different position",
			path:     "/output/56c2dcd6222d7c7767c715dd/dash/main.mpd",
			expected: "56c2dcd6222d7c7767c715dd",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "unknown",
		},
		{
			name:     "path with short hex (less than 24 chars)",
			path:     "/content/clip/abc123/dash/main.mpd",
			expected: "unknown",
		},
		{
			name:     "path with clip folder and 25 char hex",
			path:     "/content/clip/622721e908d75d0007f443111/dash/main.mpd",
			expected: "622721e908d75d0007f443111",
		},
		{
			name:     "path with multiple valid hex IDs",
			path:     "/content/clip/622721e908d75d0007f44311/sub/56244db86ffa1d5f58b77376/main.mpd",
			expected: "622721e908d75d0007f44311",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractClipIDFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("ExtractClipIDFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestExtractHLSRenditionDescription(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "avc1 codec file",
			path:     "/path/to/avc1_720p.m3u8",
			expected: "H.264 stream",
		},
		{
			name:     "h264 codec file",
			path:     "/path/to/h264_stream.m3u8",
			expected: "H.264 stream",
		},
		{
			name:     "hevc codec file",
			path:     "/path/to/hevc_4k.m3u8",
			expected: "HEVC stream",
		},
		{
			name:     "hvc1 codec file",
			path:     "/path/to/hvc1_stream.m3u8",
			expected: "HEVC stream",
		},
		{
			name:     "hev1 codec file",
			path:     "/path/to/hev1_stream.m3u8",
			expected: "HEVC stream",
		},
		{
			name:     "audio mp4a file",
			path:     "/path/to/mp4a_audio.m3u8",
			expected: "AAC stream",
		},
		{
			name:     "aac audio file",
			path:     "/path/to/aac_stereo.m3u8",
			expected: "AAC stream",
		},
		{
			name:     "ac-3 audio file",
			path:     "/path/to/ac-3_surround.m3u8",
			expected: "AC-3 stream",
		},
		{
			name:     "ec-3 audio file",
			path:     "/path/to/ec-3_atmos.m3u8",
			expected: "E-AC-3 stream",
		},
		{
			name:     "2160p resolution file",
			path:     "/path/to/2160p_uhd.m3u8",
			expected: "4K video",
		},
		{
			name:     "1080p resolution file",
			path:     "/path/to/1080p_video.m3u8",
			expected: "HD 1080p video",
		},
		{
			name:     "720p resolution file",
			path:     "/path/to/720p.m3u8",
			expected: "HD 720p video",
		},
		{
			name:     "576p resolution file",
			path:     "/path/to/576p_pal.m3u8",
			expected: "SD 576p video",
		},
		{
			name:     "480p resolution file",
			path:     "/path/to/480p_sd.m3u8",
			expected: "SD 480p video",
		},
		{
			name:     "360p resolution file",
			path:     "/path/to/360p_low.m3u8",
			expected: "SD 360p video",
		},
		{
			name:     "240p resolution file",
			path:     "/path/to/240p_mobile.m3u8",
			expected: "SD 240p video",
		},
		{
			name:     "audio keyword file",
			path:     "/path/to/audio_eng.m3u8",
			expected: "Audio stream",
		},
		{
			name:     "AUDIO uppercase keyword",
			path:     "/path/to/AUDIO_track.m3u8",
			expected: "Audio stream",
		},
		{
			name:     "unknown format",
			path:     "/path/to/variant_3.m3u8",
			expected: "variant_3",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "no extension",
			path:     "/path/to/stream",
			expected: "stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractHLSRenditionDescription(tt.path)
			if result != tt.expected {
				t.Errorf("ExtractHLSRenditionDescription(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestCollectKeyDetails(t *testing.T) {
	tests := []struct {
		name          string
		analysis      *types.MediaAnalysis
		expectedKeys  int
		expectedVault int
		expectedKMS   int
	}{
		{
			name: "DASH with single key in vault with labels",
			analysis: &types.MediaAnalysis{
				MediaType:        "DASH",
				AllKeyIDs:        []string{"00000000-1234-5678-9abc-def012345678"},
				IVLength:         8,
				EncryptionMethod: "CENC (Common Encryption)",
				KeyExistsInVault: true,
				AllVaultKeyInfo: map[string]map[string]interface{}{
					"00000000-1234-5678-9abc-def012345678": {
						"labels": []interface{}{"hd-video", "widevine"},
					},
				},
			},
			expectedKeys:  1,
			expectedVault: 1,
			expectedKMS:   0,
		},
		{
			name: "DASH with multiple keys",
			analysis: &types.MediaAnalysis{
				MediaType:        "DASH",
				AllKeyIDs:        []string{"00000000-aaaa-bbbb-cccc-111111111111", "00000000-aaaa-bbbb-cccc-222222222222"},
				IVLength:         8,
				EncryptionMethod: "CENC (Common Encryption)",
				KeyExistsInVault: true,
				AllVaultKeyInfo:  map[string]map[string]interface{}{},
			},
			expectedKeys:  2,
			expectedVault: 1,
			expectedKMS:   0,
		},
		{
			name: "HLS with single key in KMS",
			analysis: &types.MediaAnalysis{
				MediaType:        "HLS",
				KeyID:            "00000000-1234-5678-9abc-def012345678",
				IVLength:         16,
				EncryptionMethod: "SAMPLE-AES (FairPlay)",
				KeyExistsInKMS:   true,
			},
			expectedKeys:  1,
			expectedVault: 0,
			expectedKMS:   1,
		},
		{
			name: "HLS with key in Vault and labels",
			analysis: &types.MediaAnalysis{
				MediaType:        "HLS",
				KeyID:            "00000000-1234-5678-9abc-def012345678",
				IVLength:         16,
				EncryptionMethod: "SAMPLE-AES (FairPlay)",
				KeyExistsInVault: true,
				VaultKeyInfo: map[string]interface{}{
					"labels": []interface{}{"fairplay", "hd"},
				},
			},
			expectedKeys:  1,
			expectedVault: 1,
			expectedKMS:   0,
		},
		{
			name: "no encryption",
			analysis: &types.MediaAnalysis{
				MediaType:        "DASH",
				EncryptionMethod: "None",
			},
			expectedKeys:  0,
			expectedVault: 0,
			expectedKMS:   0,
		},
		{
			name: "DASH with empty AllKeyIDs",
			analysis: &types.MediaAnalysis{
				MediaType:        "DASH",
				AllKeyIDs:        []string{},
				EncryptionMethod: "CENC (Common Encryption)",
			},
			expectedKeys:  0,
			expectedVault: 0,
			expectedKMS:   0,
		},
		{
			name: "HLS with empty KeyID",
			analysis: &types.MediaAnalysis{
				MediaType:        "HLS",
				KeyID:            "",
				EncryptionMethod: "SAMPLE-AES (FairPlay)",
			},
			expectedKeys:  0,
			expectedVault: 0,
			expectedKMS:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyDetails := make(map[string]types.KeyDetail)
			stats := &types.AnalysisStats{}

			CollectKeyDetails(tt.analysis, keyDetails, stats)

			if len(keyDetails) != tt.expectedKeys {
				t.Errorf("CollectKeyDetails() collected %d keys, want %d", len(keyDetails), tt.expectedKeys)
			}
			if stats.InVault != tt.expectedVault {
				t.Errorf("CollectKeyDetails() InVault = %d, want %d", stats.InVault, tt.expectedVault)
			}
			if stats.InKMS != tt.expectedKMS {
				t.Errorf("CollectKeyDetails() InKMS = %d, want %d", stats.InKMS, tt.expectedKMS)
			}
		})
	}
}

func TestCollectKeyDetailsExistingKey(t *testing.T) {
	// Test that existing keys are not overwritten
	keyDetails := make(map[string]types.KeyDetail)
	keyDetails["00000000-1234-5678-9abc-def012345678"] = types.KeyDetail{
		KID:    "00000000-1234-5678-9abc-def012345678",
		Labels: []string{"existing-label"},
	}

	analysis := &types.MediaAnalysis{
		MediaType:        "DASH",
		AllKeyIDs:        []string{"00000000-1234-5678-9abc-def012345678"},
		IVLength:         8,
		EncryptionMethod: "CENC (Common Encryption)",
		KeyExistsInVault: true,
		AllVaultKeyInfo: map[string]map[string]interface{}{
			"00000000-1234-5678-9abc-def012345678": {
				"labels": []interface{}{"new-label"},
			},
		},
	}

	stats := &types.AnalysisStats{}
	CollectKeyDetails(analysis, keyDetails, stats)

	// Should still have the existing label, not the new one
	detail := keyDetails["00000000-1234-5678-9abc-def012345678"]
	if len(detail.Labels) != 1 || detail.Labels[0] != "existing-label" {
		t.Errorf("Existing key was overwritten, labels = %v", detail.Labels)
	}
}

func TestCollectRenditions(t *testing.T) {
	tests := []struct {
		name               string
		analysis           *types.MediaAnalysis
		clipID             string
		expectedRenditions int
	}{
		{
			name: "DASH with multiple representations",
			analysis: &types.MediaAnalysis{
				MediaType: "DASH",
				Representations: []types.RepresentationInfo{
					{ID: "1", Bandwidth: 5000000, Codecs: "avc1.4d401f", Height: 1080, KeyID: "key1"},
					{ID: "2", Bandwidth: 2500000, Codecs: "avc1.4d401e", Height: 720, KeyID: "key1"},
					{ID: "3", Bandwidth: 128000, Codecs: "mp4a.40.2", Height: 0, KeyID: "key1"},
				},
			},
			clipID:             "clip123",
			expectedRenditions: 3,
		},
		{
			name: "DASH with no representations",
			analysis: &types.MediaAnalysis{
				MediaType:       "DASH",
				Representations: []types.RepresentationInfo{},
			},
			clipID:             "clip123",
			expectedRenditions: 0,
		},
		{
			name: "HLS returns no renditions from this function",
			analysis: &types.MediaAnalysis{
				MediaType: "HLS",
			},
			clipID:             "clip123",
			expectedRenditions: 0,
		},
		{
			name: "DASH with representation without height or codecs",
			analysis: &types.MediaAnalysis{
				MediaType: "DASH",
				Representations: []types.RepresentationInfo{
					{ID: "v1", Bandwidth: 5000000, Codecs: "", Height: 0, KeyID: "key1"},
				},
			},
			clipID:             "clip123",
			expectedRenditions: 1,
		},
		{
			name: "DASH with representation with codecs but no height",
			analysis: &types.MediaAnalysis{
				MediaType: "DASH",
				Representations: []types.RepresentationInfo{
					{ID: "a1", Bandwidth: 128000, Codecs: "mp4a.40.2", Height: 0, KeyID: "key1"},
				},
			},
			clipID:             "clip123",
			expectedRenditions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renditions := CollectRenditions(tt.analysis, tt.clipID)

			if len(renditions) != tt.expectedRenditions {
				t.Errorf("CollectRenditions() returned %d renditions, want %d", len(renditions), tt.expectedRenditions)
			}

			// Verify clip ID is set correctly
			for _, r := range renditions {
				if r.ClipID != tt.clipID {
					t.Errorf("Rendition ClipID = %q, want %q", r.ClipID, tt.clipID)
				}
			}
		})
	}
}

func TestCollectRenditionsDescriptions(t *testing.T) {
	analysis := &types.MediaAnalysis{
		MediaType: "DASH",
		Representations: []types.RepresentationInfo{
			{ID: "v1", Bandwidth: 5000000, Codecs: "avc1.4d401f", Height: 1080, KeyID: "key1"},
			{ID: "v2", Bandwidth: 2500000, Codecs: "avc1.4d401e", Height: 720, KeyID: "key1"},
			{ID: "a1", Bandwidth: 128000, Codecs: "mp4a.40.2", Height: 0, KeyID: "key1"},
		},
	}

	renditions := CollectRenditions(analysis, "testclip")

	// Check descriptions are properly formatted
	expectedDescContains := []string{"1080", "720", "Audio"}
	for i, expected := range expectedDescContains {
		found := false
		for _, r := range renditions {
			if containsStr(r.Description, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected rendition %d to contain %q in description", i, expected)
		}
	}
}

func TestFindMediaFilesLocal(t *testing.T) {
	// Create a temporary directory with some manifest files
	tmpDir := t.TempDir()

	// Create test files
	dashFile := filepath.Join(tmpDir, "manifest.mpd")
	hlsFile := filepath.Join(tmpDir, "master.m3u8")
	txtFile := filepath.Join(tmpDir, "readme.txt")

	for _, f := range []string{dashFile, hlsFile, txtFile} {
		if err := os.WriteFile(f, []byte("test"), 0o644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Create a subdirectory with more manifests
	subDir := filepath.Join(tmpDir, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	subMPD := filepath.Join(subDir, "video.mpd")
	if err := os.WriteFile(subMPD, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	files, err := FindMediaFiles(tmpDir)
	if err != nil {
		t.Fatalf("FindMediaFiles() error = %v", err)
	}

	// Should find 3 manifest files (2 in root, 1 in sub)
	if len(files) != 3 {
		t.Errorf("FindMediaFiles() found %d files, want 3", len(files))
	}

	// Verify all are manifests
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext != ".mpd" && ext != ".m3u8" {
			t.Errorf("FindMediaFiles() found non-manifest file: %s", f)
		}
	}
}

func TestFindMediaFilesNonExistent(t *testing.T) {
	_, err := FindMediaFiles("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("FindMediaFiles() expected error for non-existent path")
	}
}

func TestFindMediaFilesEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	files, err := FindMediaFiles(tmpDir)
	if err != nil {
		t.Fatalf("FindMediaFiles() error = %v", err)
	}

	if len(files) != 0 {
		t.Errorf("FindMediaFiles() found %d files in empty dir, want 0", len(files))
	}
}

func TestHexStringRegex(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"622721e908d75d0007f44311", true},
		{"ABCDEF123456789012345678", true},
		{"abcdef123456789012345678", true},
		{"abc123", true},
		{"not-hex-string", false},
		{"622721e908d75d0007f44311!", false},
		{"", false}, // Empty does not match ^[0-9a-fA-F]+$
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := hexStringRegex.MatchString(tt.input)
			if result != tt.expected {
				t.Errorf("hexStringRegex.MatchString(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// Helper function
func containsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}
