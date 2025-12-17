package output

import (
	"strings"
	"testing"

	"github.com/zerogee00/whichkey/internal/types"
)

func TestExtractBitrateForSort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"kbps value", "HD 1080p H.264 (3853 kbps)", 3853},
		{"kbps value lower", "audio (128 kbps)", 128},
		{"resolution 2160p", "4K 2160p video", 15000},
		{"resolution 1080p", "HD 1080p video", 5000},
		{"resolution 720p", "HD 720p video", 2500},
		{"resolution 576p", "SD 576p video", 1500},
		{"resolution 480p", "SD 480p video", 1000},
		{"resolution 360p", "SD 360p video", 600},
		{"resolution 240p", "SD 240p video", 300},
		{"resolution 144p", "144p video", 150},
		{"audio stream", "Audio AAC", 100},
		{"mp4a codec", "mp4a.40.2 stream", 100},
		{"subtitle wvtt", "Subtitles (wvtt)", 0},
		{"subtitle text", "subtitle track", 0},
		{"unknown format", "Unknown stream", 50000},
		{"empty string", "", 50000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractBitrateForSort(tt.input)
			if result != tt.expected {
				t.Errorf("ExtractBitrateForSort(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSortRenditionsByBitrate(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name: "mixed renditions",
			input: []string{
				"HD 1080p H.264 (5000 kbps)",
				"Audio AAC (128 kbps)",
				"HD 720p H.264 (2500 kbps)",
				"SD 480p H.264 (1000 kbps)",
			},
			expected: []string{
				"Audio AAC (128 kbps)",
				"SD 480p H.264 (1000 kbps)",
				"HD 720p H.264 (2500 kbps)",
				"HD 1080p H.264 (5000 kbps)",
			},
		},
		{
			name:     "empty list",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single item",
			input:    []string{"HD 1080p"},
			expected: []string{"HD 1080p"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renditions := make([]string, len(tt.input))
			copy(renditions, tt.input)

			SortRenditionsByBitrate(renditions)

			for i, expected := range tt.expected {
				if renditions[i] != expected {
					t.Errorf("position %d: got %q, want %q", i, renditions[i], expected)
				}
			}
		})
	}
}

func TestSimplifyCodecName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"avc1 with profile", "avc1.4d401f", "H.264"},
		{"avc1 simple", "avc1", "H.264"},
		{"h264", "h264", "H.264"},
		{"H264 uppercase", "H264", "H.264"},
		{"hvc1", "hvc1.1.6.L93.90", "HEVC"},
		{"hev1", "hev1.1.6.L93.90", "HEVC"},
		{"h265", "h265", "HEVC"},
		{"vp9", "vp9", "VP9"},
		{"vp09", "vp09.00.10.08", "VP9"},
		{"av01", "av01.0.04M.08", "AV1"},
		{"av1 simple", "av1", "AV1"},
		{"mp4a", "mp4a.40.2", "AAC"},
		{"ac-3", "ac-3", "Dolby AC-3"},
		{"ec-3", "ec-3", "Dolby E-AC-3"},
		{"EC-3 uppercase", "EC-3", "Dolby E-AC-3"},
		{"opus", "opus", "Opus"},
		{"OPUS uppercase", "OPUS", "Opus"},
		{"unknown codec", "xyz123", "xyz123"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SimplifyCodecName(tt.input)
			if result != tt.expected {
				t.Errorf("SimplifyCodecName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatCodecDescription(t *testing.T) {
	tests := []struct {
		name          string
		codecs        string
		bandwidthKbps int
		expected      string
	}{
		{"AAC audio", "mp4a.40.2", 128, "Audio AAC (128 kbps)"},
		{"Dolby AC-3", "ac-3", 384, "Audio Dolby (384 kbps)"},
		{"Dolby E-AC-3", "ec-3", 640, "Audio Dolby (640 kbps)"},
		{"Opus audio", "opus", 96, "Audio Opus (96 kbps)"},
		{"HD video", "avc1.4d401f", 5000, "HD Video H.264 (5000 kbps)"},
		{"SD video", "avc1.4d401f", 1000, "SD Video H.264 (1000 kbps)"},
		{"WebVTT subtitles", "wvtt", 10, "Subtitles (WebVTT)"},
		{"TTML subtitles", "stpp", 10, "Subtitles (TTML)"},
		{"TTML via ttml", "ttml", 10, "Subtitles (TTML)"},
		{"Unknown codec", "xyz123", 1500, "xyz123 (1500 kbps)"},
		{"VTT variant", "vtt", 5, "Subtitles (WebVTT)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatCodecDescription(tt.codecs, tt.bandwidthKbps)
			if result != tt.expected {
				t.Errorf("FormatCodecDescription(%q, %d) = %q, want %q",
					tt.codecs, tt.bandwidthKbps, result, tt.expected)
			}
		})
	}
}

func TestFormatResolutionDescription(t *testing.T) {
	tests := []struct {
		name          string
		height        int
		codecs        string
		bandwidthKbps int
		expected      string
	}{
		{"4K UHD", 2160, "avc1.4d401f", 15000, "HD 2160p H.264 (15000 kbps)"},
		{"1080p HD", 1080, "avc1.4d401f", 5000, "HD 1080p H.264 (5000 kbps)"},
		{"720p HD", 720, "avc1.4d401f", 2500, "HD 720p H.264 (2500 kbps)"},
		{"719p SD boundary", 719, "avc1.4d401f", 2400, "SD 719p H.264 (2400 kbps)"},
		{"480p SD", 480, "avc1.4d401f", 1000, "SD 480p H.264 (1000 kbps)"},
		{"360p SD", 360, "avc1.4d401f", 600, "SD 360p H.264 (600 kbps)"},
		{"240p SD", 240, "avc1.4d401f", 300, "SD 240p H.264 (300 kbps)"},
		{"HEVC codec", 1080, "hvc1.1.6.L93", 8000, "HD 1080p HEVC (8000 kbps)"},
		{"VP9 codec", 1080, "vp9", 6000, "HD 1080p VP9 (6000 kbps)"},
		{"AV1 codec", 1080, "av01", 4000, "HD 1080p AV1 (4000 kbps)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatResolutionDescription(tt.height, tt.codecs, tt.bandwidthKbps)
			if result != tt.expected {
				t.Errorf("FormatResolutionDescription(%d, %q, %d) = %q, want %q",
					tt.height, tt.codecs, tt.bandwidthKbps, result, tt.expected)
			}
		})
	}
}

func TestSpinner(t *testing.T) {
	t.Run("creation", func(t *testing.T) {
		spinner := NewSpinner("Testing...")
		if spinner == nil {
			t.Fatal("NewSpinner returned nil")
		}
		if spinner.message != "Testing..." {
			t.Errorf("spinner message = %q, want %q", spinner.message, "Testing...")
		}
		if len(spinner.frames) == 0 {
			t.Error("spinner has no frames")
		}
		if spinner.frames[0] != "⠋" {
			t.Errorf("first frame = %q, want %q", spinner.frames[0], "⠋")
		}
	})

	t.Run("update message", func(t *testing.T) {
		spinner := NewSpinner("Initial")
		spinner.Update("Updated message")
		if spinner.message != "Updated message" {
			t.Errorf("after Update, message = %q, want %q", spinner.message, "Updated message")
		}
	})

	t.Run("frames count", func(t *testing.T) {
		spinner := NewSpinner("Test")
		if len(spinner.frames) != 10 {
			t.Errorf("frames count = %d, want 10", len(spinner.frames))
		}
	})
}

func TestGlobalVariables(t *testing.T) {
	t.Run("ManifestPath", func(t *testing.T) {
		original := ManifestPath
		defer func() { ManifestPath = original }()

		ManifestPath = "/test/path.mpd"
		if ManifestPath != "/test/path.mpd" {
			t.Error("Failed to set ManifestPath")
		}
	})

	t.Run("MarkdownOutput", func(t *testing.T) {
		original := MarkdownOutput
		defer func() { MarkdownOutput = original }()

		MarkdownOutput = true
		if !MarkdownOutput {
			t.Error("Failed to set MarkdownOutput to true")
		}

		MarkdownOutput = false
		if MarkdownOutput {
			t.Error("Failed to set MarkdownOutput to false")
		}
	})
}

func TestGenerateMarkdownSummary(t *testing.T) {
	t.Run("empty keys", func(t *testing.T) {
		keyMap := make(map[string]types.KeyDetail)
		renditions := make(map[string]map[string]map[string]bool)
		clips := make(map[string]map[string]bool)

		result := GenerateMarkdownSummary(keyMap, renditions, clips)

		if !strings.Contains(result, "# Keys & Renditions") {
			t.Error("Missing header in markdown")
		}
	})

	t.Run("with DASH key", func(t *testing.T) {
		ManifestPath = "s3://bucket/path/main.mpd"
		keyMap := map[string]types.KeyDetail{
			"00000000-1234-5678-9abc-def012345678": {
				KID:              "00000000-1234-5678-9abc-def012345678",
				Labels:           []string{"hd-video"},
				IV:               8,
				EncryptionMethod: "CENC (Common Encryption)",
				InVault:          true,
			},
		}
		renditions := map[string]map[string]map[string]bool{
			"00000000-1234-5678-9abc-def012345678": {
				"clip1": {
					"HD 1080p H.264 (5000 kbps)": true,
				},
			},
		}
		clips := map[string]map[string]bool{
			"00000000-1234-5678-9abc-def012345678": {
				"clip1": true,
			},
		}

		result := GenerateMarkdownSummary(keyMap, renditions, clips)

		if !strings.Contains(result, "DASH") {
			t.Error("Missing DASH section in markdown")
		}
		if !strings.Contains(result, "00000000-1234-5678-9abc-def012345678") {
			t.Error("Missing KID in markdown")
		}
		if !strings.Contains(result, "Vault") {
			t.Error("Missing Vault status in markdown")
		}
	})

	t.Run("with HLS key", func(t *testing.T) {
		ManifestPath = "s3://bucket/path/"
		keyMap := map[string]types.KeyDetail{
			"00000000-aaaa-bbbb-cccc-111111111111": {
				KID:              "00000000-aaaa-bbbb-cccc-111111111111",
				IV:               16,
				EncryptionMethod: "SAMPLE-AES (FairPlay)",
				InVault:          false,
				InKMS:            true,
			},
		}
		renditions := make(map[string]map[string]map[string]bool)
		clips := make(map[string]map[string]bool)

		result := GenerateMarkdownSummary(keyMap, renditions, clips)

		if !strings.Contains(result, "HLS") {
			t.Error("Missing HLS section in markdown")
		}
		if !strings.Contains(result, "FairPlay") {
			t.Error("Missing FairPlay in markdown")
		}
	})
}
