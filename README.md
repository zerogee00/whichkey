# whichkey

A CLI tool for analyzing DRM-protected media content. It inspects HLS and DASH manifests to identify encryption keys, verify their presence in Vault/KMS, and provide detailed rendition information.

## Features

- 🔍 Analyze HLS (.m3u8) and DASH (.mpd) manifests
- 🔐 Verify keys exist in Vault and KMS
- 📦 Support for local files, HTTP(S) URLs, and S3 buckets
- 🏷️ Display key labels and metadata from Vault
- 📋 Copy markdown summary to clipboard
- ⚡ Concurrent processing for large bucket scans
- 🎯 Auto-detect AWS profiles from bucket names

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/zerogee00/whichkey.git
cd whichkey

# Build and install to ~/go/bin
make install

# Or just build locally
make build
```

### Pre-built Binaries

Download from the [releases page](https://github.com/zerogee00/whichkey/releases).

## Usage

```bash
# Analyze a single manifest
whichkey /path/to/manifest.mpd
whichkey https://cdn.example.com/content/dash/main.mpd
whichkey s3://bucket-name/clip/path/dash/0-end/main.mpd

# Analyze all manifests in a directory or S3 prefix
whichkey /path/to/media/
whichkey s3://bucket-name/clip/path/

# Specify environment
whichkey -env prd s3://prd-bucket/clip/path/

# Verbose output
whichkey -v 1 s3://bucket/path/   # Normal verbosity
whichkey -v 2 s3://bucket/path/   # Detailed verbosity

# Skip infrastructure checks
whichkey -skip-vault -skip-kubectl /path/to/manifest.mpd
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-env` | Environment (nonprd, preprd, prd) | `nonprd` |
| `-v` | Verbosity level (0=summary, 1=normal, 2=detailed) | `0` |
| `-aws-profile` | AWS profile for S3 access | auto-detected |
| `-workers` | Concurrent workers for bucket scans | `5` |
| `-subclips` | Include subclip folders instead of just 0-end | `false` |
| `-md` | Copy markdown summary to clipboard | `true` |
| `-skip-vault` | Skip Vault authentication | `false` |
| `-skip-kubectl` | Skip kubectl context setup | `false` |
| `-config` | Path to config file | auto-detect |
| `-init-config` | Generate default config file and exit | - |

## Configuration

whichkey uses a JSON config file for environment settings. Config files are searched in order:

1. `./whichkey.json`
2. `./.whichkey.json`
3. `~/.whichkey.json`
4. `~/.config/whichkey/config.json`
5. `<executable_dir>/whichkey.json`

### Generate Default Config

```bash
whichkey -init-config
# Or specify output path
whichkey -init-config -config ~/.whichkey.json
```

### Config Structure

```json
{
  "default_environment": "nonprd",
  "environments": {
    "nonprd": {
      "name": "nonprd",
      "aliases": ["dev", "development"],
      "namespace": "nonprd-service-media-center",
      "configmap_name": "configmap.service-media-center-utility-clip-ids",
      "secret_name": "secret.service-media-center",
      "kms_endpoint": "https://service-video-kms-use1-1.nonprd.pluto.tv/v1",
      "vault_path": "app/common/shared-encryption/nonprd",
      "vault_server": "https://vault-nonprd.devops.pluto.tv",
      "vault_key": "STATIC_ENCRYPTION_KEYS"
    }
  },
  "aws_profiles": {
    "bucket_patterns": {
      "slio": "main-tier4",
      "nonprd": "nonprod-tier3",
      "preprd": "preprod-tier3",
      "prd": "main-tier4"
    }
  },
  "kubectl_contexts": {
    "nonprd": ["nonprd", "pluto-nonprd", "aws-nonprd"]
  },
  "fallback_utility_clip_ids": ["clip-id-1", "clip-id-2"]
}
```

## Output Example

```
🔑 Keys & Renditions:

📺 DASH (Widevine/PlayReady):
┌──────────────────────────────────────────────────────────┐
│ KID: 00000000-654b-bc98-c034-dae1f16995de                │
│ IV: 8 bytes | CENC (Common Encryption) | ✓ Vault        │
│ Labels: hd-video, widevine                              │
│ Renditions:                                             │
│   • HD 720p H.264 (2151 kbps)                          │
│   • HD 1080p H.264 (3853 kbps)                         │
└──────────────────────────────────────────────────────────┘

📱 HLS (FairPlay):
┌──────────────────────────────────────────────────────────┐
│ KID: 00000000-654b-bc98-c034-dae1f16995de                │
│ IV: 16 bytes | SAMPLE-AES (FairPlay) | ✓ Vault          │
│ Renditions:                                             │
│   • HD 720p H.264 (2151 kbps)                          │
│   • HD 1080p H.264 (3853 kbps)                         │
└──────────────────────────────────────────────────────────┘

✓ Vault: 2/2 keys verified

📋 Markdown copied to clipboard!
```

## Development

### Prerequisites

- Go 1.22+
- golangci-lint (for linting)
- mockery (for generating mocks)

### Setup

```bash
# Install development tools
make tools

# Download dependencies
make deps
```

### Build

```bash
# Build binary
make build

# Quick build (no version info)
make build-quick

# Build for all platforms
make build-all
```

### Test

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run short tests only
make test-short
```

### Lint

```bash
# Run linter
make lint

# Format code
make fmt
```

### Generate Mocks

```bash
make mocks
```

## Project Structure

```
whichkey/
├── cmd/
│   └── whichkey/
│       └── main.go          # Entry point
├── internal/
│   ├── analysis/            # HLS/DASH manifest parsing
│   ├── aws/                 # S3 client, AWS config
│   ├── config/              # Configuration management
│   ├── k8s/                 # kubectl integration
│   ├── output/              # Output formatting
│   ├── types/               # Shared types
│   └── vault/               # Vault/KMS integration
├── .golangci.yml            # Linter configuration
├── Makefile                 # Build automation
├── whichkey.json            # Default config
└── README.md
```

## License

MIT
