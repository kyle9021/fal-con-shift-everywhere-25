# CrowdStrike FCS CLI Downloader and Scanner

A comprehensive shell script that automatically downloads the latest CrowdStrike Falcon Cloud Security (FCS) CLI tool and executes Infrastructure as Code (IaC) security scans with enhanced reporting capabilities.

## Features

- **Automatic CLI Management**: Downloads and extracts the latest FCS CLI for your platform
- **Version Control**: Support for selecting specific CLI versions with offset-based selection
- **Multi-Format Output**: Generates JSON, SARIF, and human-readable reports
- **Proxy Support**: Auto-detects and configures proxy settings for corporate environments
- **Interactive & Non-Interactive**: Works in both manual and CI/CD environments
- **Comprehensive Reporting**: Detailed security findings with remediation guidance
- **Cross-Platform**: Supports Linux, macOS, and other Unix-like systems

## Prerequisites

### Required Dependencies
- `curl` - For API calls and file downloads
- `jq` - For JSON processing
- `tar` - For archive extraction

### CrowdStrike Requirements
- CrowdStrike Falcon Cloud Security subscription
- API credentials with FCS permissions:
  - Client ID
  - Client Secret
  - Appropriate API scopes for FCS operations

## Installation

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/kyle9021/fcs-scanner/main/fcs_cli_iac_scan.sh # or git clone https://github.com/kyle9021/FCS-CLI-downloader-scanner
chmod +x fcs_cli_iac_scan.sh
```

2. Install dependencies (if not already present):

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install curl jq tar
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install curl jq tar
# or for newer versions:
sudo dnf install curl jq tar
```

**macOS:**
```bash
brew install curl jq
# tar is included by default
```

## Quick Start

### Basic Usage
```bash
# Scan current directory with latest FCS CLI
./fcs_cli_iac_scan.sh

# Scan specific directory
./fcs_cli_iac_scan.sh ./terraform

# Scan with previous CLI version
./fcs_cli_iac_scan.sh ./infrastructure 1
```

### With Environment Variables
```bash
# Pre-configure credentials
export CS_BASE_API_URL="https://api.us-2.crowdstrike.com"
export CS_CLIENT_ID="your_client_id"
export CS_CLIENT_SECRET="your_client_secret"
./fcs_cli_iac_scan.sh
```

## Configuration

### Environment Variables

#### Required (if not set interactively)
| Variable | Description | Example |
|----------|-------------|---------|
| `CS_BASE_API_URL` | CrowdStrike API base URL | `https://api.crowdstrike.com` |
| `CS_CLIENT_ID` | CrowdStrike API Client ID | `abc123def456...` |
| `CS_CLIENT_SECRET` | CrowdStrike API Client Secret | `xyz789uvw012...` |

#### Optional Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_PATH` | Current directory | Directory to scan |
| `VERSION_OFFSET` | `0` | CLI version offset (0=latest, 1=n-1, etc.) |
| `GENERATE_SARIF` | `true` | Generate SARIF output file |
| `GENERATE_SUMMARY` | `true` | Generate human-readable summary |
| `SHOW_FULL_RESULTS` | `false` | Display complete detailed summary |
| `EXIT_WITH_FCS_CODE` | `false` | Exit with FCS CLI exit code |
| `DEBUG` | `false` | Enable debug logging |

#### Proxy Configuration (Auto-detected)
| Variable | Description | Example |
|----------|-------------|---------|
| `HTTP_PROXY` | HTTP proxy URL | `http://proxy.company.com:8080` |
| `HTTPS_PROXY` | HTTPS proxy URL | `http://proxy.company.com:8080` |
| `NO_PROXY` | Bypass proxy for hosts | `localhost,127.0.0.1,.company.com` |
| `PROXY_USER` | Proxy username | `username` |
| `PROXY_PASS` | Proxy password | `password` |

### CrowdStrike Regions

| Region | API URL |
|--------|---------|
| US-1 (Commercial) | `https://api.crowdstrike.com` |
| US-2 (Commercial) | `https://api.us-2.crowdstrike.com` |
| EU-1 (Commercial) | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 (GovCloud) | `https://api.laggar.gcw.crowdstrike.com` |
| US-GOV-2 (GovCloud) | `https://api.us-gov-2.crowdstrike.mil` |

## Usage Examples

### Development Workflow
```bash
# Quick scan with brief summary
./fcs_cli_iac_scan.sh ./src

# Detailed analysis with full results
SHOW_FULL_RESULTS=true ./fcs_cli_iac_scan.sh ./terraform

# Generate only SARIF for tool integration
GENERATE_SUMMARY=false ./fcs_cli_iac_scan.sh ./cloudformation
```

### CI/CD Integration
```bash
# Fail build on security findings
EXIT_WITH_FCS_CODE=true ./fcs_cli_iac_scan.sh

# Complete CI/CD example
#!/bin/bash
set -e

# Set credentials from CI secrets
export CS_BASE_API_URL="$CROWDSTRIKE_API_URL"
export CS_CLIENT_ID="$CROWDSTRIKE_CLIENT_ID"
export CS_CLIENT_SECRET="$CROWDSTRIKE_CLIENT_SECRET"

# Run scan and fail on findings
EXIT_WITH_FCS_CODE=true ./fcs_cli_iac_scan.sh ./infrastructure

# Check exit code
if [ $? -eq 40 ]; then
    echo "Security issues found - failing build"
    exit 1
elif [ $? -eq 0 ]; then
    echo "No security issues found"
else
    echo "Scan failed with error"
    exit 1
fi
```

### Corporate Proxy Environment
```bash
# Proxy settings are auto-detected from environment
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.internal.company.com"

# With authentication
export PROXY_USER="myusername"
export PROXY_PASS="mypassword"

./fcs_cli_iac_scan.sh
```

### Advanced Usage
```bash
# Use specific CLI version (n-2)
./fcs_cli_iac_scan.sh ./terraform 2

# Debug mode with full output
DEBUG=true SHOW_FULL_RESULTS=true ./fcs_cli_iac_scan.sh

# Custom configuration
SCAN_PATH=./infrastructure \
VERSION_OFFSET=1 \
GENERATE_SARIF=false \
SHOW_FULL_RESULTS=true \
./fcs_cli_iac_scan.sh
```

## Output Files

The script generates multiple output formats:

### 1. JSON Results (`fcs-scan-results.json`)
- Raw FCS CLI output in JSON format
- Complete scan metadata and findings
- Suitable for programmatic processing

### 2. SARIF Results (`fcs-scan-results.sarif`)
- Industry-standard Static Analysis Results Interchange Format
- Compatible with GitHub Security tab, Azure DevOps, and other tools
- Includes remediation suggestions and fix information

### 3. Human-Readable Summary (`fcs-scan-summary.txt`)
- Organized by severity level (High, Medium, Informational)
- Detailed descriptions and remediation guidance
- Easy to read and share with teams

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (default behavior) |
| 1 | Authentication failure |
| 2 | No compatible CLI version found |
| 3 | Download failure |
| 4 | Missing dependencies |
| 5 | Invalid arguments |
| 6 | User cancelled input |
| 40+ | FCS CLI exit codes (when `EXIT_WITH_FCS_CODE=true`) |

### FCS CLI Exit Codes
- `0`: No security issues found
- `40`: Security issues found (typical)
- Other codes: Various FCS CLI error conditions

## Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Verify credentials
curl -X POST "$CS_BASE_API_URL/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CS_CLIENT_ID&client_secret=$CS_CLIENT_SECRET"
```

#### Proxy Issues
```bash
# Test proxy connectivity
curl --proxy "$HTTP_PROXY" -I https://api.crowdstrike.com

# Enable debug mode
DEBUG=true ./fcs_cli_iac_scan.sh
```

#### Missing Dependencies
```bash
# Check required tools
command -v curl && echo "curl: OK" || echo "curl: MISSING"
command -v jq && echo "jq: OK" || echo "jq: MISSING"
command -v tar && echo "tar: OK" || echo "tar: MISSING"
```

### Debug Mode
Enable detailed logging:
```bash
DEBUG=true ./fcs_cli_iac_scan.sh
```

This provides:
- Detailed API interactions
- File path extraction debugging
- Proxy configuration details
- Version selection process

## Integration Examples

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Verify dependencies (optional)
        run: |
          echo "Checking dependencies..."
          curl --version
          jq --version
          tar --version
        
      - name: Run FCS Scan
        env:
          CS_BASE_API_URL: ${{ secrets.CROWDSTRIKE_API_URL }}
          CS_CLIENT_ID: ${{ secrets.CROWDSTRIKE_CLIENT_ID }}
          CS_CLIENT_SECRET: ${{ secrets.CROWDSTRIKE_CLIENT_SECRET }}
          EXIT_WITH_FCS_CODE: true
        run: |
          chmod +x fcs_cli_iac_scan.sh
          ./fcs_cli_iac_scan.sh
        
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always() && hashFiles('fcs-scan-results.sarif') != ''
        with:
          sarif_file: fcs-scan-results.sarif
        continue-on-error: true
          
      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-results
          path: |
            fcs-scan-results.json
            fcs-scan-results.sarif
            fcs-scan-summary.txt
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    environment {
        CS_BASE_API_URL = credentials('crowdstrike-api-url')
        CS_CLIENT_ID = credentials('crowdstrike-client-id')
        CS_CLIENT_SECRET = credentials('crowdstrike-client-secret')
    }
    
    stages {
        stage('Install Dependencies') {
            steps {
                sh '''
                    # Check if running as root or if packages are already available
                    if ! command -v curl &> /dev/null; then
                        if [ "$EUID" -eq 0 ]; then
                            apt-get update && apt-get install -y curl jq tar
                        else
                            echo "Dependencies not found and not running as root"
                            echo "Please ensure curl, jq, and tar are installed"
                            exit 1
                        fi
                    fi
                '''
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    chmod +x fcs_cli_iac_scan.sh
                    EXIT_WITH_FCS_CODE=true ./fcs_cli_iac_scan.sh
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'fcs-scan-*.{json,sarif,txt}', allowEmptyArchive: true
                    
                    script {
                        if (fileExists('fcs-scan-results.sarif')) {
                            recordIssues enabledForFailure: true, tools: [sarif(pattern: 'fcs-scan-results.sarif')]
                        }
                    }
                    
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'fcs-scan-summary.txt',
                        reportName: 'Security Scan Report'
                    ])
                }
            }
        }
    }
}
```

### Azure DevOps
```yaml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  CS_BASE_API_URL: $(CROWDSTRIKE_API_URL)
  CS_CLIENT_ID: $(CROWDSTRIKE_CLIENT_ID)
  CS_CLIENT_SECRET: $(CROWDSTRIKE_CLIENT_SECRET)

steps:
- script: |
    apt-get update
    apt-get install -y curl jq tar
  displayName: 'Install dependencies'

- script: |
    chmod +x fcs_cli_iac_scan.sh
    EXIT_WITH_FCS_CODE=true ./fcs_cli_iac_scan.sh
  displayName: 'Run security scan'
  env:
    CS_BASE_API_URL: $(CS_BASE_API_URL)
    CS_CLIENT_ID: $(CS_CLIENT_ID)
    CS_CLIENT_SECRET: $(CS_CLIENT_SECRET)

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: '.'
    artifactName: 'SecurityScanResults'
    includeRootFolder: false
  condition: always()
  displayName: 'Publish scan results'

- task: PublishSecurityAnalysisResults@3
  inputs:
    artifactType: 'sarif'
    artifactLocation: 'fcs-scan-results.sarif'
  condition: and(always(), exists('fcs-scan-results.sarif'))
  displayName: 'Publish SARIF results'
```

### Docker Integration
```dockerfile
# syntax=docker/dockerfile:1
FROM alpine:3.19@sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install dependencies
RUN apk update && \
    apk add --no-cache \
    curl=8.12.1-r0 \
    jq=1.6-r4 \
    tar=1.34-r3 \
    && rm -rf /var/cache/apk/*

# Create necessary directories
RUN mkdir -p /home/appuser/.crowdstrike/logs /workspace /tmp/downloads && \
    chmod 700 /home/appuser/.crowdstrike && \
    chmod 777 /tmp/downloads

# Use secrets mount to create config file
RUN --mount=type=secret,id=client_id \
    --mount=type=secret,id=client_secret \
    --mount=type=secret,id=api_url \
    CLIENT_ID=$(cat /run/secrets/client_id) && \
    CLIENT_SECRET=$(cat /run/secrets/client_secret) && \
    API_URL=$(cat /run/secrets/api_url) && \
    echo "{\
    \"schema_version\": \"\",\
    \"version\": \"1.0\",\
    \"verbose\": false,\
    \"profile\": \"default\",\
    \"profiles_path\": \"/home/appuser/.crowdstrike/fcs_profiles.json\",\
    \"timeout\": 60,\
    \"security\": {\
        \"encryption\": {\
            \"type\": \"keyring\",\
            \"passphrase_path\": \"/home/appuser/.crowdstrike/passphrase\"\
        },\
        \"credentials_path\": \"/home/appuser/.crowdstrike/fcs_credentials.enc.json\"\
    },\
    \"scan\": {\
        \"iac\": {\
            \"path\": \"\",\
            \"output_path\": \"/home/appuser/.crowdstrike/logs\",\
            \"upload_results\": true,\
            \"policy_rule\": \"default\",\
            \"disable_secrets_scan\": false,\
            \"exclude_paths\": [],\
            \"exclude_categories\": [],\
            \"exclude_severities\": [],\
            \"fail_on\": [\"critical\", \"high\", \"medium\", \"low\", \"info\"],\
            \"project_owners\": []\
        },\
        \"image\": {\
            \"path\": \"\",\
            \"output\": \"\",\
            \"image-output-path\": \"\",\
            \"upload\": true,\
            \"socket\": \"\",\
            \"temp_dir\": \"\",\
            \"source_override\": \"\",\
            \"username\": \"\",\
            \"password\": \"\",\
            \"registry\": {\
                \"url\": \"\",\
                \"type\": \"\",\
                \"port\": \"443\",\
                \"insecure\": false\
            },\
            \"vulnerability_only\": false\
        }\
    },\
    \"report\": {\
        \"format\": \"json\",\
        \"vuln_score_threshold\": 0,\
        \"vuln_severity_threshold\": \"\"\
    },\
    \"credentials\": {\
        \"output_type\": \"table\",\
        \"show_secrets\": false,\
        \"force\": false,\
        \"secure\": false,\
        \"type\": \"\"\
    },\
    \"profiles\": {\
        \"default\": {\
            \"falcon_region\": \"us-1\",\
            \"client_id\": \"${CLIENT_ID}\",\
            \"client_secret\": \"${CLIENT_SECRET}\",\
            \"falcon_domains\": {\
                \"api\": \"${API_URL}\",\
                \"container_upload\": \"https://container-upload.us-1.crowdstrike.com\",\
                \"image_assessment\": \"https://container-upload.us-1.crowdstrike.com\"\
            }\
        }\
    }\
}" | jq '.' > /home/appuser/.crowdstrike/fcs.json && \
    chmod 600 /home/appuser/.crowdstrike/fcs.json

# Copy script
COPY fcs_cli_iac_scan.sh /usr/local/bin/
RUN chmod 555 /usr/local/bin/fcs_cli_iac_scan.sh

# Set proper ownership
RUN chown -R appuser:appgroup /home/appuser

WORKDIR /tmp/downloads
USER appuser

# Add healthcheck instruction
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/fcs_cli_iac_scan.sh --help >/dev/null 2>&1 || exit 1

LABEL maintainer="your-email@crowdstrike.com"
LABEL version="1.0"
LABEL security="SCANNED"
LABEL description="CrowdStrike FCS IaC Scanner"

ENV HOME=/home/appuser
ENV PATH="/usr/local/bin:${PATH}"

# Default to scanning /workspace if no arguments provided
ENTRYPOINT ["/usr/local/bin/fcs_cli_iac_scan.sh", "/workspace"]
```

Usage with Docker:
```bash
# Build image
docker build \
  --build-arg CLIENT_ID="$CS_CLIENT_ID" \
  --build-arg CLIENT_SECRET="$CS_CLIENT_SECRET" \
  --build-arg API_URL="$CS_BASE_API_URL" \
  --platform linux/amd64 \
  -t fcs-scanner .


# Run scan
docker run --rm \
  --platform linux/amd64 \
  -v "$(pwd):/workspace" \
  fcs-scanner
```

## Command Line Reference

### Basic Syntax
```bash
./fcs_cli_iac_scan.sh [scan_directory] [version_offset]
```

### Arguments
- `scan_directory` (optional): Directory to scan (default: current directory)
- `version_offset` (optional): Version offset from latest (default: 0)
  - `0` = latest version
  - `1` = n-1 (previous version)
  - `2` = n-2 (two versions back)

### Help
```bash
./fcs_cli_iac_scan.sh --help
./fcs_cli_iac_scan.sh -h
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow POSIX shell scripting standards
- Add comprehensive error handling
- Include debug logging for new features
- Update documentation for new options
- Test across different platforms

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Check the script's built-in help: `./fcs_cli_iac_scan.sh --help`
- **CrowdStrike Support**: For FCS-specific issues, contact CrowdStrike support



**Note**: This script is not officially supported by CrowdStrike. It's a community tool designed to simplify FCS CLI usage and integration.
