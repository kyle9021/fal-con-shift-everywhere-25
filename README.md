# CrowdStrike FCS CLI Downloader and Scanner

A comprehensive shell script that automatically downloads the latest CrowdStrike Falcon Cloud Security (FCS) CLI tool and executes Infrastructure as Code (IaC) security scans with enhanced reporting capabilities..

## Features

- **Automatic CLI Management**: Downloads and extracts the latest FCS CLI for your platform
- **Version Control**: Support for selecting specific CLI versions with offset-based selection
- **Multi-Format Output**: Generates JSON, SARIF, and human-readable reports
- **Proxy Support**: Auto-detects and configures proxy settings for corporate environments
- **Interactive & Non-Interactive**: Works in both manual and CI/CD environments
- **Comprehensive Reporting**: Detailed security findings with remediation guidance
- **Cross-Platform**: Supports Linux, macOS, and other Unix-like systems
- **Multi-Architecture**: Automatically detects and downloads correct binaries for amd64 and arm64 architectures

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
# Download the script directly
curl -O https://raw.githubusercontent.com/kyle9021/FCS-CLI-downloader-scanner/main/fcs_cli_iac_scan.sh

# Or clone the entire repository
git clone https://github.com/kyle9021/FCS-CLI-downloader-scanner.git
cd FCS-CLI-downloader-scanner
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
name: FCS IaC Security Scan
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
          SHOW_FULL_RESULTS: true
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

# Build stage
FROM alpine:3.19@sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33 AS builder

# Copy script
COPY fcs_cli_iac_scan.sh /usr/local/bin/
RUN chmod 555 /usr/local/bin/fcs_cli_iac_scan.sh

# Create directory structure in builder stage (no permissions set yet)
RUN mkdir -p /tmp/app-setup/home/nonroot/.crowdstrike/logs \
             /tmp/app-setup/workspace \
             /tmp/app-setup/tmp/downloads && \
    chmod 700 /tmp/app-setup/home/nonroot/.crowdstrike

# Use secrets mount to create config file in builder stage
RUN --mount=type=secret,id=client_id \
    --mount=type=secret,id=client_secret \
    --mount=type=secret,id=api_url \
    CLIENT_ID=$(cat /run/secrets/client_id) && \
    CLIENT_SECRET=$(cat /run/secrets/client_secret) && \
    API_URL=$(cat /run/secrets/api_url) && \
    printf '{\n' > /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    "schema_version": "",\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    "version": "1.0",\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    "verbose": false,\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    "profile": "default",\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    "profiles": {\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '        "default": {\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '            "falcon_region": "us-1",\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '            "client_id": "%s",\n' "${CLIENT_ID}" >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '            "client_secret": "%s",\n' "${CLIENT_SECRET}" >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '            "falcon_domains": {\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '                "api": "%s",\n' "${API_URL}" >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '                "container_upload": "https://container-upload.us-1.crowdstrike.com",\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '                "image_assessment": "https://container-upload.us-1.crowdstrike.com"\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '            }\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '        }\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '    }\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    printf '}\n' >> /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json && \
    chmod 600 /tmp/app-setup/home/nonroot/.crowdstrike/fcs.json

# Runtime stage - minimal Alpine with shell
FROM alpine:3.19@sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33

# Create nonroot user, install dependencies, then remove root user
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S -G nonroot -h /home/nonroot nonroot && \
    apk add --no-cache \
        curl=8.12.1-r0 \
        jq=1.6-r4 \
        tar=1.34-r3 && \
    # Remove root user and group (but keep essential system accounts)
    sed -i '/^root:/d' /etc/passwd && \
    sed -i '/^root:/d' /etc/shadow && \
    sed -i '/^root:/d' /etc/group && \
    # Remove root's home directory
    rm -rf /root

# Copy script and config from builder
COPY --from=builder /usr/local/bin/fcs_cli_iac_scan.sh /usr/local/bin/
COPY --from=builder /tmp/app-setup/home/nonroot/.crowdstrike /home/nonroot/.crowdstrike

# Set ownership and create directories with proper permissions AFTER user creation
RUN chown -R nonroot:nonroot /home/nonroot && \
    mkdir -p /workspace /tmp/downloads && \
    chown nonroot:nonroot /workspace /tmp/downloads && \
    chmod 750 /tmp/downloads && \
    chmod 755 /workspace

# Set working directory
WORKDIR /tmp/downloads

# Switch to non-root user
USER nonroot

# Add healthcheck instruction (simplified for security)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD test -f /usr/local/bin/fcs_cli_iac_scan.sh || exit 1

# Security and metadata labels
LABEL maintainer="security@crowdstrike.com" \
      version="1.0" \
      security="MINIMAL_ALPINE_NO_ROOT" \
      description="CrowdStrike FCS IaC Scanner - Minimal Alpine" \
      security.scan-date="2025-01-18" \
      security.base-image-digest="sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33"

# Environment variables
ENV HOME=/home/nonroot \
    PATH="/usr/local/bin:${PATH}" \
    USER=nonroot

# Run script directly
ENTRYPOINT ["/usr/local/bin/fcs_cli_iac_scan.sh", "/workspace"]
```

Usage with Docker if buillding locally:
```bash
# Create secrets
echo "$CS_CLIENT_ID" > /tmp/client_id
echo "$CS_CLIENT_SECRET" > /tmp/client_secret
echo "$CS_BASE_API_URL" > /tmp/api_url

# Build
docker build \
  --secret id=client_id,src=/tmp/client_id \
  --secret id=client_secret,src=/tmp/client_secret \
  --secret id=api_url,src=/tmp/api_url \
  --platform linux/amd64 \
  -t fcs-scanner .

# Run
docker run --rm \
  --platform linux/amd64 \
  -v "$(pwd):/workspace" \
  -e EXIT_WITH_FCS_CODE=true \
  -e SHOW_FULL_RESULTS=true \
  fcs-scanner

# Clean up
rm -f /tmp/client_id /tmp/client_secret /tmp/api_url
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
## Security Best Practices

### Credential Management
- **Never commit credentials** to version control
- Use secure credential stores in CI/CD
- For Docker deployments, use Docker secrets
- Regularly rotate FCS API credentials

### File Permissions
- The script automatically sets secure permissions on configuration files (600)
- Ensure the script itself has appropriate execute permissions (755)

### Network Security
- The script supports corporate proxy environments
- All API communications use HTTPS
- Proxy authentication is supported for corporate environments

### Container Security
- Docker images run as non-root user
- Minimal base images (Alpine Linux) for reduced attack surface
- Secrets are handled securely using Docker BuildKit secrets
- Health checks are included for container monitoring



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
