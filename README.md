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
curl -O https://raw.githubusercontent.com/your-repo/fcs-scanner/main/fcs-scanner.sh
chmod +x fcs-scanner.sh
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
./fcs-scanner.sh

# Scan specific directory
./fcs-scanner.sh ./terraform

# Scan with previous CLI version
./fcs-scanner.sh ./infrastructure 1
```

### With Environment Variables
```bash
# Pre-configure credentials
export CS_BASE_API_URL="https://api.us-2.crowdstrike.com"
export CS_CLIENT_ID="your_client_id"
export CS_CLIENT_SECRET="your_client_secret"
./fcs-scanner.sh
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
./fcs-scanner.sh ./src

# Detailed analysis with full results
SHOW_FULL_RESULTS=true ./fcs-scanner.sh ./terraform

# Generate only SARIF for tool integration
GENERATE_SUMMARY=false ./fcs-scanner.sh ./cloudformation
```

### CI/CD Integration
```bash
# Fail build on security findings
EXIT_WITH_FCS_CODE=true ./fcs-scanner.sh

# Complete CI/CD example
#!/bin/bash
set -e

# Set credentials from CI secrets
export CS_BASE_API_URL="$CROWDSTRIKE_API_URL"
export CS_CLIENT_ID="$CROWDSTRIKE_CLIENT_ID"
export CS_CLIENT_SECRET="$CROWDSTRIKE_CLIENT_SECRET"

# Run scan and fail on findings
EXIT_WITH_FCS_CODE=true ./fcs-scanner.sh ./infrastructure

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

./fcs-scanner.sh
```

### Advanced Usage
```bash
# Use specific CLI version (n-2)
./fcs-scanner.sh ./terraform 2

# Debug mode with full output
DEBUG=true SHOW_FULL_RESULTS=true ./fcs-scanner.sh

# Custom configuration
SCAN_PATH=./infrastructure \
VERSION_OFFSET=1 \
GENERATE_SARIF=false \
SHOW_FULL_RESULTS=true \
./fcs-scanner.sh
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
DEBUG=true ./fcs-scanner.sh
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
DEBUG=true ./fcs-scanner.sh
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

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y curl jq
        
      - name: Run FCS Scan
        env:
          CS_BASE_API_URL: ${{ secrets.CROWDSTRIKE_API_URL }}
          CS_CLIENT_ID: ${{ secrets.CROWDSTRIKE_CLIENT_ID }}
          CS_CLIENT_SECRET: ${{ secrets.CROWDSTRIKE_CLIENT_SECRET }}
          EXIT_WITH_FCS_CODE: true
        run: ./fcs-scanner.sh
        
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: fcs-scan-results.sarif
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
        stage('Security Scan') {
            steps {
                sh '''
                    chmod +x fcs-scanner.sh
                    EXIT_WITH_FCS_CODE=true ./fcs-scanner.sh
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'fcs-scan-*.{json,sarif,txt}', allowEmptyArchive: true
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
    sudo apt-get update
    sudo apt-get install -y curl jq
  displayName: 'Install dependencies'

- script: |
    chmod +x fcs-scanner.sh
    EXIT_WITH_FCS_CODE=true ./fcs-scanner.sh
  displayName: 'Run security scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'fcs-scan-results.sarif'
    artifactName: 'CodeAnalysisLogs'
  condition: always()
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
- **Documentation**: Check the script's built-in help: `./fcs-scanner.sh --help`
- **CrowdStrike Support**: For FCS-specific issues, contact CrowdStrike support

## Changelog

### v1.3 (Latest)
- Added full human-readable results display option
- Implemented FCS CLI exit code passthrough
- Enhanced proxy support with authentication
- Improved error handling and logging

### v1.2
- Added comprehensive proxy support
- Auto-detection of proxy settings
- FCS CLI proxy configuration

### v1.1
- Added human-readable summary generation
- Enhanced SARIF output format
- Improved console output formatting

### v1.0
- Initial release
- Basic FCS CLI download and scan functionality
- JSON and SARIF output support

---

**Note**: This script is not officially supported by CrowdStrike. It's a community tool designed to simplify FCS CLI usage and integration.
