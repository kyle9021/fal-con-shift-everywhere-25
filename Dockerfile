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
