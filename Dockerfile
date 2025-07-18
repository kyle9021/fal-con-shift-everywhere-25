FROM alpine:3.19@sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33

# Define build arguments for sensitive data
ARG CLIENT_ID
ARG CLIENT_SECRET
ARG API_URL="https://api.crowdstrike.com"

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install dependencies with exact version pinning using available versions
RUN apk update && \
    apk add --no-cache \
    curl=8.12.1-r0 \
    jq=1.6-r4 \
    tar=1.34-r3 \
    && rm -rf /var/cache/apk/*

# Create necessary directories with proper permissions (700 = rwx------)
RUN mkdir -p /home/appuser/.crowdstrike/logs && \
    chmod 700 /home/appuser/.crowdstrike && \
    chmod 700 /home/appuser/.crowdstrike/logs

# Create configuration file with injected secrets
RUN echo "{\
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

# Create workspace directory and temp directory for downloads
RUN mkdir -p /workspace /tmp/fcs && \
    chmod 755 /tmp/fcs

# Copy script with root ownership (address informational chown issue)
COPY fcs_cli_iac_scan.sh /usr/local/bin/
RUN chmod 555 /usr/local/bin/fcs_cli_iac_scan.sh

# Set proper ownership for user directories
RUN chown -R appuser:appgroup /home/appuser /workspace /tmp/fcs

# Set working directory to a location the user can write to
WORKDIR /tmp/fcs

# Switch to non-root user
USER appuser

# Add healthcheck (address informational issue)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/fcs_cli_iac_scan.sh --help > /dev/null || exit 1

# Set security labels
LABEL maintainer="your-email@crowdstrike.com"
LABEL version="1.0"
LABEL security="SCANNED"
LABEL description="CrowdStrike FCS IaC Scanner"

# Set environment variables
ENV HOME=/home/appuser
ENV PATH="/usr/local/bin:${PATH}"

# Default command - change to workspace directory and run scan
ENTRYPOINT ["/bin/sh", "-c", "cd /workspace && /usr/local/bin/fcs_cli_iac_scan.sh"]
