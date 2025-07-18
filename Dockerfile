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
