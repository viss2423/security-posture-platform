FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
ARG OSV_SCANNER_VERSION=v2.3.3
ARG TRIVY_VERSION=0.69.3
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl tar && \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" -o /usr/local/bin/osv-scanner && \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/trivy && \
    apt-get purge -y --auto-remove curl && \
    rm -rf /var/lib/apt/lists/* /tmp/trivy.tar.gz
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py dependency_scan.py trivy_scan.py scans.py main.py ./

ENTRYPOINT ["python", "-u", "main.py"]
