# Lint: docker run --rm -i hadolint/hadolint < Dockerfile
FROM python:2.7-slim

# python:2.7-slim is based on Debian Buster (EOL), so the official mirrors are
# replaced with archive.debian.org to allow apt-get to function.
RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g; \
            s|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g; \
            /buster-updates/d' /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
        libusb-1.0-0=2:1.0.22-2 \
        usbutils=1:010-3 && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pyusb==1.1.0 scapy==2.5.0

WORKDIR /app
