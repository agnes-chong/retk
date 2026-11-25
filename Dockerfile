# retk: static reverse-engineering toolkit. This image gives you a ready-to-run
# install (no WSL/apt dance) and, just as importantly, a sandbox: the file you
# analyze never touches your host, only this container's filesystem.
#
# Ubuntu, not Debian/python:slim: radare2 isn't packaged for current Debian
# (trixie) but is available in Ubuntu's repos.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip \
        file binutils radare2 binwalk upx-ucl yara default-jre-headless \
        curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-ai.txt ./
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt -r requirements-ai.txt
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

# capa's rule pack (see setup.sh for the non-Docker equivalent)
RUN curl -sSL -o /tmp/capa-rules.zip \
        https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip \
    && unzip -q /tmp/capa-rules.zip -d /tmp/capa-rules-extract \
    && mv /tmp/capa-rules-extract/capa-rules-master /app/.capa-rules \
    && rm -rf /tmp/capa-rules.zip /tmp/capa-rules-extract

ENV CAPA_RULES_DIR=/app/.capa-rules
EXPOSE 5000

ENTRYPOINT ["python3", "retk_cli.py"]
CMD ["gui", "--host", "0.0.0.0"]
