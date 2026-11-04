# syntax=docker/dockerfile:1
# OpenSOC ai-triage. Supply chain (OWASP LLM03): dependencies are installed from a
# hash-pinned lock file; pin the base image by digest in production, e.g.
#   docker build --build-arg PYTHON_IMAGE=python:3.13-slim@sha256:<digest> .
ARG PYTHON_IMAGE=python:3.13-slim

FROM ${PYTHON_IMAGE} AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.lock /tmp/requirements.lock
# Optional extra CA for TLS-inspecting proxies (never stored in a layer):
#   docker build --secret id=pip_ca,src=/path/to/ca-bundle.crt .
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r /tmp/requirements.lock \
 && /opt/venv/bin/pip uninstall -y pip

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="opensoc-ai-triage" \
      org.opencontainers.image.description="LLM triage of Wazuh alerts with RAG over SOC runbooks" \
      org.opencontainers.image.licenses="MIT"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    TRIAGE_HOST=0.0.0.0 \
    TRIAGE_PORT=8000 \
    TRIAGE_RUNBOOKS_DIR=/app/runbooks \
    TRIAGE_AUDIT_LOG_PATH=/var/log/ai-triage/audit.jsonl
RUN groupadd --system --gid 10001 triage \
 && useradd --system --uid 10001 --gid triage --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin triage \
 && install -d -o triage -g triage -m 0750 /var/log/ai-triage
COPY --from=deps /opt/venv /opt/venv
# Code and runbooks stay owned by root: the service user can read but not modify them.
COPY src /app/src
COPY runbooks /app/runbooks
USER 10001:10001
WORKDIR /app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('TRIAGE_PORT', '8000'), timeout=3).status == 200 else 1)"]
CMD ["python", "-m", "ai_triage"]
