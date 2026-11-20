# AgentCore Runtime requires linux/arm64 images. CI builds with:
#   docker buildx build --platform linux/arm64 ...
# Local docker-compose builds for your native arch (works the same).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DOCKER_CONTAINER=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY config ./config

# Baked in at build time so every response says exactly which build produced it.
ARG AGENT_VERSION=dev
ENV AGENT_VERSION=${AGENT_VERSION}
LABEL org.opencontainers.image.revision=${AGENT_VERSION}

RUN useradd --create-home --uid 1000 agent
USER agent

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ping', timeout=2)" || exit 1

CMD ["python", "-m", "app.main"]
