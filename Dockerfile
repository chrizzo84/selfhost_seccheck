FROM python:3.13-slim

LABEL org.opencontainers.image.title="SelfHost SecCheck" \
      org.opencontainers.image.description="Security checks for self-hosted software" \
      org.opencontainers.image.source="https://github.com/chrizzo84/selfhost-seccheck" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECCHECK_DATA_DIR=/app/data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY seccheck ./seccheck
COPY static ./static
# [full] adds sslyze for complete cipher-suite enumeration. If its native
# wheels are missing for this platform, fall back to the base installation.
RUN (pip install --no-cache-dir '.[full]' || pip install --no-cache-dir .) \
    && useradd --system --uid 10001 seccheck \
    && mkdir -p /app/data && chown seccheck /app/data

USER seccheck
VOLUME /app/data
EXPOSE 8000
CMD ["uvicorn", "seccheck.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
