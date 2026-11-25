FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code.
COPY pcapdiff ./pcapdiff
COPY wsgi.py ./wsgi.py
COPY app.py ./app.py

# Run as an unprivileged user; /data holds uploads + per-run SQLite DBs.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data
USER appuser

ENV PCAPDIFF_VAR_DIR=/data
EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=4)" || exit 1

# Two workers / four threads keep concurrent uploads responsive.  Analysis is
# streaming and disk-backed, so worker memory stays bounded by SQLite cache.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "600", "--graceful-timeout", "60", "wsgi:app"]
