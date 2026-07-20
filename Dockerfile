# Multi-stage Dockerfile for the Adaptive Privacy Observatory backend.
# Serves the FastAPI application and the dashboard static files.
#
# Build:  docker build -t apo-backend .
# Run:    docker run -p 8000:8000 apo-backend

FROM python:3.12-slim AS base

# Prevent Python from writing pyc files and enable unbuffered output.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# -- Dependencies ---------------------------------------------------------
FROM base AS deps

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -- Application ----------------------------------------------------------
FROM deps AS app

# Copy backend source.
COPY backend/ ./backend/

# Copy dashboard static files.
COPY dashboard/ ./dashboard/

WORKDIR /app/backend

# Health check — probes the /api/health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

# Expose the server port.
EXPOSE 8000

# Default environment variables (can be overridden).
ENV APO_HOST=0.0.0.0 \
    APO_PORT=8000 \
    APO_LOG_LEVEL=info

# Run the server.
CMD ["python", "main.py"]
