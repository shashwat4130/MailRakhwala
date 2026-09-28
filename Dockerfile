# ==============================================================================
# Multi-stage Dockerfile for MailRakhwala
# Stage 1: Build the React / Vite frontend
# Stage 2: Production Python runtime with TShark & FastAPI
# ==============================================================================

# ------------------------------------------------------------------------------
# STAGE 1: Frontend Build
# ------------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Install dependencies first for Docker layer caching
COPY frontend/package*.json ./
RUN npm ci

# Copy frontend source and build production bundle
COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------------------------
# STAGE 2: Python Runtime + TShark Dissection Engine
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install TShark (Wireshark CLI), packet capture libraries, compiler & curl
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       tshark \
       libpcap-dev \
       gcc \
       curl \
    && rm -rf /var/lib/apt/lists/*

# Verify tshark installation
RUN tshark -v

WORKDIR /app

# Install Python backend dependencies
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend application, security rules catalog, and pre-built frontend
COPY backend/ /app/backend/
COPY rules/ /app/rules/
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

WORKDIR /app/backend

# Ensure upload directory exists
RUN mkdir -p /app/backend/data/uploads

# Configure environment defaults
ENV PYTHONPATH=/app/backend \
    RULES_DIR=/app/rules \
    STATIC_DIR=/app/frontend/dist \
    APP_ENV=production \
    PORT=8001

EXPOSE 8001

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8001}/health || exit 1

# Launch FastAPI via Uvicorn (adapting dynamically to platform-provided $PORT)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
