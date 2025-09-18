# M365 Big Brain Crawl - Production Container
# Multi-stage build for optimized deployment

# Stage 1: Builder
FROM python:3.11-slim AS builder

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN uv venv /venv && \
    /venv/bin/pip install --upgrade pip && \
    /venv/bin/pip install -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /venv /venv

# Set environment variables
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AZURE_FUNCTIONS_ENVIRONMENT=Production \
    FUNCTIONS_WORKER_RUNTIME=python

# Create non-root user
RUN useradd -m -u 1000 funcuser

# Set working directory
WORKDIR /home/funcuser

# Copy function app code
COPY --chown=funcuser:funcuser . .

# Switch to non-root user
USER funcuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/api/health || exit 1

# Expose port (Azure Functions default)
EXPOSE 80

# Entry point for Azure Functions
CMD ["python", "-m", "azure.functions", "start", "--python", "--host", "0.0.0.0", "--port", "80"]