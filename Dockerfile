# Multi-stage build for smaller image size
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final stage
FROM python:3.11-slim

# Set metadata
LABEL maintainer="VulnX Security Scanner"
LABEL description="VulnX - Real-time Port Analysis & Security Scanner"
LABEL version="1.0"

# Create non-root user for security
RUN groupadd -r vulnx && useradd -r -g vulnx -s /bin/bash vulnx

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/vulnx/.local

# Copy application code
COPY --chown=vulnx:vulnx . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/data && \
    chown -R vulnx:vulnx /app && \
    chmod -R 755 /app

# Update PATH to include user site-packages
ENV PATH=/home/vulnx/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER vulnx

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Set working directory to src for proper module imports
WORKDIR /app/src

# Run the application with gunicorn
CMD ["gunicorn", \
    "--chdir", "/app/src", \
    "app:app", \
    "--bind", "0.0.0.0:8000", \
    "--workers", "1", \
    "--worker-class", "gthread", \
    "--threads", "4", \
    "--timeout", "120", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "--log-level", "info"]
