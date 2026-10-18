# Shadowprint — Model Context Protocol Security Auditor & Exploit Knowledge Graph
# Hackathon Track 01: Agents That Act on Connected Data
# Co-builders: Gaurang Udgirkar & Jasjyot Singh

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FALKORDB_HOST=falkordb \
    FALKORDB_PORT=6379

WORKDIR /app

# Install minimal system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source repository
COPY . /app

# Install shadowprint package in editable mode
RUN pip install --no-cache-dir -e .

# Pre-generate dashboard data and ensure output directory
RUN mkdir -p output && python dashboard/generate_data.py

EXPOSE 8080 6379

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

# Default command: launch the unified starter server
CMD ["python", "start.py", "--host", "0.0.0.0", "--port", "8080"]
