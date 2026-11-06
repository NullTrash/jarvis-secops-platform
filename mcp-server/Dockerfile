FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application source
COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
ENV ELASTIC_HOST=elasticsearch
ENV ELASTIC_PORT=9200

# Run FastMCP server
CMD ["python", "-m", "src.server"]
