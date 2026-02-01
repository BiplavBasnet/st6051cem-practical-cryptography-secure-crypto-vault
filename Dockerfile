# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create work directory and set permissions
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user
RUN useradd -m appuser

# Pre-create state directories and set ownership
RUN mkdir -p data keys pki tsa && chown -R appuser:appuser /app

# Copy the rest of the application code with perms
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Default command
CMD ["python", "secure_crypt_cli.py"]
