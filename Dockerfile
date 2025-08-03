# Use an official lightweight Python runtime as base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.9.0 \
    PYTHONPATH=/app/src

# Install build dependencies and curl (if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside container
WORKDIR /app

# Copy only necessary files for dependency installation first
COPY pyproject.toml poetry.lock* /app/

# Install Poetry package manager
RUN python3 -m pip install --upgrade pip && python3 -m pip install poetry

ENV PATH="/root/.local/bin:$PATH"

# Install project dependencies (without dev to keep image small)
RUN poetry config virtualenvs.create false
RUN poetry install --no-root

# Copy application source code
COPY src /app/src

# Expose the port your FastAPI app will run on
EXPOSE 8000

# Run the app with uvicorn
CMD ["uvicorn", "bashman.main:app", "--host", "0.0.0.0", "--port", "8000"]
