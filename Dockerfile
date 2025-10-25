# Use a lightweight Python base image
FROM python:3.12-slim

# Unbuffered output, Poetry version, and ensure /app/src on PYTHONPATH
ENV PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.9.0 \
    PYTHONPATH=/app/src \
    BASHMAN_REQUIRE_AUTH=1 \
    BASHMAN_AUTO_PUBLISH=1 

# Install system build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential curl shellcheck && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project metadata and README (for Poetry)
COPY pyproject.toml poetry.lock* README.md /app/

# Copy your application code so Poetry can see it
COPY src /app/src

# Install Poetry itself
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install poetry

# Make Poetry’s bin directory available
ENV PATH="/root/.local/bin:$PATH"

# Configure Poetry to install into the container’s site-packages
RUN poetry config virtualenvs.create false

# Install runtime deps + your bashman package (skip dev group)
RUN poetry install --without dev --no-interaction --no-ansi

# Expose the FastAPI port
EXPOSE 8000

# Launch the server via Uvicorn
CMD ["uvicorn", "bashman.server.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
