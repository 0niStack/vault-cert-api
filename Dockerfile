FROM python:3.12-slim

# Create a dedicated, non-root, non-login user for the app.
RUN groupadd --gid 10001 certapi \
    && useradd --uid 10001 --gid certapi --no-create-home --shell /usr/sbin/nologin certapi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Own the app directory as the non-root user.
RUN chown -R certapi:certapi /app

USER certapi

# Internal only — this port is never published to the host (see
# docker-compose.yml). Nginx and other containers reach it over the
# Docker network by service name.
EXPOSE 8080

# 1 workers is plenty for a low-traffic, read-only certificate endpoint.
# UvicornWorker is required to run an ASGI app (FastAPI) under Gunicorn.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "15", \
     "-k", "uvicorn.workers.UvicornWorker", "app:app"]
