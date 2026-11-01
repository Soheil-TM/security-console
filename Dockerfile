FROM node:22-slim AS ui

WORKDIR /ui
COPY frontend/package.json frontend/vite.config.js frontend/index.html ./
COPY frontend/src ./src
RUN npm install && npm run build

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 console \
    && useradd --system --uid 10001 --gid 10001 --home-dir /home/console --create-home console \
    && pip install --no-cache-dir \
        flask==3.1.2 \
        docker==7.1.0 \
        PyJWT==2.10.1 \
        argon2-cffi==23.1.0 \
        "psycopg[binary]==3.2.9"

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY app.py /app/app.py
COPY security_console /app/security_console
COPY templates /app/templates
COPY entrypoint.sh /app/entrypoint.sh
COPY --from=ui /ui/dist /app/static
# Self-hosted fonts (after UI dist so they are not overwritten).
COPY static/fonts /app/static/fonts
RUN chmod 755 /app/entrypoint.sh
EXPOSE 8080
# Starts as root only to chown secrets/data; entrypoint then drops to uid 10001.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4)"
ENTRYPOINT ["/app/entrypoint.sh"]
