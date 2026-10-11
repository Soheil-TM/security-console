FROM node:22-slim AS ui

WORKDIR /ui
COPY frontend/package.json frontend/vite.config.js frontend/index.html ./
COPY frontend/src ./src
RUN npm install && npm run build

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir \
        flask==3.1.2 \
        docker==7.1.0 \
        PyJWT==2.10.1 \
        argon2-cffi==23.1.0 \
        "psycopg[binary]==3.2.9"

WORKDIR /app
COPY app.py /app/app.py
COPY security_console /app/security_console
COPY templates /app/templates
COPY --from=ui /ui/dist /app/static
EXPOSE 8080
ENTRYPOINT ["python", "/app/app.py"]
