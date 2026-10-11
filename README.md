# Security console

A web page for running Semgrep, Checkov, and Trivy, and for reading a SonarQube summary and Falco alerts. Sign-in uses an HttpOnly cookie. Passwords are not stored in the source.

## Start on any server

On a server that has Docker and Docker Compose:

```bash
git clone https://github.com/Soheil-TM/security-console.git
cd security-console
./scripts/init-secrets.sh
docker compose up -d --build
```

The page opens on port 8091. The first account is `admin` with password `admin`. After the first sign-in the console stays closed until that password is replaced. The new password must be at least 12 characters, typed twice.

Semgrep, Checkov, Trivy, and SonarQube each start a short-lived container through the Docker socket on that server, and pull the scanner image when it is missing. Point SonarQube at its server:

```bash
SONAR_URL=https://sonar.example.com SONAR_PROJECT_KEY=my-project docker compose up -d --build
```

Put the SonarQube token in `secrets/sonar_token.txt`. Without that file, the other scanners still run and SonarQube is skipped.

## Secrets

Create these files and keep them out of git, or run `./scripts/init-secrets.sh`:

- `secrets/console_db_password.txt`
- `secrets/console_jwt_key.txt` — at least 32 characters
- `secrets/falco_ingest_token.txt`

`init-secrets.sh` also writes `secrets/console_admin_password.txt` so Compose can mount it. That file is not the sign-in password. The first sign-in is always username `admin` and password `admin`, and it must be changed before the console opens. The account is created only when the user table is empty. On an existing database, the `admin` account is switched to that password once.

## Docker

`docker compose up --build` starts a Postgres database for the console and the console itself on port 8091.

## Docker Swarm

The image `security-console:17` must be on work-01. Deploy it with:

```bash
docker stack deploy -c docker-stack.yml --resolve-image never console
```

On this cluster the user database is `security_console_db` on the Postgres instance that SonarQube already uses. The console connects as the `console` role, not as the SonarQube application role.

## Kubernetes

The manifest `deploy/kubernetes/console.yaml` starts the same image with its own Postgres. Replace every `CHANGE_ME` value. `COOKIE_SECURE` is on there, so TLS must sit in front of the console.

Starting a scan still creates a Docker container through the Docker socket. Without that socket, sign-in and saved results work, and starting a scan returns an error.

## Tests

```bash
DATABASE_URL=postgresql://console:console@127.0.0.1:5432/security_console_db \
CONSOLE_JWT_KEY=test-jwt-key-must-be-32-characters \
FALCO_INGEST_TOKEN=falco-test-token \
pytest
```
