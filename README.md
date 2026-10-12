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

The page opens on port 8091. This Compose file is local development: `CONSOLE_ENV=development` and plain HTTP. The first account is `admin` with password `admin`. The server rejects every user API call except reading the session, refreshing it, logging out, and changing the password until that password is replaced. The Falco ingest webhook is separate and still uses its own token. The new password must be at least 12 characters, typed twice. Do not expose port 8091 to an untrusted network before that change. Restarting the process or signing in again does not clear the requirement, and an existing database is never reset to password `admin`.

The console container does not mount the Docker socket. A scanner service on the same machine does, and it only accepts approved scan jobs from the console. Semgrep, Checkov, Trivy, and the Sonar scanner each start a short-lived container from that service.

SonarQube Community Build and its own Postgres start with the rest of the stack. The site is not published on port 9000. Open it from the console at `/sonar/` after an admin turns on SonarQube workspace for that account. SonarQube still has its own login. The first SonarQube account is `admin` / `admin`. Create a user token there, put that token in `secrets/sonar_token.txt`, and restart the scanner:

```bash
docker compose up -d scanner
```

Until that file has a token, the other scanners still run and SonarQube analysis is skipped. The host must allow Elasticsearch inside SonarQube:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Add `vm.max_map_count=262144` to `/etc/sysctl.conf` so it survives a reboot. Leave a few gigabytes free on the disk. Elasticsearch inside SonarQube stops when the disk is nearly full. Set `SONAR_PROJECT_KEY` to change the project name.

## Secrets

Create these files and keep them out of git, or run `./scripts/init-secrets.sh`:

- `secrets/console_db_password.txt`
- `secrets/console_jwt_key.txt` — at least 32 characters
- `secrets/falco_ingest_token.txt`
- `secrets/scanner_token.txt` — shared by the console and the scanner service
- `secrets/sonar_db_password.txt` — SonarQube's Postgres password
- `secrets/sonar-db.env` — the same password, for the SonarQube process
- `secrets/sonar_token.txt` — empty until you create a token in SonarQube

The account is created only when the user table is empty. Startup does not change the password of an account that already exists.

## Docker

`docker compose up --build` starts the console Postgres, SonarQube and its Postgres, the scanner, and the console on port 8091. That command also loads `docker-compose.override.yml`, which publishes `8091:8080`. SonarQube stays on the Compose network.

Production is `docker-compose.yml` plus `docker-compose.production.yml`, and only those two files:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
```

Do not add `docker-compose.override.yml` to that list. Compose appends port lists, so the development publish would sit beside the production one. The production command sets `CONSOLE_ENV=production` and `COOKIE_SECURE=1`, and the rendered console port is `127.0.0.1:8091:8080`. The process refuses to start in production when `COOKIE_SECURE` is not `1`. Put TLS on the proxy. Point `TRUSTED_PROXIES` at the proxy address the console sees, and configure the proxy to set `X-Forwarded-For` to the client address. The console ignores that header from every other address. It does not turn cookie security on or off from `X-Forwarded-Proto`.

```nginx
log_format console_no_agent '$remote_addr - [$time_local] "$request" '
    '$status $body_bytes_sent';

server {
    listen 443 ssl;
    location /api/falco {
        access_log /var/log/nginx/access.log console_no_agent;
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
    location / {
        proxy_pass http://127.0.0.1:8091;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

The `/api/falco` log format omits `$http_user_agent`, `$http_authorization`, and `$http_x_falco_token`. Falco 0.45 can only send the ingest token as the User-Agent. A sensor that can set headers should send `X-Falco-Token` or `Authorization: Bearer` instead. When either of those headers is present, the User-Agent is not accepted as the token. Failed ingest calls are limited to 5 per minute per address, and all ingest calls are limited to 120 per minute.

Keep port 8080 inside the container unpublished except through that proxy. Put TLS on that proxy as well. SonarQube is reached through the console at `/sonar/`, so the proxy does not need a separate port 9000.

## Security

Application controls (authentication, the password gate, CSRF, session invalidation, scanner request validation, container restrictions, and SSRF checks on clone URLs) are the same in development and production. Development may use HTTP. Production may not.

The console and the scanner are split so a request to the web process cannot call the Docker API. Scanner containers drop all Linux capabilities, set `no-new-privileges`, use a read-only root filesystem where the tool allows it, and do not receive the Docker socket or the console's secrets. Semgrep and Checkov run as uid 65534. Set `SCANNER_FORCE_ROOT=1` on the scanner if one of those images cannot run as that user. Trivy and SonarQube still run as the image user, because Trivy writes its cache and SonarQube writes the project directory.

Repository URLs may use an internal RFC1918 git server. Loopback, link-local, `100.64.0.0/10`, and known metadata addresses are rejected. Image references follow the same address rules. A short name such as `nginx:1.27` remains a Docker Hub reference. `localhost` is not an accepted registry host. Set `SCANNER_NETWORK` to a Docker network whose egress you have already filtered when the default bridge is too open.

The first password is `admin` only so a controlled first install can sign in. Change it before the console is reachable from an untrusted network. The server stores that requirement in the database, so a new browser, a restart, or a refresh cannot skip it. Secret files created by `scripts/init-secrets.sh` are mode 600. Keep `secrets/` off the web root and out of git. The console entrypoint copies them to `/run/console-secrets` for uid 10001 and does not change the host files. The scanner worker stays root and reads its own mount directly.

### Residual risks

These three limits are still present after the application controls above. Passing the test suite does not remove them.

**Scanner Docker socket.** The worker process mounts `/var/run/docker.sock`. A compromise of that process is a compromise of the Docker host, because the socket can create a privileged container. Do not publish port 8092, and do not treat the current split as a production sandbox. The current layout is acceptable only when the Docker host is dedicated to this console and is not shared with unrelated production containers.

Operational mitigation: run the scanner daemon on its own virtual machine, with its own Docker daemon, and point `SCANNER_URL` at that machine over a management network that users cannot reach. Keep the socket on that virtual machine only. This repository does not create the virtual machine. Where a separate machine is not available yet, run the scanner under rootless Docker (`dockerd-rootless-setuptool.sh`, socket owned by an unprivileged user). A container started from that daemon does not receive host root. Rootless mode still exposes every container that daemon runs, so it is the weaker of the two options.

**Git address pinning depends on libcurl.** Clone disables HTTP redirects and passes `http.curloptResolve` for each address that was accepted. That option is honored when Git is built with libcurl, which is the normal Debian and Ubuntu `git` package. A Git build that ignores it resolves the name again at connect time, so DNS rebinding is not fully closed. Confirm the worker image's Git with `git version --build-options` and look for `libcurl`. Do not describe the pin as a complete rebinding control.

**Falco 0.45 sends the ingest token in the User-Agent.** The application prefers `X-Falco-Token` or `Authorization: Bearer` and uses the User-Agent only when both are absent. Falco 0.45 cannot set those headers, so any proxy, ingress, or load balancer that logs `$http_user_agent` stores the credential. The nginx example on this page uses `log_format console_no_agent` for `location /api/falco` and omits `$http_user_agent`, `$http_authorization`, and `$http_x_falco_token`. Apply the same omission on every other hop that logs that location. When the sensor can set a header, send `X-Falco-Token` and stop putting the token in the User-Agent.

**Cloud metadata from a scanner container.** `extra_hosts` pins `metadata.google.internal` and `metadata.google` to loopback. It does not stop a raw connection to `169.254.169.254`. Block that address on the Docker host, in the `DOCKER-USER` chain, so forwarded container traffic is dropped before it leaves the bridge:

```bash
iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP
ip6tables -I DOCKER-USER -d fd00:ec2::254/128 -j DROP
```

Persist the rules with the host's firewall tool (`iptables-persistent`, `nftables`, or the cloud security group). Also drop `169.254.169.254` in the host `OUTPUT` chain if untrusted processes run outside Docker. An allow-list for the scanner network is stronger than these two drops.

### SonarQube token and project file

`sonar-scanner-cli` 12.2 reads `SONAR_TOKEN` from its process environment. It does not accept the token on stdin or from a token file of its own. Putting the value in Docker's `environment` field stores it in `docker inspect` (`Config.Env`). The worker therefore writes the token to a file in a mode `0700` directory, bind-mounts that file read-only at `/run/secrets/sonar_token` (mode `0444` so the image user can read it), and starts `/bin/sh` which exports `SONAR_TOKEN` only inside the container process. The value is not in `Config.Env` or in the process arguments. It is still in `/proc/<pid>/environ` for the life of the scan, and the file remains on the worker until the scan function returns and deletes it. Anyone who can `docker exec` into that container, or read the worker's scan directory as root while the scan is running, can read the token. That is the boundary the scanner's own configuration leaves.

Command-line `-D` properties outrank `sonar-project.properties`. The scanner command pins `sonar.host.url`, clears `sonar.scanner.proxyHost`, `proxyPort`, `proxyUser`, and `proxyPassword`, sets `sonar.scanner.javaOpts` to the memory limit only, and clears `sonar.scanner.truststorePath`, `truststorePassword`, `keystorePath`, and `keystorePassword`. A repository file cannot replace those with another server, an HTTP proxy, a JVM proxy flag, or a private trust store. Other unpinned properties can still change. The token is not passed as `sonar.token` on the command line.

## Tests

```bash
DATABASE_URL=postgresql://console:console@127.0.0.1:5432/security_console_db \
CONSOLE_JWT_KEY=test-jwt-key-must-be-32-characters \
FALCO_INGEST_TOKEN=falco-test-token \
pytest
```
