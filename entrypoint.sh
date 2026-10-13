#!/bin/sh
# Root is used only to hand /data and the secret copies to the console user.
# The process then drops privileges. The scanner worker overrides this
# entrypoint and stays root because it has to open the Docker socket.
set -eu
if [ "$(id -u)" != "0" ]; then
  exec python /app/app.py
fi
mkdir -p /data
chown -R 10001:10001 /data
if [ -d /run/secrets ]; then
  # Compose mounts the host files with their mode, usually 600, so uid 10001
  # cannot read them. Copy the bytes to a directory this user owns. The host
  # files are left unchanged.
  python - <<'PY'
import os
from pathlib import Path

source = Path("/run/secrets")
destination = Path("/run/console-secrets")
destination.mkdir(mode=0o700, exist_ok=True)
os.chown(destination, 10001, 10001)
env_path = Path("/run/console-secret-env")
lines = []
for item in source.iterdir():
    if not item.is_file():
        continue
    target = destination / item.name
    target.write_bytes(item.read_bytes())
    os.chmod(target, 0o400)
    os.chown(target, 10001, 10001)
for key, value in os.environ.items():
    prefix = "/run/secrets/"
    if key.endswith("_FILE") and value.startswith(prefix):
        lines.append(f"{key}={destination / value[len(prefix):]}")
env_path.write_text("\n".join(lines) + ("\n" if lines else ""))
os.chmod(env_path, 0o600)
PY
  set -a
  # shellcheck disable=SC1091
  . /run/console-secret-env
  set +a
  rm -f /run/console-secret-env
fi
# Sonar setup files are bind-mounted from the host. The console user has to
# read the status and replace the token when an admin rotates it.
for file in /run/sonar/admin_password /run/sonar/token /run/sonar/status; do
  if [ -f "$file" ]; then
    chown 10001:10001 "$file"
    chmod 600 "$file"
  fi
done
if [ -f /run/sonar/db_password ]; then
  mkdir -p /run/sonar-private
  cp /run/sonar/db_password /run/sonar-private/db_password
  chown 10001:10001 /run/sonar-private /run/sonar-private/db_password
  chmod 700 /run/sonar-private
  chmod 400 /run/sonar-private/db_password
  export SONAR_DB_PASSWORD_FILE=/run/sonar-private/db_password
fi
exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all python /app/app.py
