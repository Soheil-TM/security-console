#!/bin/sh
# Create the secret files Compose needs. Existing files are left as they are.
# The first console login is not one of these files.
set -eu
cd "$(dirname "$0")/.."
mkdir -p secrets
umask 077

write_if_missing() {
  file=$1
  bytes=$2
  if [ -f "$file" ]; then
    return
  fi
  python3 -c 'import secrets,sys; print(secrets.token_urlsafe(int(sys.argv[1])))' "$bytes" > "$file"
  chmod 600 "$file"
  echo "created $file"
}

write_if_missing secrets/console_db_password.txt 18
write_if_missing secrets/console_jwt_key.txt 32
write_if_missing secrets/falco_ingest_token.txt 18
write_if_missing secrets/scanner_token.txt 24

echo "First sign-in is username admin and password admin."
echo "Change that password before exposing the console. It is not written to a log."
