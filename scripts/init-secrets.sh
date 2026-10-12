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
write_if_missing secrets/sonar_db_password.txt 18

if [ ! -f secrets/sonar_token.txt ]; then
  : > secrets/sonar_token.txt
  chmod 600 secrets/sonar_token.txt
  echo "created empty secrets/sonar_token.txt"
fi

if [ ! -s secrets/sonar-db.env ]; then
  password=$(cat secrets/sonar_db_password.txt)
  printf 'SONAR_JDBC_PASSWORD=%s\n' "$password" > secrets/sonar-db.env
  chmod 600 secrets/sonar-db.env
  echo "created secrets/sonar-db.env"
fi

echo "First sign-in is username admin and password admin."
echo "Change that password before exposing the console. It is not written to a log."
echo "SonarQube first sign-in is admin / admin on port 9000."
echo "Create a token there, write it to secrets/sonar_token.txt, then restart the scanner."
map_count=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$map_count" -lt 262144 ]; then
  echo "SonarQube needs vm.max_map_count >= 262144. Current value is $map_count."
  echo "Run: sudo sysctl -w vm.max_map_count=262144"
fi
