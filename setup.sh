#!/bin/sh
# Submarine sync server — make .env from .env.example with random secrets.
# Does nothing to an .env that is already there.
set -eu
cd "$(dirname "$0")"

if [ -e .env ]; then
    echo ".env is already there; nothing changed."
    exit 0
fi

secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$1"
    else
        head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

umask 077
sed -e "s/^SUBMARINE_DB_PASSWORD=$/SUBMARINE_DB_PASSWORD=$(secret 24)/" \
    -e "s/^MARIADB_ROOT_PASSWORD=$/MARIADB_ROOT_PASSWORD=$(secret 24)/" \
    -e "s/^SUBMARINE_TOKEN_PEPPER=$/SUBMARINE_TOKEN_PEPPER=$(secret 32)/" \
    .env.example > .env

echo "Made .env with random secrets (readable only by you)."
echo "Next:"
echo "  docker compose up -d"
echo "  docker compose exec app php bin/admin.php invite you@example.com"
