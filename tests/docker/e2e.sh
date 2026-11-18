#!/bin/sh
# End-to-end check of the Docker setup, from the repository's folder, on a
# machine with Docker, PHP (cli + curl) and curl:
#
#   SUBMARINE_TEST_DISPOSABLE=1 sh tests/docker/e2e.sh
#
# It runs its own compose project ("submarine-e2e") with its own settings file
# (made in a temporary folder, random secrets, a test admin password), its own
# image tag (submarine-sync-server:e2e) and its own ports (127.0.0.1:18080, and
# 18443 for Caddy with its own test CA). It never reads or changes .env, and it
# never touches the project you run for real. At the end it removes its
# containers and volumes (keep them with SUBMARINE_E2E_KEEP=1).
set -u
if [ "${SUBMARINE_TEST_DISPOSABLE:-}" != "1" ]; then
    echo "This starts and removes a test stack (project submarine-e2e). Set SUBMARINE_TEST_DISPOSABLE=1 to go on." >&2
    exit 2
fi
cd "$(dirname "$0")/../.."
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
is() { if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got '$2', expected '$3'"; fi; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
secret() { openssl rand -hex "$1" 2>/dev/null || head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

WORK=$(mktemp -d)
ENVF="$WORK/e2e.env"
ADMIN_PW="e2e admin $(secret 8)"
cat > "$ENVF" <<EOF
SUBMARINE_IMAGE=submarine-sync-server:e2e
SUBMARINE_DB_PASSWORD=$(secret 16)
MARIADB_ROOT_PASSWORD=$(secret 16)
SUBMARINE_TOKEN_PEPPER=$(secret 32)
SUBMARINE_HTTP_PORT=18080
SUBMARINE_TRUSTED_PROXIES=caddy
SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL=1
SUBMARINE_TOKEN_TTL_DAYS=30
SUBMARINE_QUOTA_RECORDS=12345
SUBMARINE_QUOTA_PROFILES=77
SUBMARINE_QUOTA_SHARES=7
SUBMARINE_MAIL_PER_HOUR=66
SUBMARINE_SMTP_VERIFY_PEER=false
SUBMARINE_KEYS_NEED_PASSWORD=false
EOF
chmod 600 "$ENVF"
dc="docker compose -p submarine-e2e --env-file $ENVF -f docker-compose.yml"
dch="$dc -f tests/docker/https-test.yml --profile https"
cleanup() {
    if [ "${SUBMARINE_E2E_KEEP:-}" != "1" ]; then
        $dch down -v --remove-orphans >/dev/null 2>&1
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
healthy() {
    for i in $(seq 1 60); do
        [ "$(docker inspect -f '{{.State.Health.Status}}' "$($dc ps -q app)" 2>/dev/null)" = healthy ] && return 0
        sleep 3
    done
    return 1
}

echo "---- build and start (project submarine-e2e)"
$dc build -q app || exit 1
$dc up -d || exit 1
healthy
HASH=$($dc exec -T app php -r 'echo password_hash($argv[1], PASSWORD_DEFAULT);' "$ADMIN_PW")
echo "SUBMARINE_ADMIN_PASSWORD_HASH='$HASH'" >> "$ENVF"
$dc up -d
healthy
is "app healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$($dc ps -q app)")" healthy

echo "---- every setting reaches the app"
GOT=$($dc exec -T app php -r 'require "src/lib/Bootstrap.php"; Submarine\Lib\Bootstrap::registerAutoload();
  $c = Submarine\Lib\Config::load("/var/www/submarine");
  echo json_encode([$c["token_ttl_seconds"], $c["quota"]["records"], $c["quota"]["share_records"], $c["quota"]["profiles"],
    $c["quota"]["shares"], $c["mail"]["per_hour"], $c["mail"]["smtp_verify_peer"], $c["admin"]["allow_http_local"],
    $c["security"]["keys_need_password"], $c["security"]["trusted_proxies"], $c["admin"]["password_hash"] !== ""]);' | tr -d '\r')
is "TTL, quotas, mail cap, verify-peer, panel, keys, proxies" "$GOT" '[2592000,12345,12345,77,7,66,false,true,false,["caddy"],true]'

echo "---- smoke test over http://127.0.0.1:18080"
SUBMARINE_TEST_URL=http://127.0.0.1:18080 SUBMARINE_TEST_ADMIN_CMD="$dc exec -T app php bin/admin.php" \
  php tests/smoke-test.php || fails=$((fails + 1))

echo "---- what is served"
for p in /.htaccess /.user.ini /index.php /src/api.php /bin/admin.php /config.example.php /schema.sql /../config.php; do
  c=$(code "http://127.0.0.1:18080$p")
  case "$c" in 403|404) pass "$p not served ($c)";; *) fail "$p answered $c";; esac
done
is "an unknown path is the API's JSON 404" "$(curl -s http://127.0.0.1:18080/nothing | head -c 20)" '{"error":"no_route",'
is "Server header says only Apache" "$(curl -s -D - -o /dev/null http://127.0.0.1:18080/health | tr -d '\r' | grep -i '^server:' | cut -d' ' -f2-)" "Apache"
is "no X-Powered-By" "$(curl -s -D - -o /dev/null http://127.0.0.1:18080/health | grep -ci '^x-powered-by')" 0
is "a sync body over 6 MB is refused by Apache" "$(head -c 7000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:18080/sync)" 413

echo "---- the admin panel over plain http (SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL=1 here)"
is "at http://127.0.0.1:18080/admin (this machine): the sign-in page" "$(curl -s http://127.0.0.1:18080/admin | grep -c 'Admin password')" 1
is "with another host name: refused" "$(code -H 'Host: sync.example.test' http://127.0.0.1:18080/admin)" 403
is "through a proxy (X-Forwarded-For), even to localhost: refused" "$(code -H 'X-Forwarded-For: 203.0.113.9' http://127.0.0.1:18080/admin)" 403

CADDYLESS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$($dc ps -q app)")
is "the panel knows the host's connections come from the gateway ($CADDYLESS_IP)" \
  "$($dc exec -T app php -r 'require "src/lib/Bootstrap.php"; Submarine\Lib\Bootstrap::registerAutoload(); echo Submarine\Lib\Util::dockerGateway();' | tr -d '\r')" "$CADDYLESS_IP"
is "another container saying Host: localhost is not this machine" \
  "$($dc exec -T db bash -c 'exec 3<>/dev/tcp/app/8080 && printf "GET /admin HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3 && head -n 1 <&3' 2>/dev/null | tr -d '\r' | cut -d' ' -f2)" 403

echo "---- the container"
for s in app db cron; do
  is "$s keeps at most 3 log files of 10 MB" "$(docker inspect -f '{{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config "max-size"}} {{index .HostConfig.LogConfig.Config "max-file"}}' "$($dc ps -q $s)")" "json-file 10m 3"
done
is "runs as www-data" "$($dc exec -T app id -un | tr -d '\r')" www-data
is "read-only file system" "$($dc exec -T app sh -c 'touch /var/www/submarine/x 2>/dev/null && echo writable || echo read-only' | tr -d '\r')" read-only
is "the database has no published port" "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$($dc ps -q db)")" "{}"
is "the app port is on 127.0.0.1 only" "$(docker port "$($dc ps -q app)" 8080 | head -1 | cut -d: -f1)" 127.0.0.1
is "the access log leaves out query strings" "$($dc logs --no-color app 2>/dev/null | grep -c 'token=')" 0
is "the access log has the verify request" "$([ "$($dc logs --no-color app 2>/dev/null | grep -c '/auth/verify ')" -gt 0 ] && echo yes)" yes
is "cron ran" "$([ "$($dc logs --no-color cron 2>/dev/null | grep -c 'expired sign-ins')" -gt 0 ] && echo yes)" yes

echo "---- through Caddy (https profile, test CA)"
$dch up -d caddy
for i in $(seq 1 30); do
  [ "$(code -k https://localhost:18443/health)" = 200 ] && break
  sleep 2
done
is "https://localhost:18443/health" "$(code -k https://localhost:18443/health)" 200
is "Caddy runs with no capabilities but NET_BIND_SERVICE" "$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$($dch ps -q caddy)")" '["ALL"] ["NET_BIND_SERVICE"]'
SUBMARINE_TEST_URL=https://localhost:18443 SUBMARINE_TEST_INSECURE=1 SUBMARINE_TEST_ADMIN_CMD="$dc exec -T app php bin/admin.php" \
  php tests/smoke-test.php || fails=$((fails + 1))
CADDY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$($dch ps -q caddy)")
curl -sk -o /dev/null https://localhost:18443/health
ROWS=$($dc exec -T db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "SELECT bucket FROM submarine.rate_limits WHERE bucket LIKE \"global:ip:%\""' | tr -d '\r')
case "$ROWS" in *"global:ip:$CADDY_IP"*) fail "rate limits count Caddy's address ($CADDY_IP), not the client's";; *) pass "rate limits count the client's address, not Caddy's ($CADDY_IP)";; esac
R='--resolve sync.example.test:18443:127.0.0.1'
is "the panel over HTTPS with a real host name" "$(curl -sk $R https://sync.example.test:18443/admin | grep -c 'Admin password')" 1
J="$WORK/cookies"
curl -sk $R -c "$J" -o /dev/null --data-urlencode "do=login" --data-urlencode "password=$ADMIN_PW" https://sync.example.test:18443/admin
is "signed in: a __Host- cookie, Secure" "$(grep -c '__Host-submarine_admin' "$J") $(awk '$6=="__Host-submarine_admin"{print $4}' "$J")" "1 TRUE"
is "the dashboard" "$(curl -sk $R -b "$J" https://sync.example.test:18443/admin | grep -c 'Invite someone')" 1
is "admin.php check lists the client addresses it saw" "$($dc exec -T app php bin/admin.php check | grep -c '^Client addresses in the last hour')" 1

echo
[ $fails -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit $fails
