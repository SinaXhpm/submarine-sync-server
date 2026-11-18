#!/bin/bash
# install.sh and the submarine-sync command, end to end, on a machine made for
# testing (a new VM is best: then install.sh installs Docker too):
#
#   sudo SUBMARINE_TEST_DISPOSABLE=1 bash tests/install/install-test.sh
#
# It installs into /opt/submarine-sync from a throwaway copy of this folder
# with test releases v9.0.0 to v9.0.3 (one of them broken on purpose), and goes
# through invitations, the admin panel, backups, restore, a wrong setting,
# update (also a failed one), running install.sh again, and uninstall. The
# domain is "localhost" (Caddy's own CA), and Caddy listens on 127.0.0.1 only.
# At the end it removes everything it made; Docker stays.
#
# It refuses to start where /opt/submarine-sync is there already. With PHP and
# its curl extension, it also runs tests/smoke-test.php over HTTPS.
set -u
if [ "${SUBMARINE_TEST_DISPOSABLE:-}" != "1" ]; then
    echo "This installs and removes a server in /opt/submarine-sync. Set SUBMARINE_TEST_DISPOSABLE=1 to go on." >&2
    exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo "Run it as root." >&2; exit 2; }
if [ -e /opt/submarine-sync ] || [ -e /usr/local/bin/submarine-sync ]; then
    echo "/opt/submarine-sync (or the submarine-sync command) is there already; this test runs only where it isn't." >&2
    exit 2
fi
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
D=/opt/submarine-sync
SS=/usr/local/bin/submarine-sync
BK=/var/backups/submarine-sync
fails=0
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
is() { if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got '$2', expected '$3'"; fi; }
gq() { git -c user.name=test -c user.email=test@example.invalid "$@"; }
api() { curl -sk --max-time 20 "$@"; }
code() { api -o /dev/null -w '%{http_code}' "$@"; }
envv() { sed -n "s/^$1=//p" "$D/.env"; }
cleanup() {
    if [ -x "$D/submarine-sync" ]; then "$D/submarine-sync" uninstall --purge --yes >/dev/null 2>&1 || true; fi
    rm -rf "$BK"
    if [ $fails -eq 0 ]; then
        rm -rf "$W" /var/log/submarine-sync-install.log
    else
        echo "Kept for a look: $W (the outputs) and /var/log/submarine-sync-install.log"
    fi
}
trap cleanup EXIT

echo "---- a throwaway origin with releases v9.0.0 and v9.0.1"
mkdir -p "$W/src"
tar -C "$REPO" --exclude=./.git --exclude=./.env --exclude=./config.php -cf - . | tar -C "$W/src" -xf -
cd "$W/src" || exit 1
find . -type f -exec chmod 644 {} +
chmod 755 install.sh submarine-sync setup.sh docker/entrypoint.sh tests/docker/e2e.sh tests/install/install-test.sh
gq init -q -b main && gq add -A && gq commit -q -m "release 9.0.0" && gq tag v9.0.0
echo "<!-- 9.0.1 -->" >> README.md && gq commit -q -am "release 9.0.1" && gq tag v9.0.1
gq clone -q --bare "$W/src" "$W/origin.git"
cp "$W/src/install.sh" "$W/install.sh"
cat > "$W/override.yml" <<'Y'
services:
  caddy:
    ports: !override
      - "127.0.0.1:80:80"
      - "127.0.0.1:443:443"
Y
export COMPOSE_FILE=$D/docker-compose.yml:$W/override.yml
export SUBMARINE_REPO_URL=$W/origin.git

echo "---- install"
bash "$W/install.sh" --domain localhost --email owner@example.com --admin-panel --yes > "$W/install1.log" 2>&1; rc=$?
is "install.sh exit code" "$rc" 0
[ $rc = 0 ] || tail -n 40 "$W/install1.log"
is "the newest release is installed" "$(git -C $D describe --tags)" v9.0.1
is ".env is private" "$(stat -c %a $D/.env)" 600
is "the command is linked" "$(readlink -f $SS)" "$D/submarine-sync"
is "the daily backup timer is on" "$(systemctl is-enabled submarine-sync-backup.timer 2>&1)" enabled
is "COMPOSE_PROFILES=https in .env" "$(envv COMPOSE_PROFILES)" https
is "no secret in the install output" "$(grep -c -F -e "$(envv SUBMARINE_TOKEN_PEPPER)" -e "$(envv MARIADB_ROOT_PASSWORD)" -e "$(envv SUBMARINE_DB_PASSWORD)" "$W/install1.log")" 0
CODE=$(grep -oE '^ +[0-9a-f]{48}$' "$W/install1.log" | tr -d ' ' | sed -n 1p)
is "an invitation code is printed" "${#CODE}" 48
ADMIN_URL=$(sed -n 's/^ *Address: *//p' "$W/install1.log" | grep '/admin-' | sed -n 1p)
ADMIN_PW=$(sed -n 's/^ *Password: *//p' "$W/install1.log" | sed -n 1p)
is "the admin panel is at an address nobody guesses" "$(printf '%s' "$ADMIN_URL" | grep -cE '^https://localhost/admin-[0-9a-f]{12}$')" 1
is "with a generated password" "$([ ${#ADMIN_PW} -ge 20 ] && echo yes)" yes
is "status: HTTPS works" "$($SS status 2>&1 | grep -c '^HTTPS: *works')" 1
is "the server answers over HTTPS" "$(code https://localhost/health)" 200
is "/admin is only a 404" "$(code https://localhost/admin)" 404

echo "---- the invitation, the way the app uses it"
CLAIM=$(api "https://localhost/auth/verify?token=$CODE" | sed -n 's/.*"claim_token":"\([0-9a-f]*\)".*/\1/p')
TOKEN=$(api -H 'Content-Type: application/json' -d "{\"claim_token\":\"$CLAIM\",\"password\":\"owner password 1\"}" https://localhost/auth/set-password | sed -n 's/.*"token":"\([0-9a-f]*\)".*/\1/p')
is "a sign-in token" "${#TOKEN}" 64
is "a sync with it" "$(code -H "X-Auth-Token: $TOKEN" -H 'Content-Type: application/json' -d '{"profile":"p1","since":"","records":[{"uuid":"ab","entity_type":"servers","updated_at":"001794000000000:00000:t1","deleted":false,"blob":"abcd"}]}' https://localhost/sync)" 200

echo "---- the admin panel"
api -c "$W/jar" -o /dev/null --data-urlencode do=login --data-urlencode "password=$ADMIN_PW" "$ADMIN_URL"
is "signed in with the printed password" "$(api -b "$W/jar" "$ADMIN_URL" | grep -c 'Invite someone')" 1
$SS admin-password --off > /dev/null 2>&1
is "admin-password --off: the panel is gone" "$(code "$ADMIN_URL")" 404

echo "---- files a strict umask (027, 077) made private still work in the image"
chmod -R go-rwx "$D/public" "$D/src" "$D/bin" "$D/docker"
(cd "$D" && docker compose build app > /dev/null 2>&1)
$SS restart > /dev/null 2>&1; rc=$?
is "rebuilt from private files: healthy" "$rc $(code https://localhost/health)" "0 200"
chmod -R go+rX "$D/public" "$D/src" "$D/bin" "$D/docker"

if command -v php >/dev/null 2>&1 && php -m | grep -qx curl; then
    echo "---- smoke test over HTTPS, with submarine-sync as the admin command"
    SUBMARINE_TEST_URL=https://localhost SUBMARINE_TEST_INSECURE=1 SUBMARINE_TEST_ADMIN_CMD="$SS" php "$W/src/tests/smoke-test.php" > "$W/smoke.log" 2>&1
    is "smoke test" "$(tail -n 1 "$W/smoke.log")" "ALL PASS"
else
    echo "SKIP smoke test (no PHP with curl here)"
fi

echo "---- backups"
$SS backup > "$W/b1.log" 2>&1
B1=$(sed -n 's/^ *Backup: \([^ ]*\) .*/\1/p' "$W/b1.log")
is "a backup file" "$([ -f "$B1" ] && echo yes)" yes
is "a private file in a private folder" "$(stat -c %a "$B1") $(stat -c %a $BK)" "600 700"
is "it holds db.sql, env and info" "$(tar -tzf "$B1" | sort | tr '\n' ' ')" "db.sql env info "
is "the dump is complete" "$(tar -xzOf "$B1" db.sql | tail -n 1 | cut -c1-17)" "-- Dump completed"
systemctl start submarine-sync-backup.service
is "the timer's service makes one too" "$(ls $BK/submarine-sync-*.tar.gz | wc -l)" 2
sleep 1; $SS backup --keep 2 > /dev/null 2>&1
is "--keep 2 keeps two" "$(ls $BK/submarine-sync-*.tar.gz | wc -l)" 2
is "the oldest went" "$([ -f "$B1" ] && echo kept || echo gone)" gone
$SS backup > "$W/b2.log" 2>&1
B2=$(sed -n 's/^ *Backup: \([^ ]*\) .*/\1/p' "$W/b2.log")

echo "---- restore, with the backup's token pepper"
OLDPEP=$(envv SUBMARINE_TOKEN_PEPPER)
$SS set "SUBMARINE_TOKEN_PEPPER=$(openssl rand -hex 32)" > /dev/null 2>&1
$SS restart > /dev/null 2>&1
is "a new pepper ends the sign-in" "$(code -H "X-Auth-Token: $TOKEN" https://localhost/sync/profiles)" 401
LATE=$($SS invite late@example.com 2>&1 | grep -oE '[0-9a-f]{48}' | sed -n 1p)
is "an account made after the backup" "${#LATE}" 48
setsid -w $SS restore "$B2" < /dev/null > "$W/r0.log" 2>&1; rc=$?
is "restore with no terminal and no --yes: refused" "$rc $(grep -c 'Add --yes' "$W/r0.log")" "1 1"
$SS restore "$B2" --yes > /dev/null 2>&1; rc=$?
is "restore --yes" "$rc" 0
is "the backup's pepper is back" "$([ "$(envv SUBMARINE_TOKEN_PEPPER)" = "$OLDPEP" ] && echo same || echo different)" same
is "so the old sign-in works again" "$(code -H "X-Auth-Token: $TOKEN" https://localhost/sync/profiles)" 200
is "the later account is gone" "$($SS list 2>&1 | grep -c late@example.com)" 0
is "a backup from before the restore" "$(ls $BK/*-before-restore.tar.gz 2>/dev/null | wc -l)" 1

echo "---- a wrong setting fails fast, check says why, and it comes back"
setsid -w $SS set SUBMARINE_DB_PASSWORD=x < /dev/null > "$W/s0.log" 2>&1; rc=$?
is "the database password can't be set here" "$rc $(grep -c 'lock the server out' "$W/s0.log")" "1 1"
$SS set SUBMARINE_SIGNUP=open > /dev/null 2>&1
t0=$(date +%s); $SS restart > /dev/null 2>&1; rc=$?; took=$(( $(date +%s) - t0 ))
is "restart with open sign-up and no mail fails" "$rc" 1
is "in under 2 minutes" "$([ $took -lt 120 ] && echo yes || echo "no ($took s)")" yes
is "check names the setting" "$($SS check 2>&1 | grep -c 'SUBMARINE_SIGNUP=open needs mail')" 1
$SS set SUBMARINE_SIGNUP=invite > /dev/null 2>&1
$SS restart > /dev/null 2>&1
is "fixed: healthy again" "$(code https://localhost/health)" 200

echo "---- update"
is "nothing new: up to date" "$($SS update 2>&1 | grep -c 'Already up to date (v9.0.1)')" 1
cd "$W/src" || exit 1
sed -i 's#/src/api.php#/src/missing.php#' public/index.php && gq commit -q -am "broken 9.0.2" && gq tag v9.0.2
gq push -q "$W/origin.git" main --tags
$SS update > "$W/u1.log" 2>&1; rc=$?
is "a broken release: the update fails" "$rc" 1
is "and goes back" "$(git -C $D describe --tags) $(grep -c 'Back on v9.0.1' "$W/u1.log")" "v9.0.1 1"
is "healthy on the old version" "$(code https://localhost/health)" 200
sed -i 's#/src/missing.php#/src/api.php#' public/index.php && echo "<!-- 9.0.3 -->" >> README.md && gq commit -q -am "release 9.0.3" && gq tag v9.0.3
gq push -q "$W/origin.git" main --tags
$SS update > /dev/null 2>&1; rc=$?
is "a good release: updated" "$rc $(git -C $D describe --tags)" "0 v9.0.3"
is "with a backup from before each try" "$(ls $BK/*-before-update.tar.gz 2>/dev/null | wc -l)" 2
is "the data is still there" "$(code -H "X-Auth-Token: $TOKEN" https://localhost/sync/profiles)" 200
setsid -w $SS update v9.0.1 < /dev/null > /dev/null 2>&1; rc=$?
is "an older version needs --yes" "$rc $(git -C $D describe --tags)" "1 v9.0.3"
$SS update v9.0.1 --yes > /dev/null 2>&1; rc=$?
is "with --yes it goes back" "$rc $(git -C $D describe --tags)" "0 v9.0.1"
$SS update > /dev/null 2>&1
is "update: the newest again" "$(git -C $D describe --tags)" v9.0.3
is "status: no newer release" "$($SS status 2>&1 | grep -c 'is out')" 0

echo "---- install.sh again"
pep=$(envv SUBMARINE_TOKEN_PEPPER)
bash "$W/install.sh" --email second@example.com --yes > "$W/install2.log" 2>&1; rc=$?
is "again with --email" "$rc" 0
is "the settings and their secrets are kept" "$([ "$(envv SUBMARINE_TOKEN_PEPPER)" = "$pep" ] && echo same || echo different)" same
is "the version is kept" "$(git -C $D describe --tags)" v9.0.3
is "a second invitation" "$(grep -cE '^ +[0-9a-f]{48}$' "$W/install2.log")" 1
bash "$W/install.sh" --no-https --yes > /dev/null 2>&1; rc=$?
is "again with --no-https: no Caddy" "$rc $(docker ps -q --filter label=com.docker.compose.service=caddy --filter label=com.docker.compose.project=submarine-sync | wc -l)" "0 0"
is "the server on 127.0.0.1:8080" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" 200
bash "$W/install.sh" --domain localhost --yes > /dev/null 2>&1; rc=$?
is "again with --domain: HTTPS is back" "$rc $(code https://localhost/health)" "0 200"

echo "---- stop, start, uninstall"
$SS stop > /dev/null 2>&1
is "stopped" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8080/health)" 000
$SS start > /dev/null 2>&1
is "started" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health)" 200
$SS uninstall --yes > /dev/null 2>&1; rc=$?
is "uninstall: no containers" "$rc $(docker ps -aq --filter label=com.docker.compose.project=submarine-sync | wc -l)" "0 0"
is "the data stays" "$(docker volume ls -q | grep -c '^submarine-sync_db$')" 1
is "the timer is off" "$(systemctl is-enabled submarine-sync-backup.timer 2>&1 | grep -c '^enabled')" 0
$SS start > /dev/null 2>&1
is "start again: the data is there" "$(code -H "X-Auth-Token: $TOKEN" https://localhost/sync/profiles)" 200
$SS uninstall --purge --yes > /dev/null 2>&1; rc=$?
is "uninstall --purge" "$rc" 0
is "folder, command and volumes gone" "$([ -e $D ] && echo folder) $([ -e $SS ] && echo command) $(docker volume ls -q | grep -c '^submarine-sync_')" "  0"
is "a last backup stays" "$(ls $BK/*-before-uninstall.tar.gz 2>/dev/null | wc -l)" 1

echo
[ $fails -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit $fails
