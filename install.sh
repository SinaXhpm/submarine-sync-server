#!/usr/bin/env bash
# Submarine sync server — install on a Linux server with one command:
#
#   curl -fsSLO https://raw.githubusercontent.com/SinaXhpm/submarine-sync-server/main/install.sh
#   sudo bash install.sh --domain sync.example.com --email you@example.com
#
# What it does, step by step (each step says so when it runs):
#   1. checks the machine: root, Linux, 64-bit, memory, disk, the domain's DNS
#      record, and that nothing else uses ports 80 and 443;
#   2. installs Docker with Compose from Docker's own repository if it isn't
#      there, or the distribution's own Docker packages where that repository
#      can't be reached (Debian and Ubuntu; on another Linux, install Docker
#      first);
#   3. puts the server in /opt/submarine-sync (the newest release);
#   4. makes the settings (.env) with random secrets;
#   5. opens ports 80 and 443 in ufw or firewalld, if one of them is on;
#   6. builds and starts the server, its database, the hourly clean-up and
#      Caddy, which gets a free Let's Encrypt certificate for the domain;
#   7. installs the submarine-sync command and a daily backup;
#   8. prints an invitation code for --email, to make your account in the app.
#
# Safe to run again: it keeps the settings and the data, and only adds what is
# missing. Later updates: submarine-sync update.

set -euo pipefail
umask 022

REPO_URL=${SUBMARINE_REPO_URL:-https://github.com/SinaXhpm/submarine-sync-server.git}
DIR=/opt/submarine-sync
DIR_GIVEN=0
DOMAIN=
EMAIL=
VERSION=
HTTPS=ask
PORT=
ADMIN_PANEL=0
BACKUPS=1
ASSUME_YES=0
LOG=/var/log/submarine-sync-install.log

if [ -t 1 ]; then B=$'\033[1m'; Y=$'\033[33m'; R=$'\033[31m'; G=$'\033[32m'; N=$'\033[0m'; else B=; Y=; R=; G=; N=; fi
say()  { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%s!!  %s%s\n' "$Y" "$*" "$N" >&2; }
die()  { printf '\n%sError: %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

usage() {
    cat <<'TXT'
Usage: sudo bash install.sh [options]

  --domain NAME    The server's name, for example sync.example.com. Its DNS
                   record must point at this machine, and ports 80 and 443 must
                   be open: Caddy gets a Let's Encrypt certificate for it.
  --email ADDRESS  Make an invitation code for this address (your account).
  --no-https       No HTTPS and no Caddy: the server answers on 127.0.0.1 only,
                   for your own reverse proxy, or for an SSH tunnel.
  --port N         The local port (default 8080).
  --admin-panel    Also switch on the web admin panel, with a new password.
  --dir PATH       Where to install (default /opt/submarine-sync).
  --version TAG    The release to install (default: the newest).
  --no-backup      Don't set up the daily backup.
  --yes            Ask nothing; stop instead where an answer is needed.
  -h, --help       This text.

Without --domain or --no-https it asks. Run it again to change the domain or
to make another invitation; it keeps the settings and the data.
TXT
}

need_value() { [ $# -ge 2 ] && [ -n "$2" ] && [ "${2#--}" = "$2" ] || die "$1 needs a value (see --help)."; }

while [ $# -gt 0 ]; do
    case "$1" in
        --domain) need_value "$@"; DOMAIN=$2; HTTPS=yes; shift 2 ;;
        --domain=*) DOMAIN=${1#*=}; HTTPS=yes; shift ;;
        --email) need_value "$@"; EMAIL=$2; shift 2 ;;
        --email=*) EMAIL=${1#*=}; shift ;;
        --no-https) HTTPS=no; shift ;;
        --port) need_value "$@"; PORT=$2; shift 2 ;;
        --port=*) PORT=${1#*=}; shift ;;
        --admin-panel) ADMIN_PANEL=1; shift ;;
        --dir) need_value "$@"; DIR=$2; DIR_GIVEN=1; shift 2 ;;
        --dir=*) DIR=${1#*=}; DIR_GIVEN=1; shift ;;
        --version) need_value "$@"; VERSION=$2; shift 2 ;;
        --version=*) VERSION=${1#*=}; shift ;;
        --no-backup) BACKUPS=0; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

# Run from inside a copy of the repository (git clone, then sudo bash
# install.sh): use that copy where it is.
if [ $DIR_GIVEN = 0 ] && [ -f "${BASH_SOURCE[0]:-}" ]; then
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    if [ -f "$here/docker-compose.yml" ] && [ -f "$here/submarine-sync" ]; then DIR=$here; fi
fi

# Whether there is a terminal to ask on (/dev/tty can exist and still not open).
have_tty() { [ $ASSUME_YES = 0 ] && (exec < /dev/tty) 2>/dev/null; }
ask() {  # $1: question; the answer on stdout
    local a=''
    printf '%s' "$1" > /dev/tty
    read -r a < /dev/tty || true
    printf '%s' "$a"
}
# Output of a long step goes to the log; on failure its end is shown.
run_logged() {
    local what=$1; shift
    if ! "$@" >> "$LOG" 2>&1; then
        tail -n 25 "$LOG" >&2 || true
        die "$what failed. The whole output is in $LOG."
    fi
}
env_val() {  # a setting from an existing .env, without quotes
    local v=''
    [ -f "$DIR/.env" ] && v=$(sed -n "s/^$1=//p" "$DIR/.env" | sed -n '$p')
    v=${v%$'\r'}; v=${v#\'}; v=${v%\'}; v=${v#\"}; v=${v%\"}
    printf '%s' "$v"
}

# --- 1. The machine ---------------------------------------------------------

say "Checking this machine"
[ "$(id -u)" -eq 0 ] || die "Run it as root, for example: sudo bash install.sh --domain sync.example.com"
[ "$(uname -s)" = Linux ] || die "This installer is for Linux servers."
case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) die "A 64-bit x86 or ARM machine is needed (this is $(uname -m))." ;;
esac
touch "$LOG" 2>/dev/null || LOG=/tmp/submarine-sync-install.log
printf '\n=== install.sh %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$LOG"
chmod 600 "$LOG" 2>/dev/null || true

mem_kb=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
if [ "${mem_kb:-0}" -lt 900000 ]; then
    warn "This machine has $((mem_kb / 1024)) MB of memory; about 1 GB is needed. Add swap if the build stops."
fi
mkdir -p /var/lib
avail_kb=$(df -Pk /var/lib | awk 'NR == 2 { print $4 }')
[ "${avail_kb:-0}" -ge 2500000 ] || die "About 2.5 GB of free disk space is needed under /var/lib (there is $((${avail_kb:-0} / 1024)) MB)."
info "$(uname -m), $((mem_kb / 1024)) MB of memory, $((avail_kb / 1024 / 1024)) GB free."

# What an earlier run set up stays, unless an option says otherwise.
if [ "$HTTPS" = ask ] && [ -f "$DIR/.env" ]; then
    if [[ ,$(env_val COMPOSE_PROFILES), == *,https,* ]] && [ -n "$(env_val SUBMARINE_DOMAIN)" ]; then
        HTTPS=yes; DOMAIN=$(env_val SUBMARINE_DOMAIN)
    else
        HTTPS=no
    fi
    info "Keeping the earlier choice: $([ $HTTPS = yes ] && echo "HTTPS for $DOMAIN" || echo 'no HTTPS')."
fi
if [ "$HTTPS" = ask ]; then
    have_tty || die "Say --domain NAME (HTTPS with a Let's Encrypt certificate) or --no-https."
    DOMAIN=$(ask "Domain name for HTTPS (e.g. sync.example.com; its DNS record must point here), or empty for none: ")
    if [ -n "$DOMAIN" ]; then HTTPS=yes; else HTTPS=no; fi
    if [ -z "$EMAIL" ]; then
        EMAIL=$(ask "Your email, for an invitation code to make your account (empty: none): ")
    fi
fi

if [ "$HTTPS" = yes ]; then
    DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z')
    DOMAIN=${DOMAIN%.}
    if [ "$DOMAIN" != localhost ]; then
        [[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] \
            || die "'$DOMAIN' is not a domain name (an address alone can't get a certificate here)."
        addrs=$(getent ahosts "$DOMAIN" 2>/dev/null | awk '{ print $1 }' | sort -u | tr '\n' ' ' || true)
        [ -n "$addrs" ] || die "$DOMAIN has no DNS record yet. Make an A record (and AAAA, for IPv6) that points at this server's public address, wait a few minutes, and run this again."
        mine=$(ip -o addr show scope global 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }' | tr '\n' ' ' || true)
        match=0
        for a in $addrs; do case " $mine " in *" $a "*) match=1 ;; esac; done
        if [ $match = 1 ]; then
            info "$DOMAIN points at this machine ($addrs)."
        else
            info "$DOMAIN points at $addrs. That is not an address of this machine's own network"
            info "cards, which is normal behind a cloud provider's NAT; if it isn't the server's public"
            info "address, fix the DNS record first, or getting the certificate fails."
        fi
    fi
    if [ "$(docker compose --project-directory "$DIR" ps -q caddy 2>/dev/null || true)" = "" ] && command -v ss >/dev/null 2>&1; then
        busy=$(ss -ltnp '( sport = :80 or sport = :443 )' 2>/dev/null | tail -n +2 | grep -v docker-proxy || true)
        if [ -n "$busy" ]; then
            printf '%s\n' "$busy" >&2
            die "Something else already uses port 80 or 443 (above). Stop that web server, or install with --no-https and let it pass requests to 127.0.0.1:${PORT:-8080} (README: Your own reverse proxy)."
        fi
    fi
fi
if [ -n "$EMAIL" ]; then
    [[ $EMAIL =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "'$EMAIL' is not an email address."
fi
if [ -n "$PORT" ]; then
    [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port needs a port number."
fi

# --- 2. Docker --------------------------------------------------------------

apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    run_logged "apt-get update" apt-get update
    run_logged "Installing $*" apt-get install -y --no-install-recommends "$@"
}

say "Docker"
missing=()
for t in git curl openssl flock; do command -v $t >/dev/null 2>&1 || missing+=("$t"); done
if [ ${#missing[@]} -gt 0 ]; then
    if command -v apt-get >/dev/null 2>&1; then
        pk=(ca-certificates)
        for t in "${missing[@]}"; do case $t in flock) pk+=(util-linux) ;; *) pk+=("$t") ;; esac; done
        info "Installing ${pk[*]}"
        apt_install "${pk[@]}"
    else
        die "Install these first: ${missing[*]}"
    fi
fi

if command -v docker >/dev/null 2>&1; then
    info "Docker is installed: $(docker --version 2>/dev/null || echo '?')"
else
    [ -r /etc/os-release ] || die "Install Docker Engine with the Compose plugin first: https://docs.docker.com/engine/install/"
    # shellcheck disable=SC1091
    . /etc/os-release
    os=${ID:-}; codename=${VERSION_CODENAME:-}
    case "$os" in
        ubuntu|debian) ;;
        raspbian) os=debian ;;
        *)
            case " ${ID_LIKE:-} " in
                *" ubuntu "*) os=ubuntu; codename=${UBUNTU_CODENAME:-$codename} ;;
                *" debian "*) os=debian; codename=${DEBIAN_CODENAME:-$codename} ;;
                *) die "Docker isn't installed, and this installer only installs it on Debian and Ubuntu. Install Docker Engine with the Compose plugin (https://docs.docker.com/engine/install/), then run this again." ;;
            esac ;;
    esac
    [ -n "$codename" ] || die "Can't tell which $os release this is; install Docker first (https://docs.docker.com/engine/install/)."
    apt_install ca-certificates curl
    # Docker's own repository, as Docker's instructions set it up. It may not
    # be usable from here: no packages for this release, or blocked (it
    # answers some countries with 403). Then it goes again, so apt keeps
    # working, and the distribution's own Docker packages are used.
    docker_repo() {
        info "Installing Docker from Docker's own repository (download.docker.com, $os $codename)"
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL --max-time 60 "https://download.docker.com/linux/$os/gpg" -o /etc/apt/keyrings/docker.asc >> "$LOG" 2>&1 || return 1
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$os $codename stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update >> "$LOG" 2>&1 || return 1
        [ -n "$(apt-cache policy docker-ce 2>/dev/null | sed -n 's/^ *Candidate: *//p' | grep -v '(none)')" ] || return 1
        run_logged "Installing Docker" apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    }
    if ! docker_repo; then
        rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
        warn "Docker's own repository can't be used from here (see $LOG); installing the Docker packages of $os instead."
        run_logged "apt-get update" apt-get update
        run_logged "Installing Docker" apt-get install -y docker.io
        # Builds the image the way Docker's own packages do (Compose warns without it).
        apt-get install -y docker-buildx >> "$LOG" 2>&1 || true
    fi
fi
if ! docker compose version >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || die "Docker Compose (docker compose) is missing; install the Compose plugin."
    info "Installing the Compose plugin"
    export DEBIAN_FRONTEND=noninteractive
    run_logged "apt-get update" apt-get update
    apt-get install -y docker-compose-plugin >> "$LOG" 2>&1 || apt-get install -y docker-compose-v2 >> "$LOG" 2>&1 \
        || apt-get install -y docker-compose >> "$LOG" 2>&1 || true
    docker compose version >/dev/null 2>&1 || die "Couldn't install Docker Compose; install the Compose plugin and run this again."
fi
if ! docker info >/dev/null 2>&1; then
    # The daemon may wait for its socket unit (docker.socket), and systemd
    # stops retrying after a few quick failures.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reset-failed docker.service docker.socket >> "$LOG" 2>&1 || true
        systemctl enable --now docker.socket >> "$LOG" 2>&1 || true
        systemctl enable --now docker.service >> "$LOG" 2>&1 || true
    fi
    docker info >/dev/null 2>&1 || die "Docker is installed but doesn't run (systemctl status docker)."
fi
info "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), Compose $(docker compose version --short 2>/dev/null)."

# --- 3. The server's files ---------------------------------------------------

g() { git -c safe.directory="$DIR" -C "$DIR" "$@"; }
version_label() { g describe --tags --always 2>/dev/null || echo '(a copy without git)'; }

say "The server's files in $DIR"
if [ -d "$DIR/.git" ]; then
    info "Already there ($(version_label)); kept as it is. Later updates: submarine-sync update"
elif [ -f "$DIR/docker-compose.yml" ] && [ -f "$DIR/submarine-sync" ]; then
    info "Using the copy in $DIR as it is. It isn't a git copy, so submarine-sync update can't"
    info "update it; for that, install from git (the default)."
else
    if [ -e "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
        die "$DIR is there and not empty. Choose another place with --dir."
    fi
    run_logged "Downloading $REPO_URL" git clone --quiet "$REPO_URL" "$DIR"
    if [ -z "$VERSION" ]; then
        VERSION=$(g tag -l 'v[0-9]*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed -n 1p || true)
    fi
    if [ -n "$VERSION" ]; then
        rev=$(g rev-parse --verify --quiet "refs/tags/$VERSION^{commit}" || g rev-parse --verify --quiet "origin/$VERSION^{commit}") \
            || die "There is no release (or branch) $VERSION."
        g checkout --quiet --detach "$rev"
    fi
    info "Version: $(g describe --tags --always)"
fi
[ -f "$DIR/submarine-sync" ] || die "$DIR has no submarine-sync command: this version is too old for this installer."
chmod 755 "$DIR/submarine-sync"
SS="$DIR/submarine-sync"

# --- 4. Settings -------------------------------------------------------------

say "Settings ($DIR/.env)"
if [ ! -f "$DIR/.env" ]; then
    (cd "$DIR" && sh ./setup.sh >/dev/null)
    info "Made with random secrets. Keep this file private: it holds them."
else
    info "Kept as they are, with their secrets."
fi
chmod 600 "$DIR/.env"
sets=()
if [ "$HTTPS" = yes ]; then
    sets+=(COMPOSE_PROFILES=https "SUBMARINE_DOMAIN=$DOMAIN")
    # IPv6 inside Docker's network stays a choice (README, "IPv6"): whether
    # Docker can forward IPv6 to it depends on the host's firewall setup.
    if [ "$(env_val SUBMARINE_IPV6)" != true ] && [ -n "$(ip -6 addr show scope global 2>/dev/null || true)" ]; then
        info "This machine has IPv6. Users who come over IPv6 share one address for the rate limits"
        info "until Docker's network gets IPv6 too (Docker 27+): see README, \"IPv6\"."
    fi
else
    sets+=(COMPOSE_PROFILES=)
fi
[ -z "$PORT" ] || sets+=("SUBMARINE_HTTP_PORT=$PORT")
"$SS" set "${sets[@]}" >/dev/null

# --- 5. Firewall -------------------------------------------------------------

if [ "$HTTPS" = yes ] && [ "$DOMAIN" != localhost ]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        say "Firewall (ufw)"
        for p in 80/tcp 443/tcp 443/udp; do ufw allow "$p" comment 'Submarine sync' >> "$LOG" 2>&1 || ufw allow "$p" >> "$LOG" 2>&1 || true; done
        info "Ports 80 and 443 are open."
    elif command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null || true)" = running ]; then
        say "Firewall (firewalld)"
        run_logged "Opening ports 80 and 443" firewall-cmd --permanent --add-service=http --add-service=https --add-port=443/udp
        run_logged "Reloading firewalld" firewall-cmd --reload
        info "Ports 80 and 443 are open."
    fi
    info "If your provider has a firewall of its own (a security group), open ports 80 and 443 there too."
fi

# --- 6. Build and start ------------------------------------------------------

if [ "$HTTPS" = no ]; then
    # Compose leaves a service of a profile that is no longer on running: an
    # earlier run's Caddy goes here.
    (cd "$DIR" && docker compose --profile https rm --stop --force caddy >> "$LOG" 2>&1 || true)
fi

say "Building the server (a few minutes the first time)"
(cd "$DIR" && run_logged "Building the server image" docker compose build app)
https_ok=0
code=0
"$SS" start || code=$?
case $code in 0) https_ok=1 ;; 3) ;; *) die "The server didn't start (see above)." ;; esac
[ "$HTTPS" = yes ] || https_ok=1

admin_out=''
if [ $ADMIN_PANEL = 1 ]; then
    admin_out=$("$SS" admin-password --generate) || die "Switching on the admin panel failed."
fi

# --- 7. The command and the daily backup ------------------------------------

say "The submarine-sync command"
ln -sfn "$SS" /usr/local/bin/submarine-sync
info "submarine-sync help lists what it does."

if [ $BACKUPS = 1 ]; then
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        install -m 644 "$DIR/deploy/systemd/submarine-sync-backup.service" "$DIR/deploy/systemd/submarine-sync-backup.timer" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable --now submarine-sync-backup.timer >> "$LOG" 2>&1
        info "Daily backup: on, kept 14 days in $(env_val SUBMARINE_BACKUP_DIR)."
    else
        warn "No systemd here, so no daily backup was set up. Run submarine-sync backup from cron yourself."
    fi
fi

# --- 8. The invitation -------------------------------------------------------

invite_out=''
if [ -n "$EMAIL" ]; then
    invite_out=$("$SS" invite "$EMAIL" 2>&1) || true
fi

# --- Done --------------------------------------------------------------------

base=$(env_val SUBMARINE_BASE_PATH); base=${base%/}
port=$(env_val SUBMARINE_HTTP_PORT)
if [ "$HTTPS" = yes ]; then address="https://$DOMAIN$base"; else address="http://127.0.0.1:${port:-8080}$base"; fi
say "${G}Done${N}${B}: Submarine sync server $(version_label) is installed"
info "Address for the app:  $address"
[ "$HTTPS" = yes ] || info "It answers on this machine only: use your own reverse proxy, or an SSH tunnel (README)."
info "In Submarine: Cloud sync > Sync server > Change > $address"
if [ -n "$invite_out" ]; then
    echo
    printf '%s\n' "$invite_out" | sed 's/^/    /'
fi
if [ -n "$admin_out" ]; then
    echo
    printf '%s\n' "$admin_out" | sed 's/^==> /    /'
fi
echo
info "Manage it:  submarine-sync status | invite <email> | backup | update | help"
info "Settings:   $DIR/.env (private: it holds the secrets, and is in every backup)"
if [ $https_ok = 0 ]; then
    echo
    warn "HTTPS doesn't work yet (above). The server is installed; Caddy keeps trying."
    warn "Once the DNS record and ports are right, check with: submarine-sync status"
    exit 3
fi
