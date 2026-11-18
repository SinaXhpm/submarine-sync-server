# Submarine sync server

The server behind **Cloud sync** in [Submarine](https://github.com/SinaXhpm/Submarine), the SSH, SFTP, RDP and VNC client. Run it yourself, and your devices sync their profiles through your own machine instead of Submarine's server.

It keeps the accounts, the encrypted profiles and the shared profiles. Profiles are encrypted on your devices before they are sent. The server stores them and passes them on, but it never has the keys to open them.

This is the same code as Submarine's own sync server, without the parts only that one needs. It speaks the same protocol, so the app needs no changes.

## Contents

- [What you need](#what-you-need)
- [Install on a server with one command](#install-on-a-server-with-one-command)
- [Connect the app](#connect-the-app)
- [Manage the server](#manage-the-server)
- [Install by hand with Docker](#install-by-hand-with-docker)
- [HTTPS](#https)
- [Accounts and invitations](#accounts-and-invitations)
- [The web admin panel](#the-web-admin-panel)
- [Mail](#mail)
- [Install on PHP hosting without Docker](#install-on-php-hosting-without-docker)
- [Settings](#settings)
- [Backups and upgrades](#backups-and-upgrades)
- [Limits](#limits)
- [Security](#security)
- [Tests](#tests)
- [Help](#help)

## What you need

- **A Submarine version with the "Sync server" setting**, for example the 0.5 betas or newer.
- **A machine to run it on**, one of:
  - a Linux server, for example a small VPS with 1 GB of memory: Debian or Ubuntu for the [one-command install](#install-on-a-server-with-one-command), or any 64-bit Linux that already has Docker;
  - any machine with **Docker** and Compose, [set up by hand](#install-by-hand-with-docker);
  - **PHP hosting** with PHP 8.1+ and MariaDB 10.6+ (MySQL 8.0 works too; from 8.0.20 it logs deprecation notes about `VALUES()` in the sync queries, which are harmless).
- **HTTPS with a real certificate** for devices other than the server itself. The app accepts plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`. It also refuses self-signed certificates and certificates from a private CA. A free Let's Encrypt certificate works, and both Docker ways get one for you: all they need is a domain name whose DNS record points at the server.

## Install on a server with one command

On a Linux server (Debian or Ubuntu), with a domain name whose DNS record points at it and ports 80 and 443 open:

```sh
curl -fsSLO https://raw.githubusercontent.com/SinaXhpm/submarine-sync-server/main/install.sh
sudo bash install.sh --domain sync.example.com --email you@example.com
```

`install.sh` is a plain shell script; read it first if you like. It:

1. checks the machine and the domain's DNS record;
2. installs Docker with Compose from Docker's own repository, if it isn't there (where that repository can't be reached, the distribution's own Docker packages);
3. puts the server in `/opt/submarine-sync` (the newest release), with settings that have random secrets;
4. opens ports 80 and 443 in `ufw` or `firewalld`, if one of them is on;
5. starts the server with HTTPS: [Caddy](https://caddyserver.com) gets a free Let's Encrypt certificate and renews it;
6. installs the [`submarine-sync` command](#manage-the-server) and a daily backup;
7. prints an invitation code for your email. Enter it in the app: see [Connect the app](#connect-the-app).

| Option | What it does |
|---|---|
| `--no-https` | No Caddy and no certificate: the server answers on `127.0.0.1:8080` only, for [your own reverse proxy](#https) or an SSH tunnel. |
| `--admin-panel` | Also switch on the [web admin panel](#the-web-admin-panel), at an address nobody guesses, with a new password (both printed once). |
| `--port N` | The local port instead of 8080. |
| `--dir PATH` | Install somewhere else than `/opt/submarine-sync`. |
| `--version TAG` | A given release instead of the newest. |
| `--no-backup` | No daily backup. |
| `--yes` | Ask nothing, for scripts (with `--domain` or `--no-https`). |

Without `--domain` or `--no-https`, it asks. Run it again any time, for example with `--email` for another invitation, or with another `--domain`: it keeps the settings and the data. It writes what it does to `/var/log/submarine-sync-install.log`.

On another Linux, install Docker Engine with the Compose plugin first, and the script does the rest. If your provider has a firewall of its own (often called a security group), open ports 80 and 443 there too.

Docker's repository and Docker Hub refuse connections from some countries (an error 403). The script then installs the distribution's Docker packages instead, but the images (PHP, MariaDB, Caddy) still come from Docker Hub: give Docker a [registry mirror](https://docs.docker.com/docker-hub/image-library/mirror/) or a [proxy](https://docs.docker.com/engine/daemon/proxy/) first, then run the script.

## Connect the app

In Submarine, open **Cloud sync**:

1. At **Sync server**, choose **Change**, enter your server's address (for example `https://sync.example.com`) and save. The app checks that the server answers.
2. Choose **Have a verify token? Continue verifying**, paste the code from the invitation, then choose your password.
3. Sign in on your other devices with the same server address, email and password.

A shared profile stays on the server it was shared on. For a personal profile that was synced with another server, the app offers to move it to the server in use.

## Manage the server

`install.sh` installs the `submarine-sync` command. Run it as root:

```sh
sudo submarine-sync status                       # what runs, the address, HTTPS, the last backup
sudo submarine-sync invite friend@example.com    # an invitation code
sudo submarine-sync update                       # the newest release
sudo submarine-sync help                         # everything else
```

| Command | What it does |
|---|---|
| `status` | What runs, the address, whether HTTPS works and until when its certificate is good, the last backup, and whether a newer release is out. |
| `start`, `stop`, `restart` | Start or stop everything. `restart` uses the settings in `.env` again. |
| `logs [app\|db\|cron\|caddy]` | Follow the logs. Ctrl+C ends it. |
| `update [version]` | Make a backup, move to the newest release (or the one named), rebuild and restart. If the new version doesn't start, it goes back to the old one. |
| `invite`, `reset-code`, `list`, `suspend`, `unsuspend`, `signout`, `delete`, `check` | The [account commands](#accounts-and-invitations). |
| `set NAME=VALUE` | Change a [setting](#settings) in `.env`, then `restart`. |
| `edit` | Open `.env` in an editor, then restart. |
| `admin-password` | Switch the [web admin panel](#the-web-admin-panel) on or give it a new password; `--generate` makes one, `--off` switches the panel off. |
| `backup`, `backups`, `restore <file>` | See [Backups and upgrades](#backups-and-upgrades). |
| `uninstall` | Stop and remove the containers; the data stays, and `start` brings it back. `--purge` also removes the data and the folder, after a last backup. |

It works for a server you [set up by hand](#install-by-hand-with-docker) too: run `sudo ./submarine-sync` in its folder. If you started that one with `docker compose --profile https`, put `COMPOSE_PROFILES=https` in its `.env` first, so the command starts Caddy too. Or run `sudo ./install.sh --domain sync.example.com` in that folder: it keeps the settings and the data, and adds the rest.

## Install by hand with Docker

```sh
git clone https://github.com/SinaXhpm/submarine-sync-server.git
cd submarine-sync-server
./setup.sh                 # makes .env with random secrets
docker compose up -d       # the server, the database and the hourly clean-up
docker compose exec app php bin/admin.php invite you@example.com
```

The last command prints a code. Enter it in the app (see [Connect the app](#connect-the-app)).

The server now answers on `http://127.0.0.1:8080`, on this computer only. Check it:

```sh
curl http://127.0.0.1:8080/health
docker compose exec app php bin/admin.php check
```

To reach it from your other devices, add HTTPS. The [`submarine-sync` command](#manage-the-server) works here too (`sudo ./submarine-sync status`); for the daily backup, copy the two files in `deploy/systemd/` to `/etc/systemd/system/`, link the command to `/usr/local/bin/submarine-sync`, and run `systemctl enable --now submarine-sync-backup.timer`.

## HTTPS

The compose file includes [Caddy](https://caddyserver.com), which gets a Let's Encrypt certificate and renews it for you. The [one-command install](#install-on-a-server-with-one-command) sets it up; by hand, you need:

- a domain name, for example `sync.example.com`, whose DNS record points at this machine;
- ports 80 and 443 open to the internet (Let's Encrypt checks the domain through them).

Put the name in `.env`, and switch Caddy on there:

```sh
SUBMARINE_DOMAIN=sync.example.com
COMPOSE_PROFILES=https
```

Then start again:

```sh
docker compose up -d
```

(`COMPOSE_PROFILES=https` does what `docker compose --profile https ...` does, for every command.) The sync server address for the app is then `https://sync.example.com`.

**Your own reverse proxy instead** (nginx, Traefik, another Caddy): send it to the app container's port (`127.0.0.1:8080` by default), and tell the server to believe that proxy about the client's address, or every user shares its rate limits. Requests from a proxy on the host reach the container from Docker's network gateway, not from 127.0.0.1, so set `SUBMARINE_TRUSTED_PROXIES` to that network, for example `172.16.0.0/12` (`docker network inspect submarine-sync_default` shows the exact gateway). `php bin/admin.php check` lists the addresses the server saw in the last hour: if nearly everything comes from one private address, that is the proxy and it isn't trusted yet. See [Settings](#settings).

**IPv6.** If the domain also has an AAAA record, devices that connect over IPv6 work, but Docker passes their connections on through a proxy of its own, so the server sees that proxy's address for all of them, and they share one set of rate limits (`submarine-sync check` then lists a `172.x.x.1` address). With Docker 27 or newer, Docker's network can get IPv6 too, and they keep their own addresses:

```sh
sudo submarine-sync set SUBMARINE_IPV6=true
cd /opt/submarine-sync && sudo docker compose down && sudo submarine-sync start   # the network is made again
curl -6 https://sync.example.com/health                                          # from a machine with IPv6
```

If that last request fails, your machine's firewall setup doesn't let Docker forward IPv6: set it back with `SUBMARINE_IPV6=false` and the same two commands. (Removing the AAAA record is the other way to keep every user's own address.)

**No domain name?** Reach the server through an SSH tunnel: forward a local port to the server's `127.0.0.1:8080` (Submarine can do that itself, with a local port forward on the server's SSH connection), and use `http://localhost:<port>` as the sync server address. Plain http to localhost is allowed, because the traffic stays inside the tunnel.

## Accounts and invitations

By default the server takes new accounts **by invitation** (`SUBMARINE_SIGNUP=invite`), and no mail is needed:

```sh
sudo submarine-sync invite friend@example.com      # a code to make the account
sudo submarine-sync reset-code friend@example.com  # a code to set a new password
sudo submarine-sync list
sudo submarine-sync suspend friend@example.com     # sign out everywhere and stop the account; unsuspend
sudo submarine-sync signout friend@example.com     # sign out every device
sudo submarine-sync delete friend@example.com      # the account and everything it holds
```

Without the `submarine-sync` command, the same are `docker compose exec app php bin/admin.php invite friend@example.com` and so on, or `php bin/admin.php ...` in the server's folder without Docker. Signing out and suspending also cancel the account's unused codes.

Give the code to the person in a private way. It works once, an invitation for 7 days and a reset code for 24 hours. For a reset code, the person chooses **Sign in**, **Forgot password?** and **Already have a reset token? Continue** in the app. Codes are shown only when they are made. The server keeps only a keyed hash of them and never writes them to a log.

With `SUBMARINE_SIGNUP=open`, anyone who can reach the server can make an account in the app and gets their code by mail. That needs [mail](#mail). Things to know then:

- `SUBMARINE_MAX_ACCOUNTS` counts finished accounts only: sign-ups that are never finished don't fill the server, and the hourly clean-up removes them after 7 days. Once the server is full, sign-up says "no new accounts" to everybody, whatever the address, and a sign-up code can't finish an account any more. Your own invitations are never held back.
- The server sends at most `SUBMARINE_MAIL_PER_HOUR` mails (200 by default), and sign-up codes may use half of them, so a flood of sign-ups for made-up addresses can't hold back the reset and sign-in codes of real accounts. When an hour's mail is used up, no new codes are made, and the ones already sent keep working. Per-address limits slow floods down too (5 sign-ups an hour per address, 3 per email).
- An invitation you made stays valid even if someone signs up with the same address meanwhile.
- Email addresses are taken in their usual plain form only: printable ASCII, no quoted names.

## The web admin panel

The command line can do everything. If you prefer a page in the browser, switch on the panel:

```sh
sudo submarine-sync admin-password
```

It asks for a password (12 characters or more; `--generate` makes one), stores only its hash in `.env`, puts the panel at an address nobody guesses (for example `https://sync.example.com/admin-3f9a1c0e72b4`) and restarts the server. The address keeps password guessers away; on a guessed address, they could also set off the sign-in lock below. It shows the accounts with their status, dates, number of profiles and storage, and some totals. It can make invitation and reset codes, suspend, sign out and delete accounts. It never shows what is inside a profile.

Without the `submarine-sync` command: make the hash with `docker compose run --rm app php bin/admin.php hash-password`, paste the line it prints into `.env` with its single quotes (`SUBMARINE_ADMIN_PASSWORD_HASH='$2y$12$...'`), choose a path (`SUBMARINE_ADMIN_PATH`, `/admin` if you don't), and run `docker compose up -d`.

It only opens over HTTPS. To use it from a browser on the server itself without HTTPS, set `SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL=1` and open it as `http://localhost:8080/...` (also through an SSH tunnel): the address must name `localhost` or `127.0.0.1`, and the connection must come from the server itself. A request that came through any proxy still needs HTTPS. Five sign-in tries from one address, or fifty from anywhere within an hour, close sign-in for a while; the command line keeps working.

## Mail

Mail is needed only for open sign-up and for "forgot password" or "sign in by email" from the app. Set an SMTP server in `.env`:

```sh
SUBMARINE_MAIL_TRANSPORT=smtp
SUBMARINE_MAIL_FROM=sync@example.com
SUBMARINE_SMTP_HOST=smtp.example.com
SUBMARINE_SMTP_PORT=587
SUBMARINE_SMTP_SECURITY=starttls     # or tls (port 465), or none (a relay on this machine only)
SUBMARINE_SMTP_USER=sync@example.com
SUBMARINE_SMTP_PASSWORD=...
```

With `starttls`, nothing is sent if the mail server doesn't offer encryption, so the SMTP password never goes out in the clear. On plain PHP hosting, `mail` uses the host's own mail system instead (`SUBMARINE_MAIL_TRANSPORT=mail`).

## Install on PHP hosting without Docker

For shared hosting with cPanel or similar, or your own Apache with PHP.

1. **Database.** Make a MariaDB or MySQL database and a user with all rights on it.
2. **Files.** Upload this folder, for example to `submarine-sync-server` next to `public_html`. Point a (sub)domain's document root at its **`public/`** folder. If your host can't do that, put the whole folder in the web root: its `.htaccess` sends every request to `public/index.php`, and nothing else in the folder can be downloaded.
3. **Settings.** Copy `config.example.php` to `config.php` and fill in the database, a token pepper (`openssl rand -hex 32`, or 64 random letters and digits) and the rest you need.
4. **Tables.** Run `php bin/migrate.php` in the host's terminal, or import `schema.sql` with phpMyAdmin.
5. **Clean-up.** Add a cron job that runs every hour: `php /path/to/submarine-sync-server/bin/cron.php`.
6. **HTTPS.** Most hosts give a free certificate (AutoSSL or Let's Encrypt). Switch it on for the domain.
7. **Check and invite.** `php bin/admin.php check`, then `php bin/admin.php invite you@example.com`. Without a terminal, switch on the [web admin panel](#the-web-admin-panel) and invite from there.

PHP needs the extensions `pdo_mysql`, `mbstring`, `openssl` and `zlib` (most hosts have them). The `.user.ini` in `public/` sets PHP's limits on hosts that read it.

The app sends a verify token as `GET /auth/verify?token=...`, and many hosts keep the query string in their access log. A token works once and the app uses it right away, so the risk is small; still, keep that log private. (The Docker image leaves query strings out of its log.)

**nginx** instead of Apache: serve `public/` and send every request to `index.php`:

```nginx
root /path/to/submarine-sync-server/public;
client_max_body_size 6m;
location / {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root/index.php;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

## Settings

Docker reads them from `.env`. Without Docker, use `config.php` (copied from `config.example.php`); environment variables override it.

| Environment variable | In config.php | Default | What it does |
|---|---|---|---|
| `SUBMARINE_DB_HOST`, `_PORT`, `_NAME`, `_USER`, `_PASSWORD` | `db` | `127.0.0.1`, `3306`, `submarine`, `submarine`, empty | The database. |
| `SUBMARINE_TOKEN_PEPPER` | `security.token_pepper` | none, required | A secret of 32+ characters mixed into every stored token hash. Changing it signs everybody out. |
| `SUBMARINE_SIGNUP` | `signup` | `invite` | `invite` or `open` (open needs mail). |
| `SUBMARINE_MAX_ACCOUNTS` | `max_accounts` | `0` | The most finished accounts sign-up may make; 0 means no limit. Your invitations are never held back by it. |
| `SUBMARINE_BASE_PATH` | `base_path` | empty | A path in front of every address, for example `/submarine`. The app's server address is then `https://example.com/submarine`. |
| `SUBMARINE_TRUSTED_PROXIES` | `security.trusted_proxies` | empty (Docker: `caddy`) | Comma-separated IP addresses, CIDR ranges or host names of reverse proxies in front of the server. Only they may name the client's address. |
| `SUBMARINE_CLIENT_IP_HEADER` | `security.client_ip_header` | `X-Forwarded-For` | Where they name it: `X-Forwarded-For`, `X-Real-IP` or `CF-Connecting-IP`. |
| `SUBMARINE_KEYS_NEED_PASSWORD` | `security.keys_need_password` | off | Setting up a sharing key for the first time takes the account password too. Turn it on once your apps send it; see [Security](#security). |
| `SUBMARINE_MAIL_TRANSPORT` | `mail.transport` | `off` | `off`, `smtp` or `mail`. |
| `SUBMARINE_MAIL_FROM`, `SUBMARINE_MAIL_FROM_NAME` | `mail.from_address`, `mail.from_name` | empty, `Submarine sync` | The sender. |
| `SUBMARINE_SMTP_HOST`, `_PORT`, `_SECURITY`, `_USER`, `_PASSWORD` | `mail.smtp_*` | empty, `587`, `starttls`, empty, empty | The SMTP server. Without a user name the server is not asked to sign in. |
| `SUBMARINE_SMTP_VERIFY_PEER` | `mail.smtp_verify_peer` | on | Check the mail server's certificate. Turn off only for a relay with a certificate of its own on your own network. |
| `SUBMARINE_MAIL_PER_HOUR` | `mail.per_hour` | `200` | The most mails the server sends in an hour. |
| `SUBMARINE_ADMIN_PASSWORD_HASH` | `admin.password_hash` | empty (panel off) | From `php bin/admin.php hash-password`. |
| `SUBMARINE_ADMIN_PATH` | `admin.path` | `/admin` | Where the panel is. |
| `SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL` | `admin.allow_http_local` | off | Let a browser on this machine open the panel over plain http. |
| `SUBMARINE_QUOTA_MB` | `quota.bytes` (in bytes) | `5` | Storage per account and per shared profile. |
| `SUBMARINE_QUOTA_RECORDS`, `_PROFILES`, `_SHARES` | `quota.records`, `.profiles`, `.shares` | `20000`, `100`, `50` | More caps per account. |
| `SUBMARINE_TOKEN_TTL_DAYS` | `token_ttl_seconds` | `90` | How long a device stays signed in. |
| `SUBMARINE_LOGIN_FLOOR_MS` | `limits.login_fail_floor_ms` | `1000` | Every failed sign-in is answered at this moment, so its timing doesn't tell whether an email has an account. `bin/admin.php check` tells you if it is too low for this machine. |

Docker only: `SUBMARINE_DOMAIN` (for HTTPS), `COMPOSE_PROFILES` (`https` starts Caddy), `SUBMARINE_HTTP_BIND` and `SUBMARINE_HTTP_PORT` (where the app container listens, `127.0.0.1:8080`), `SUBMARINE_IPV6` (see [IPv6](#https)), `SUBMARINE_DB_PASSWORD` and `MARIADB_ROOT_PASSWORD` (read only when the database is made: don't change them afterwards). For the `submarine-sync` command: `SUBMARINE_BACKUP_DIR` (`/var/backups/submarine-sync`) and `SUBMARINE_BACKUP_KEEP` (`14`).

The rate limits and code lifetimes are in `src/lib/Config.php` and can be changed in `config.php` under `limits`.

If a setting is wrong, the Docker container doesn't start, and `submarine-sync check` (or `docker compose logs app`) says which setting. On PHP hosting, the server answers every request with error 500 `misconfigured`, its log says which setting, and `php bin/admin.php check` lists the problems.

## Backups and upgrades

**With the `submarine-sync` command** (the [one-command install](#install-on-a-server-with-one-command) sets it up):

- A backup is made every day at about 03:30 (a systemd timer) into `/var/backups/submarine-sync`, and the newest 14 are kept. `sudo submarine-sync backup` makes one now; `sudo submarine-sync backups` lists them.
- A backup is one file with the database and `.env`. `.env` holds the secrets, so keep backups private. Copy them to another machine now and then: a backup on the server itself is lost with the server. For example, from your computer: `scp root@sync.example.com:/var/backups/submarine-sync/<file> .`
- `sudo submarine-sync restore <file>` puts a backup's database back. It makes a backup of the database as it is first, and brings back the backup's token pepper too, so devices stay signed in.
- To move to a new server: install there with `install.sh`, copy a backup over, and restore it.
- `sudo submarine-sync update` makes a backup, moves to the newest release, rebuilds the image with the newest builds of its base images, and restarts. If the new version doesn't start, it goes back to the old one. `update v1.2.3` picks a release.

**By hand with Docker**, in the server's folder. A backup of the database, as one consistent snapshot that doesn't stop the server (the password is read inside the container):

```sh
docker compose exec -T db sh -c 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb-dump -uroot --single-transaction --quick submarine' > submarine-backup.sql
```

Keep `.env` with it. Without the token pepper, the data is still there, but every device has to sign in again. To restore:

```sh
docker compose stop app cron
docker compose exec -T db sh -c 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb -uroot submarine' < submarine-backup.sql
docker compose up -d
```

To upgrade:

```sh
git pull
docker compose build --pull
docker compose up -d
```

The app container runs `bin/migrate.php` when it starts: it makes missing tables and applies the changes a new version brings to existing ones. Without Docker, replace the files (keep `config.php`) and run `php bin/migrate.php`.

## Limits

Per account (all can be changed, see [Settings](#settings)):

- 5 MB of encrypted profile data, 20,000 records and 100 profiles;
- 50 shared profiles it owns, each with 5 MB and 20,000 records;
- one sync request carries at most 5,000 records and 4 MB.

Rate limits per address: 180 requests a minute in all, 15 sign-in attempts in 5 minutes, 5 sign-ups an hour. Five wrong passwords pause password sign-in for that account for 15 minutes; a sign-in code by mail, or a reset code from the admin, still works.

## Security

**What the server can't see.** The contents of your profiles: servers, passwords, keys, notes and the rest. They are encrypted on your devices with keys that never reach the server. A shared profile's key reaches the server only sealed to each member's public key.

**What the server does see**, and so whoever runs it:

- account emails, sign-up and sign-in times, and the IP addresses of sign-ins and syncs (in the event log, kept 90 days);
- profile names as you named them, shared profile names, and who shares with whom;
- how many records each profile holds, their sizes, their kinds (server, folder, key...) and when they changed.

**Sharing trusts the server.** To share a profile, the app asks the server for the other account's public key. A dishonest server operator could hand out a key of their own. Share profiles only on a server whose operator you trust, which is the case when that is you.

**The first sharing key and a stolen sign-in.** Replacing an account's sharing key takes the account password. Setting it up the first time takes it only if the app sends it, and the apps released so far send only their sign-in token there. So someone who stole a device's sign-in token (not the password) could set up a key of their own on an account that has none yet, and read profiles shared with that account later. When mail is on, the account's email gets a note each time a first key is set up. Once your apps send the password, set `SUBMARINE_KEYS_NEED_PASSWORD=1`.

**Passwords** are 8 to 72 bytes: bcrypt, which stores them, ignores everything after the 72nd byte.

**How it protects accounts.** Passwords are stored as bcrypt hashes. Sign-in tokens and one-time codes are stored only as keyed hashes. Answers about accounts take the same time and say the same thing whether or not the email has an account. There are rate limits and a lockout against password guessing. Replacing a sharing key and deleting an account take the password, not only a sign-in token. Request bodies are capped, also when gzipped.

**Docker defaults.** The database has no published port. The app container listens on `127.0.0.1` only, runs as `www-data` on a read-only file system with no extra capabilities, and its access log leaves out query strings. Each container keeps at most 30 MB of logs.

**Keep it up to date.** `sudo submarine-sync update` brings the newest release and the newest builds of the base images (PHP, MariaDB, Caddy) with their security fixes; `submarine-sync status` says when a release is out.

Found a security problem? See [SECURITY.md](SECURITY.md).

## Tests

The `tests/` folder holds suites that run against a server you start for testing. They **empty its database**, so never point them at a real one. A test of `install.sh` and `submarine-sync` runs on a machine made for testing. See [tests/README.md](tests/README.md).

## Help

- Problems with this server: open an issue in this repository.
- The app: [Submarine](https://github.com/SinaXhpm/Submarine).

MIT license, see [LICENSE](LICENSE).
