# Submarine sync server

The server behind **Cloud sync** in [Submarine](https://github.com/SinaXhpm/Submarine), the SSH, SFTP, RDP and VNC client. Run it yourself, and your devices sync their profiles through your own machine instead of Submarine's server.

It keeps the accounts, the encrypted profiles and the shared profiles. Profiles are encrypted on your devices before they are sent. The server stores them and passes them on, but it never has the keys to open them.

This is the same code as Submarine's own sync server, without the parts only that one needs. It speaks the same protocol, so the app needs no changes.

## Contents

- [What you need](#what-you-need)
- [Quick start with Docker](#quick-start-with-docker)
- [HTTPS](#https)
- [Connect the app](#connect-the-app)
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
- **Docker** with Compose, or **PHP hosting** with PHP 8.1+ and MariaDB 10.6+ (MySQL 8.0 works too; from 8.0.20 it logs deprecation notes about `VALUES()` in the sync queries, which are harmless).
- **HTTPS with a real certificate** for devices other than the server itself. The app accepts plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`. It also refuses self-signed certificates and certificates from a private CA. A free Let's Encrypt certificate works; the [HTTPS](#https) section shows the easy way.

## Quick start with Docker

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

To reach it from your other devices, add HTTPS.

## HTTPS

The compose file includes [Caddy](https://caddyserver.com), which gets a Let's Encrypt certificate and renews it for you. You need:

- a domain name, for example `sync.example.com`, whose DNS record points at this machine;
- ports 80 and 443 open to the internet (Let's Encrypt checks the domain through them).

Put the name in `.env`:

```sh
SUBMARINE_DOMAIN=sync.example.com
```

Then start with the `https` profile:

```sh
docker compose --profile https up -d
```

The sync server address for the app is then `https://sync.example.com`.

**Your own reverse proxy instead** (nginx, Traefik, another Caddy): send it to the app container's port (`127.0.0.1:8080` by default), and tell the server to believe that proxy about the client's address, or every user shares its rate limits. Requests from a proxy on the host reach the container from Docker's network gateway, not from 127.0.0.1, so set `SUBMARINE_TRUSTED_PROXIES` to that network, for example `172.16.0.0/12` (`docker network inspect submarine-sync_default` shows the exact gateway). `php bin/admin.php check` lists the addresses the server saw in the last hour: if nearly everything comes from one private address, that is the proxy and it isn't trusted yet. See [Settings](#settings).

**No domain name?** Reach the server through an SSH tunnel: forward a local port to the server's `127.0.0.1:8080` (Submarine can do that itself, with a local port forward on the server's SSH connection), and use `http://localhost:<port>` as the sync server address. Plain http to localhost is allowed, because the traffic stays inside the tunnel.

## Connect the app

In Submarine, open **Cloud sync**:

1. At **Sync server**, choose **Change**, enter your server's address (for example `https://sync.example.com`) and save. The app checks that the server answers.
2. Choose **Have a verify token? Continue verifying**, paste the code from `bin/admin.php invite`, then choose your password.
3. Sign in on your other devices with the same server address, email and password.

A shared profile stays on the server it was shared on. For a personal profile that was synced with another server, the app offers to move it to the server in use.

## Accounts and invitations

By default the server takes new accounts **by invitation** (`SUBMARINE_SIGNUP=invite`), and no mail is needed:

```sh
docker compose exec app php bin/admin.php invite friend@example.com      # a code to make the account
docker compose exec app php bin/admin.php reset-code friend@example.com  # a code to set a new password
docker compose exec app php bin/admin.php list
docker compose exec app php bin/admin.php suspend friend@example.com     # and unsuspend
docker compose exec app php bin/admin.php signout friend@example.com     # sign out every device
docker compose exec app php bin/admin.php delete friend@example.com      # the account and everything it holds
```

Give the code to the person in a private way. It works once, an invitation for 7 days and a reset code for 24 hours. For a reset code, the person chooses **Sign in**, **Forgot password?** and **Already have a reset token? Continue** in the app. Codes are shown only when they are made. The server keeps only a keyed hash of them and never writes them to a log.

With `SUBMARINE_SIGNUP=open`, anyone who can reach the server can make an account in the app and gets their code by mail. That needs [mail](#mail). Things to know then:

- Sign-ups that are never finished count toward `SUBMARINE_MAX_ACCOUNTS` until the hourly clean-up removes them after 7 days. Once the server is full, every sign-up gets "no new accounts", whatever the address.
- The server sends at most `SUBMARINE_MAIL_PER_HOUR` mails (200 by default). Someone sending many sign-ups for different addresses can use that up for an hour, so real codes are held back too. Per-address limits slow that down (5 sign-ups an hour per address, 3 per email).
- An invitation you made stays valid even if someone signs up with the same address meanwhile.

Without Docker, run the same commands as `php bin/admin.php ...` in the server's folder.

## The web admin panel

The command line can do everything. If you prefer a page in the browser, switch on the panel by giving it a password:

```sh
docker compose run --rm app php bin/admin.php hash-password
```

Paste the line it prints into `.env` with its single quotes:

```sh
SUBMARINE_ADMIN_PASSWORD_HASH='$2y$12$...'
```

Then run `docker compose up -d`. The panel is at `/admin` (`SUBMARINE_ADMIN_PATH`), for example `https://sync.example.com/admin`. It shows the accounts with their status, dates, number of profiles and storage, and some totals. It can make invitation and reset codes, suspend, sign out and delete accounts. It never shows what is inside a profile.

It only opens over HTTPS. To use it from a browser on the server itself without HTTPS (`http://localhost:8080/admin`, also through an SSH tunnel), set `SUBMARINE_ADMIN_ALLOW_HTTP_LOCAL=1`; a request that came through any proxy still needs HTTPS. Five sign-in tries from one address, or fifty from anywhere within an hour, close sign-in for a while; the command line keeps working.

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
| `SUBMARINE_MAX_ACCOUNTS` | `max_accounts` | `0` | The most accounts the server takes by sign-up; 0 means no limit. |
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

Docker only: `SUBMARINE_DOMAIN` (for HTTPS), `SUBMARINE_HTTP_BIND` and `SUBMARINE_HTTP_PORT` (where the app container listens, `127.0.0.1:8080`), `SUBMARINE_DB_PASSWORD` and `MARIADB_ROOT_PASSWORD`.

The rate limits and code lifetimes are in `src/lib/Config.php` and can be changed in `config.php` under `limits`.

If a setting is wrong, the server answers every request with error 500 `misconfigured`, and its log says which setting (`docker compose logs app`). `php bin/admin.php check` lists the problems too.

## Backups and upgrades

**Back up** the database. With Docker:

```sh
docker compose exec db sh -c 'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" submarine' > submarine-backup.sql
```

Keep `.env` too. Without the token pepper, the data is still there, but every device has to sign in again.

**Restore**:

```sh
docker compose exec -T db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" submarine' < submarine-backup.sql
```

**Upgrade** with Docker:

```sh
git pull
docker compose build
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

**Docker defaults.** The database has no published port. The app container listens on `127.0.0.1` only, runs as `www-data` on a read-only file system with no extra capabilities, and its access log leaves out query strings.

Found a security problem? See [SECURITY.md](SECURITY.md).

## Tests

The `tests/` folder holds suites that run against a server you start for testing. They **empty its database**, so never point them at a real one. See [tests/README.md](tests/README.md).

## Help

- Problems with this server: open an issue in this repository.
- The app: [Submarine](https://github.com/SinaXhpm/Submarine).

MIT license, see [LICENSE](LICENSE).
