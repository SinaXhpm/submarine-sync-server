# Tests

End-to-end suites: each one talks to a running server over HTTP and to its database directly, to set things up and check them.

**They empty the database.** Run them only against a server and database made for testing.

## Run them

1. Make an empty database and a `config.php` for it (outside this folder is fine), with `db` and `security.token_pepper` set. Nothing else: the suites change other settings themselves and put the file back afterwards.
2. Make the tables: `SUBMARINE_CONFIG_FILE=/path/to/test-config.php php bin/migrate.php`
3. Start a test server **without opcache** (otherwise it keeps old settings for a moment):

   ```sh
   SUBMARINE_CONFIG_FILE=/path/to/test-config.php PHP_CLI_SERVER_WORKERS=6 \
     php -d opcache.enable=0 -S 127.0.0.1:18120 public/index.php 2>> /tmp/submarine-test.log
   ```

4. Run the suites:

   ```sh
   export SUBMARINE_CONFIG_FILE=/path/to/test-config.php
   export SUBMARINE_TEST_DISPOSABLE=1                      # says the database may be emptied
   export SUBMARINE_TEST_URL=http://127.0.0.1:18120        # the default
   export SUBMARINE_TEST_SERVER_LOG=/tmp/submarine-test.log  # optional: checks no code reaches the log
   for t in tests/*-test.php; do php "$t" || echo "FAILED: $t"; done
   ```

Each suite prints `PASS` or `FAIL` per check and ends with `ALL PASS` or the number that failed.

| Suite | What it covers |
|---|---|
| `api-test.php` | What the apps do, end to end; request rules; record checks; the caps; invitations and open sign-up; the base path; client addresses behind proxies; bad settings. |
| `auth-test.php` | The lockout, timing, single-use codes under a race, mail caps, rate limits, sharing rules, the sharing key, account deletion, suspended accounts. |
| `delta-test.php` | Delta sync: revisions, epochs, what comes back. |
| `gzip-test.php` | Gzipped sync bodies and answers, and their limits. |
| `json-shape-test.php` | The guard against JSON bodies made to be slow to parse (no server needed). |
| `admin-test.php` | The web admin panel and `bin/admin.php`, `bin/cron.php`, `bin/migrate.php`. |
| `mail-test.php` | Mail through a fake SMTP server (`fake-smtp.php`, ports 18125-18126): STARTTLS required, contents, codes. Needs `openssl`. |
| `config-test.php` | Every setting in the README's table reaches the settings, and `docker-compose.yml` passes it on (no server needed). |
| `smoke-test.php` | A round trip as the app does it, over HTTP only; safe on a server with real accounts (it deletes the ones it makes). |

## Docker

`tests/docker/e2e.sh` builds the image and runs a whole stack under its own compose project (`submarine-e2e`), its own settings file in a temporary folder, its own image tag and ports (18080, and 18443 with Caddy and its own test CA). It never reads or changes your `.env` or your running project, and removes its containers and volumes at the end. It refuses to start without the same switch:

```sh
SUBMARINE_TEST_DISPOSABLE=1 sh tests/docker/e2e.sh
```

The suites need PHP's `curl` extension, besides what the server needs. Some checks measure answer times; on a very busy machine they can fail for that reason alone.
