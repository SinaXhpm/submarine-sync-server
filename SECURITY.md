# Security

## Reporting a problem

Please send security problems by email to **sinaxhpm@gmail.com**, not as a public issue. Say what you found, how to see it, and which version or commit it is in. You get an answer within a few days, and a fix as soon as it is ready. Tell me if you want to be named in the release notes.

This covers the code in this repository. Security problems in the Submarine app go to the same address.

## Running your own server safely

- Use HTTPS with a real certificate (`install.sh --domain ...`, or the `https` profile in `docker-compose.yml`, does it for you).
- Keep `.env` or `config.php` private, and back them up with the database. The daily backups of `submarine-sync` hold `.env`: keep them private, and keep a copy off the server.
- Keep the server up to date: `sudo submarine-sync update` (by hand: `git pull`, `docker compose build --pull`, `docker compose up -d`).
- Leave sign-up on `invite` unless you want strangers to be able to make accounts.
- If you switch on the web admin panel, keep it at an address nobody guesses (`submarine-sync admin-password` picks one).
- Read the [Security](README.md#security) section of the README for what the server can and can't see.
