# Security

## Reporting a problem

Please send security problems by email to **sinaxhpm@gmail.com**, not as a public issue. Say what you found, how to see it, and which version or commit it is in. You get an answer within a few days, and a fix as soon as it is ready. Tell me if you want to be named in the release notes.

This covers the code in this repository. Security problems in the Submarine app go to the same address.

## Running your own server safely

- Use HTTPS with a real certificate (the `https` profile in `docker-compose.yml` does it for you).
- Keep `.env` or `config.php` private, and back them up with the database.
- Keep the server up to date: `git pull`, `docker compose build`, `docker compose up -d`.
- Leave sign-up on `invite` unless you want strangers to be able to make accounts.
- Read the [Security](README.md#security) section of the README for what the server can and can't see.
