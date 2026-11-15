#!/bin/sh
# Submarine sync server — container start. The web server first makes or
# updates the database tables (waiting for the database to come up); any
# other command (the cron loop, bin/admin.php) runs as it is.
set -e
if [ "$1" = "apache2-foreground" ]; then
    php /var/www/submarine/bin/migrate.php --wait=90
fi
exec "$@"
