# Submarine sync server — Apache + PHP in one image. The database runs in its
# own container (see docker-compose.yml).
FROM php:8.4.26-apache-trixie

LABEL org.opencontainers.image.title="Submarine sync server" \
      org.opencontainers.image.source="https://github.com/SinaXhpm/submarine-sync-server" \
      org.opencontainers.image.licenses="MIT"

RUN set -eux; \
    docker-php-ext-install -j"$(nproc)" pdo_mysql; \
    docker-php-ext-enable opcache; \
    a2enmod rewrite headers; \
    a2disconf other-vhosts-access-log; \
    mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"; \
    rm -rf /var/www/html; \
    # Apache listens on 8080, so it runs as www-data, not root.
    echo 'Listen 8080' > /etc/apache2/ports.conf

# Files keep the modes they have in the folder the image is built from, and a
# machine whose umask is 027 or 077 makes them unreadable for www-data: the
# modes are set here, whatever they were there.
COPY --chmod=0644 docker/apache.conf /etc/apache2/sites-available/000-default.conf
COPY --chmod=0644 docker/security.conf /etc/apache2/conf-enabled/zz-submarine.conf
COPY --chmod=0644 docker/php.ini "$PHP_INI_DIR/conf.d/zz-submarine.ini"
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/submarine-entrypoint

WORKDIR /var/www/submarine
COPY --chown=root:root public ./public
COPY --chown=root:root src ./src
COPY --chown=root:root bin ./bin
COPY --chown=root:root schema.sql config.example.php ./
RUN chmod -R u=rwX,go=rX /var/www/submarine

# Tells the admin panel's "browser on this machine" rule that connections from
# the host arrive from the container's gateway (src/admin-panel.php).
ENV SUBMARINE_IN_DOCKER=1

USER www-data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["submarine-entrypoint"]
CMD ["apache2-foreground"]
