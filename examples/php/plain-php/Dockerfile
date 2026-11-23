# For running the example without a local PHP. The official image already
# includes the two extensions the example needs: openssl and curl.
FROM php:8.3-cli

WORKDIR /app
COPY index.php ./
COPY src ./src

ENV PORT=9008 \
    PHP_CLI_SERVER_WORKERS=4

USER www-data
EXPOSE 9008

# The built-in server handles one request at a time unless
# PHP_CLI_SERVER_WORKERS is set. It is a development server.
CMD ["sh", "-c", "exec php -S 0.0.0.0:${PORT} index.php"]
