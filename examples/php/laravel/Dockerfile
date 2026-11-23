# Assembles a runnable Laravel application: a fresh Laravel skeleton, plus
# firebase/php-jwt, plus the integration files in this directory. install.sh
# does the same on a machine with PHP and Composer installed.

FROM php:8.3-cli AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1

# create-project also writes .env and generates APP_KEY.
RUN composer create-project --no-interaction --prefer-dist "laravel/laravel:^13.0" /app
WORKDIR /app
RUN composer require --no-interaction "firebase/php-jwt:^7.0"

# The integration files replace bootstrap/app.php and add the rest.
COPY app ./app
COPY config ./config
COPY routes ./routes
COPY bootstrap ./bootstrap


FROM php:8.3-cli
COPY --from=build --chown=www-data:www-data /app /app
WORKDIR /app

# Real environment variables take precedence over the generated .env file.
# The example needs no database, session or queue: the routes are stateless,
# and the JWKS and the notes live in the file cache.
ENV PORT=9009 \
    APP_ENV=production \
    APP_DEBUG=false \
    LOG_CHANNEL=stderr \
    CACHE_STORE=file \
    SESSION_DRIVER=array \
    QUEUE_CONNECTION=sync \
    PHP_CLI_SERVER_WORKERS=4

USER www-data
EXPOSE 9009

# "artisan serve" runs PHP's built-in development server; it is not a
# production server. --no-reload makes it pass the container's environment
# (KEYORA_*) to the server process and honour PHP_CLI_SERVER_WORKERS.
CMD ["sh", "-c", "exec php artisan serve --host=0.0.0.0 --port=${PORT} --no-reload"]
