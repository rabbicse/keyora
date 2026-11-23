#!/bin/sh
# Assembles a runnable Laravel application in ./build (or the directory given
# as the first argument): a fresh Laravel skeleton, plus firebase/php-jwt,
# plus the integration files in this directory. Needs PHP 8.3+ and Composer 2.
#
#     ./install.sh
#     cd build && php artisan serve --port=9009 --no-reload
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
target="${1:-$here/build}"

if [ -e "$target" ]; then
    echo "$target already exists; remove it first to reinstall" >&2
    exit 1
fi

# create-project also writes .env and generates APP_KEY.
composer create-project --no-interaction --prefer-dist "laravel/laravel:^13.0" "$target"
(cd "$target" && composer require --no-interaction "firebase/php-jwt:^7.0")

# The integration files replace bootstrap/app.php and add the rest.
for dir in app config routes bootstrap; do
    cp -R "$here/$dir/." "$target/$dir/"
done

# The example needs no database, session or queue: the routes are stateless,
# and the JWKS and the notes live in the file cache.
set_env() {
    if grep -q "^$1=" "$target/.env"; then
        sed -i.bak "s|^$1=.*|$1=$2|" "$target/.env" && rm -f "$target/.env.bak"
    else
        echo "$1=$2" >> "$target/.env"
    fi
}
set_env CACHE_STORE file
set_env SESSION_DRIVER array
set_env QUEUE_CONNECTION sync

cat <<EOF

Installed in $target

Load the Keyora settings and start the application:

    set -a; . "$here/../../.env"; set +a
    cd "$target" && php artisan serve --port=\${PORT:-9009} --no-reload
EOF
