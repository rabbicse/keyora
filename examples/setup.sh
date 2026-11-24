#!/usr/bin/env bash
# Prepares a running Keyora for the examples: creates a tenant, an application,
# two permissions and two roles, and writes the resulting settings to
# examples/.env. Needs only bash and curl.
#
#   KEYORA_URL=http://localhost:8080 KEYORA_ADMIN_KEY=... ./examples/setup.sh
set -euo pipefail

KEYORA_URL="${KEYORA_URL:-http://localhost:8080}"
: "${KEYORA_ADMIN_KEY:?set KEYORA_ADMIN_KEY to the value Keyora was started with}"
OUT="$(cd "$(dirname "$0")" && pwd)/.env"

api() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}" response status
  response="$(curl -sS -X "$method" "$KEYORA_URL$path" \
    -H "Authorization: Bearer $KEYORA_ADMIN_KEY" -H "Content-Type: application/json" \
    ${body:+-d "$body"} -w $'\n%{http_code}')"
  status="${response##*$'\n'}"
  if [ "$status" -ge 300 ]; then
    echo "error: $method $path returned $status: ${response%$'\n'*}" >&2
    exit 1
  fi
  printf '%s' "${response%$'\n'*}"
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1; }

curl -sSf "$KEYORA_URL/readyz" >/dev/null || { echo "error: Keyora is not reachable at $KEYORA_URL" >&2; exit 1; }

TENANT_ID="$(api POST /api/v1/tenants "{\"slug\":\"examples-$(date +%s)\",\"name\":\"Keyora examples\"}" | field id)"
T="/api/v1/tenants/$TENANT_ID"

# A 60-second access token keeps the "expired token" scenario quick to observe.
# The redirect URI is never visited: verify.py uses it to obtain an ID token and
# check that the example refuses it as an API credential.
VERIFY_REDIRECT_URI="http://localhost:9099/verify-callback"
APP="$(api POST "$T/applications" "{\"name\":\"example-app\",\"type\":\"confidential\",\"access_token_ttl_seconds\":60,\"redirect_uris\":[\"$VERIFY_REDIRECT_URI\"]}")"
CLIENT_ID="$(printf '%s' "$APP" | field client_id)"
CLIENT_SECRET="$(printf '%s' "$APP" | field client_secret)"
# A second application, used to show that tokens issued to another audience are rejected.
OTHER="$(api POST "$T/applications" '{"name":"other-app","type":"confidential"}')"

# A public application (no secret) for the authorization code + PKCE example.
PKCE_REDIRECT_URI="${PKCE_REDIRECT_URI:-http://localhost:9010/callback}"
PKCE="$(api POST "$T/applications" "{\"name\":\"example-pkce\",\"type\":\"public\",\"redirect_uris\":[\"$PKCE_REDIRECT_URI\"]}")"

api POST "$T/permissions" '{"name":"notes:read","description":"Read notes"}' >/dev/null
api POST "$T/permissions" '{"name":"notes:write","description":"Create notes"}' >/dev/null
READER_ID="$(api POST "$T/roles" '{"name":"reader","permissions":["notes:read"]}' | field id)"
EDITOR_ID="$(api POST "$T/roles" '{"name":"editor","permissions":["notes:read","notes:write"]}' | field id)"

umask 077
cat > "$OUT" <<ENV
# Written by examples/setup.sh. Contains secrets: do not commit.
KEYORA_URL=$KEYORA_URL
KEYORA_ISSUER=${KEYORA_ISSUER:-$KEYORA_URL}
KEYORA_CLIENT_ID=$CLIENT_ID
KEYORA_CLIENT_SECRET=$CLIENT_SECRET
# Public application used by examples/golang/pkce (redirects to $PKCE_REDIRECT_URI).
KEYORA_PKCE_CLIENT_ID=$(printf '%s' "$PKCE" | field client_id)

# Used only by examples/verify.py to grant roles and to mint a foreign token.
KEYORA_ADMIN_KEY=$KEYORA_ADMIN_KEY
KEYORA_TENANT_ID=$TENANT_ID
KEYORA_READER_ROLE_ID=$READER_ID
KEYORA_EDITOR_ROLE_ID=$EDITOR_ID
KEYORA_OTHER_CLIENT_ID=$(printf '%s' "$OTHER" | field client_id)
KEYORA_OTHER_CLIENT_SECRET=$(printf '%s' "$OTHER" | field client_secret)
KEYORA_VERIFY_REDIRECT_URI=$VERIFY_REDIRECT_URI
ENV
echo "Wrote $OUT (tenant $TENANT_ID, application $CLIENT_ID)"
