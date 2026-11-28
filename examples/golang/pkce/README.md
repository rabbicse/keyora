# Go client: authorization code flow with PKCE

A small command-line program that runs the OAuth 2.0 **authorization code flow with
PKCE** against Keyora, the way a mobile, desktop or single-page app does it in code.

Keyora is API only: it serves no pages and redirects no browser. The app collects the
email and password in its own interface (here, environment variables) and the whole
sign-in is two calls:

```
1. POST /api/v1/oauth/authorize   request + email + password + code_challenge  ->  code
2. POST /api/v1/oauth/token       code + code_verifier                         ->  tokens
```

The program is registered as a **public** application — it has no client secret. PKCE
is what makes that safe: a code is worthless without the verifier, which never leaves
the app.

## Prerequisites

- Go 1.24 or newer
- A running Keyora, prepared with `examples/setup.sh`, which registers the public
  application `example-pkce` with the redirect URI `com.example.keyora-pkce:/callback`
- A user to sign in as (the curl below creates one)

## Installation

No third-party dependencies.

```sh
cd examples/golang/pkce
go build ./...
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where Keyora is reached |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | `iss` required in tokens and in the authorization response |
| `KEYORA_PKCE_CLIENT_ID` | *(required)* | Client ID of the public application |
| `KEYORA_PKCE_REDIRECT_URI` | `com.example.keyora-pkce:/callback` | Must equal a registered `redirect_uris` entry exactly |
| `DEMO_EMAIL` | `ada@example.com` | User to sign in as |
| `DEMO_PASSWORD` | `correct horse battery` | That user's password |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a

# a user to sign in with
curl -X POST "$KEYORA_URL/api/v1/auth/register" -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" \
  -H 'Content-Type: application/json' -d '{"email":"ada@example.com","password":"correct horse battery"}'

(cd examples/golang/pkce && go run .)
```

Output of a real run:

```
1. authorize, wrong password   -> 401 invalid_credentials
2. authorize                   -> 200 code=kyc_4aj9jTFk9p-U... expires_in=60
3. token (authorization_code)  -> 200 access_token=eyJhbGciOiJSUzI1... refresh_token=kyr_jiQQUugk1agu... id_token=true
4. token, same code again      -> 400 invalid_grant
5. verify locally              -> sub=af237240-5e9b-4b... email=ada@example.com
6. userinfo                    -> 200 email=ada@example.com
7. token (refresh_token)       -> 200 new refresh_token=true
8. token, old refresh token    -> 400 invalid_grant
9. logout                      -> 204
```

## The two calls

Request the code:

```sh
curl -X POST "$KEYORA_URL/api/v1/oauth/authorize" -H 'Content-Type: application/json' -d '{
  "client_id": "'$KEYORA_PKCE_CLIENT_ID'", "redirect_uri": "com.example.keyora-pkce:/callback",
  "state": "af0ifjsldkj", "scope": "openid email profile",
  "code_challenge": "<BASE64URL(SHA256(verifier))>", "code_challenge_method": "S256",
  "email": "ada@example.com", "password": "correct horse battery"}'
# 200 {"data":{"code":"kyc_lcP7…","state":"af0ifjsldkj","redirect_uri":"com.example.keyora-pkce:/callback",
#      "redirect_to":"com.example.keyora-pkce:/callback?code=kyc_lcP7…&iss=http%3A%2F%2Flocalhost%3A8080&state=af0ifjsldkj",
#      "expires_in":60,"iss":"http://localhost:8080"},"meta":{"request_id":"…"}}
# wrong password: 401 {"error":{"code":"invalid_credentials","message":"invalid email or password"},"meta":{…}}
```

Exchange it:

```sh
curl "$KEYORA_URL/api/v1/oauth/token" \
  -d grant_type=authorization_code -d client_id=$KEYORA_PKCE_CLIENT_ID \
  -d code=kyc_… -d redirect_uri=com.example.keyora-pkce:/callback -d code_verifier=<the verifier>
# 200 {"access_token":"eyJhbGci…","token_type":"Bearer","expires_in":900,"refresh_token":"kyr_…","id_token":"eyJ…",…}
```

## How it works

Everything is in [`main.go`](main.go).

- A random `code_verifier` and `state` are created for every sign-in. Only the
  verifier's SHA-256 (`code_challenge`) is sent with the credentials.
- The authorization answer is checked: `state` must be the one sent, and `iss` must be
  the expected Keyora (RFC 9207).
- The code is exchanged with the verifier. Keyora hashes the verifier and compares it
  with the challenge stored with the code; a code is valid for 60 seconds and once.
  Presenting it again is refused and revokes the session the code opened, which is why
  the program signs in a second time after step 4.
- The access token is verified locally with the `guard` package (signature, expiry,
  issuer, audience, and `token_use`, so an ID token is never accepted in its place).
- Refresh rotates the refresh token: the old one is refused once the new pair exists.

`redirect_uri` is never visited — Keyora redirects nowhere. It must still be
registered, because the code is bound to it and the token request must repeat it. A
private-use scheme such as `com.example.keyora-pkce:/callback` makes that explicit.

In a real app the email and password come from the app's own user interface. A
single-page app makes the same two calls with `fetch`, keeps the verifier in memory or
`sessionStorage`, and has its origin registered in `allowed_origins`; Keyora refuses
the authorization call from any other browser origin.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `authorize failed: 400 invalid_redirect_uri` | `KEYORA_PKCE_REDIRECT_URI` must equal a registered URI character for character. Re-run `examples/setup.sh`, or `PATCH` the application's `redirect_uris`. |
| `authorize failed: 400 invalid_client` | Wrong `KEYORA_PKCE_CLIENT_ID`. |
| `authorize failed: 401 invalid_credentials` | The user does not exist or the password is wrong. Register the user (see above). |
| `authorize failed: 423 account_locked` | Too many wrong passwords. Wait, or unlock the user with the admin API. |
| `unexpected issuer` | `KEYORA_ISSUER` differs from Keyora's own. |
| `access token did not verify` | `KEYORA_ISSUER` or the client ID does not match the token, or this machine's clock is far off. |
