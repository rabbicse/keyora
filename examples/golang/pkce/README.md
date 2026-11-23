# Go browser sign-in with PKCE

A small web application that signs users in with the OAuth 2.0 **authorization code
flow with PKCE**. Unlike the API examples, it never handles a password: the browser
goes to Keyora's own sign-in page and comes back with a one-time code.

It is registered as a **public** application — it has no client secret. PKCE is what
makes that safe.

## Prerequisites

- Go 1.24 or newer
- A running Keyora, prepared with `examples/setup.sh`, which registers the public
  application `example-pkce` with the redirect URI `http://localhost:9010/callback`
- A user to sign in as (register one through any API example, or with the curl below)

## Installation

No third-party dependencies.

```sh
cd examples/golang/pkce
go build ./...
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `KEYORA_URL` | `http://localhost:8080` | Where this server reaches Keyora (token endpoint, JWKS) |
| `KEYORA_PUBLIC_URL` | value of `KEYORA_URL` | Where the **browser** reaches Keyora (sign-in page) |
| `KEYORA_ISSUER` | value of `KEYORA_URL` | `iss` required in tokens and in the callback |
| `KEYORA_PKCE_CLIENT_ID` | *(required)* | Client ID of the public application |
| `PORT` | `9010` | Listen port |
| `REDIRECT_URI` | `http://localhost:$PORT/callback` | Must equal a registered `redirect_uris` entry exactly |

## How to run

From the repository root:

```sh
set -a; . examples/.env; set +a

# a user to sign in with
curl -X POST "$KEYORA_URL/api/v1/auth/register" -u "$KEYORA_CLIENT_ID:$KEYORA_CLIENT_SECRET" \
  -H 'Content-Type: application/json' -d '{"email":"ada@example.com","password":"correct horse battery"}'

(cd examples/golang/pkce && go run .)
# PKCE example on http://localhost:9010 (Keyora at http://localhost:8080, client app_781e…)
```

Open <http://localhost:9010>, choose **Sign in with Keyora**, and enter the email and
password on Keyora's page. You are returned to the application, signed in.

## What you will see

| Step | Request | Result |
|---|---|---|
| 1 | `GET localhost:9010/login` | `302` to `…/api/v1/oauth/authorize?response_type=code&client_id=app_…&redirect_uri=http%3A%2F%2Flocalhost%3A9010%2Fcallback&state=…&code_challenge=…&code_challenge_method=S256` |
| 2 | Keyora shows its sign-in page | `200`; "Sign in — to continue to example-pkce" |
| 3 | Wrong password | `401`; the page again with "Incorrect email or password." No redirect. |
| 4 | Correct password | `303` to `http://localhost:9010/callback?code=kyc_…&iss=http%3A%2F%2Flocalhost%3A8080&state=…` |
| 5 | The app exchanges the code | `303` to `/`, which shows "Signed in as ada@example.com" |
| 6 | Replaying the code from step 4 | `400 {"error":"invalid_grant",…}` and the session it opened is revoked |

The token exchange the application performs in step 5:

```sh
curl "$KEYORA_URL/api/v1/oauth/token" \
  -d grant_type=authorization_code -d client_id=$KEYORA_PKCE_CLIENT_ID \
  -d code=kyc_… -d redirect_uri=http://localhost:9010/callback -d code_verifier=<the verifier>
# 200 {"access_token":"eyJhbGci…","token_type":"Bearer","expires_in":900,"refresh_token":"kyr_…","session_id":"…"}
```

## How it works

Everything is in [`main.go`](main.go).

- **`/login`** creates a random `code_verifier` and `state`, keeps both in `HttpOnly`
  cookies, and redirects the browser to Keyora with the verifier's SHA-256
  (`code_challenge`). The verifier itself never appears in a URL.
- **`/callback`** checks that `state` matches the cookie (so the response belongs to a
  flow this browser started) and that `iss` is the expected Keyora (RFC 9207), then
  posts the code and the verifier to the token endpoint. Keyora hashes the verifier and
  compares it with the challenge; a code stolen from the redirect is useless without it.
- The access token is verified with the `guard` package and both tokens are kept in
  `HttpOnly` cookies, out of reach of page JavaScript.
- **`/`** refreshes with `grant_type=refresh_token` when the access token has expired,
  storing the rotated pair.
- **`/logout`** revokes the session at Keyora.

Against Keyora: the browser redirect, the code exchange, refresh, logout. Inside this
application: creating the verifier and state, checking state and issuer, verifying the
token.

Because this application has a server, it could equally be registered as
*confidential* and also send its secret when exchanging the code; Keyora requires PKCE
either way. A single-page app does the same steps in the browser, keeping the verifier
in `sessionStorage` and registering its origin in `allowed_origins`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Keyora shows "The redirect URI is not registered for this application." | `REDIRECT_URI` must equal a registered URI character for character — scheme, host, port and path. Changing `PORT` changes it; re-run `examples/setup.sh` with `PKCE_REDIRECT_URI` set, or `PATCH` the application. |
| Keyora shows "The application is unknown or disabled" | Wrong `KEYORA_PKCE_CLIENT_ID`. |
| "Sign-in failed: state mismatch." | Cookies were lost between `/login` and `/callback`: the flow was started on one host name (`127.0.0.1`) and finished on another (`localhost`), or it took longer than ten minutes. |
| "Sign-in failed: unexpected issuer." | `KEYORA_ISSUER` differs from Keyora's own. |
| "Sign-in failed: the code could not be exchanged." | The code is older than 60 seconds, was already used, or the page was reloaded on `/callback`. Start again from `/login`. |
| "Your sign-in page expired." on Keyora | The sign-in page was open for more than ten minutes, or cookies are blocked. |
| Browser cannot reach the sign-in page but the server can reach Keyora | Set `KEYORA_PUBLIC_URL` to the address the browser should use. |
