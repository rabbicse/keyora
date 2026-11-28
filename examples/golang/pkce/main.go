// The OAuth 2.0 authorization code flow with PKCE, API only.
//
// This program plays the part of a public client, such as a mobile, desktop
// or single-page app: it has no client secret, and PKCE is what stops a
// stolen authorization code from being usable by anyone else. Keyora serves
// no pages; the app collects the credentials in its own interface (here,
// environment variables) and everything else is two JSON/form calls:
//
//  1. POST /api/v1/oauth/authorize  request + credentials + code_challenge -> code
//  2. POST /api/v1/oauth/token      code + code_verifier                   -> tokens
//
// It then verifies the access token locally, calls userinfo, refreshes,
// shows that a replayed code and a replayed refresh token are refused, and
// signs out.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rabbicse/keyora/guard"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// randomString returns 32 random bytes, base64url-encoded: 43 characters,
// which is what RFC 7636 asks of a code verifier.
func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type client struct {
	keyora   string
	clientID string
	http     *http.Client
}

// authorize asks Keyora for an authorization code. The answer is the Keyora
// envelope: {"data": {...}} on success, {"error": {"code", "message"}} otherwise.
func (c *client) authorize(ctx context.Context, body map[string]string) (status int, data map[string]any, errCode string, err error) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.keyora+"/api/v1/oauth/authorize", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer res.Body.Close()
	var env struct {
		Data  map[string]any `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
		return res.StatusCode, nil, "", err
	}
	return res.StatusCode, env.Data, env.Error.Code, nil
}

// token posts to the token endpoint, which uses the OAuth 2.0 wire format
// (form in, plain JSON out). A public client sends client_id and no secret.
func (c *client) token(ctx context.Context, form url.Values) (status int, out map[string]any, err error) {
	form.Set("client_id", c.clientID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.keyora+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out, err
}

func (c *client) send(ctx context.Context, method, path, bearer string, body any) (int, map[string]any, error) {
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.keyora+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out, nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func main() {
	keyoraURL := env("KEYORA_URL", "http://localhost:8080")
	issuer := env("KEYORA_ISSUER", keyoraURL)
	clientID := os.Getenv("KEYORA_PKCE_CLIENT_ID")
	redirectURI := env("KEYORA_PKCE_REDIRECT_URI", "com.example.keyora-pkce:/callback")
	email := env("DEMO_EMAIL", "ada@example.com")
	password := env("DEMO_PASSWORD", "correct horse battery")
	if clientID == "" {
		log.Fatal("KEYORA_PKCE_CLIENT_ID is required (run examples/setup.sh)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := &client{keyora: keyoraURL, clientID: clientID, http: &http.Client{Timeout: 10 * time.Second}}
	g, err := guard.New(guard.Config{Issuer: issuer, Audience: clientID, JWKSURL: keyoraURL + "/.well-known/jwks.json"})
	if err != nil {
		log.Fatal(err)
	}

	// A fresh verifier and state for every sign-in. The verifier stays in this
	// process; only its SHA-256 (the challenge) is sent with the credentials.
	verifier, state := randomString(), randomString()
	sum := sha256.Sum256([]byte(verifier))
	request := map[string]string{
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"response_type":         "code",
		"scope":                 "openid email profile",
		"state":                 state,
		"nonce":                 randomString(),
		"code_challenge":        base64.RawURLEncoding.EncodeToString(sum[:]),
		"code_challenge_method": "S256",
	}

	// 1. Wrong password: an error code the app can show, nothing else.
	wrong := map[string]string{"email": email, "password": password + "-wrong"}
	for k, v := range request {
		wrong[k] = v
	}
	status, _, code, err := c.authorize(ctx, wrong)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("1. authorize, wrong password   -> %d %s\n", status, code)

	// 2. Correct credentials: a single-use code.
	creds := map[string]string{"email": email, "password": password}
	for k, v := range request {
		creds[k] = v
	}
	status, data, code, err := c.authorize(ctx, creds)
	if err != nil || status != http.StatusOK {
		log.Fatalf("authorize failed: %d %s %v (register the user first; see README)", status, code, err)
	}
	authCode, _ := data["code"].(string)
	// state ties the answer to this request; iss (RFC 9207) says which server answered.
	if got, _ := data["state"].(string); subtle.ConstantTimeCompare([]byte(got), []byte(state)) != 1 {
		log.Fatal("state mismatch")
	}
	if data["iss"] != issuer {
		log.Fatalf("unexpected issuer %v", data["iss"])
	}
	fmt.Printf("2. authorize                   -> %d code=%s expires_in=%v\n", status, short(authCode), data["expires_in"])

	// 3. Exchange the code, proving with the verifier that we started the flow.
	exchange := url.Values{"grant_type": {"authorization_code"}, "code": {authCode},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	status, tok, err := c.token(ctx, exchange)
	if err != nil || status != http.StatusOK {
		log.Fatalf("code exchange failed: %d %v %v", status, tok, err)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	_, hasID := tok["id_token"]
	fmt.Printf("3. token (authorization_code)  -> %d access_token=%s refresh_token=%s id_token=%v\n",
		status, short(access), short(refresh), hasID)

	// 4. The same code again: refused, and Keyora revokes the session it opened.
	//    (So this demo signs in once more afterwards.)
	status, replay, _ := c.token(ctx, exchange)
	fmt.Printf("4. token, same code again      -> %d %v\n", status, replay["error"])

	status, data, _, _ = c.authorize(ctx, creds)
	authCode, _ = data["code"].(string)
	exchange.Set("code", authCode)
	_, tok, _ = c.token(ctx, exchange)
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)

	// 5. Verify the access token locally: signature, exp, iss, aud, token_use.
	claims, err := g.Verify(ctx, access)
	if err != nil {
		log.Fatalf("access token did not verify: %v", err)
	}
	fmt.Printf("5. verify locally              -> sub=%s email=%s\n", short(claims.Subject), claims.Email)

	// 6. userinfo with the access token.
	status, info, _ := c.send(ctx, http.MethodGet, "/api/v1/oauth/userinfo", access, nil)
	fmt.Printf("6. userinfo                    -> %d email=%v\n", status, info["email"])

	// 7. Refresh: the old refresh token stops working; store the new pair.
	status, next, _ := c.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	fmt.Printf("7. token (refresh_token)       -> %d new refresh_token=%v\n", status, next["refresh_token"] != refresh)
	status, reused, _ := c.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
	fmt.Printf("8. token, old refresh token    -> %d %v\n", status, reused["error"])

	// 9. Sign out with the refresh token from step 7.
	status, _, _ = c.send(ctx, http.MethodPost, "/api/v1/auth/logout", "",
		map[string]string{"client_id": clientID, "refresh_token": fmt.Sprint(next["refresh_token"])})
	fmt.Printf("9. logout                      -> %d\n", status)
}
