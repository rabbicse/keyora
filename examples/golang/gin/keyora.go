package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// keyoraClient calls Keyora's REST API on behalf of this application. It
// holds the client secret, which is why it lives on the server and never in
// a browser.
type keyoraClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	http         *http.Client
}

func newKeyoraClient(baseURL, clientID, clientSecret string) *keyoraClient {
	return &keyoraClient{baseURL: baseURL, clientID: clientID, clientSecret: clientSecret,
		http: &http.Client{Timeout: 10 * time.Second}}
}

// envelope is Keyora's response shape: data on success, error on failure.
type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error json.RawMessage `json:"error"`
}

// post sends a JSON body with the application's credentials (HTTP Basic) and
// returns Keyora's status code and envelope.
func (k *keyoraClient) post(ctx context.Context, path string, body any) (int, envelope, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, envelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, envelope{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(k.clientID, k.clientSecret)
	res, err := k.http.Do(req)
	if err != nil {
		return 0, envelope{}, fmt.Errorf("keyora unreachable: %w", err)
	}
	defer res.Body.Close()
	var env envelope
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusAccepted {
		if err := json.NewDecoder(res.Body).Decode(&env); err != nil {
			return res.StatusCode, env, fmt.Errorf("unexpected response from keyora: %w", err)
		}
	}
	return res.StatusCode, env, nil
}

// introspection is the live state of a token as reported by Keyora.
type introspection struct {
	Active      bool     `json:"active"`
	Subject     string   `json:"sub"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (k *keyoraClient) introspect(ctx context.Context, token string) (*introspection, error) {
	status, env, err := k.post(ctx, "/api/v1/auth/introspect", map[string]string{"token": token})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("introspection failed with status %d", status)
	}
	var out introspection
	return &out, json.Unmarshal(env.Data, &out)
}
