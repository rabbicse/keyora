package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/store"
)

const maxBodyBytes = 1 << 20

type pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Total  int `json:"total"`
}

type meta struct {
	RequestID  string      `json:"request_id"`
	Pagination *pagination `json:"pagination,omitempty"`
}

type errorBody struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// envelope is the single response shape of the versioned API: exactly one of
// Data or Error is present, and Meta always is.
type envelope struct {
	Data  any        `json:"data,omitempty"`
	Error *errorBody `json:"error,omitempty"`
	Meta  meta       `json:"meta"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func respond(w http.ResponseWriter, r *http.Request, status int, data any) {
	writeJSON(w, status, envelope{Data: data, Meta: meta{RequestID: requestID(r)}})
}

func respondPage(w http.ResponseWriter, r *http.Request, data any, p store.Page, total int) {
	writeJSON(w, http.StatusOK, envelope{Data: data, Meta: meta{RequestID: requestID(r),
		Pagination: &pagination{Limit: p.Limit, Offset: p.Offset, Total: total}}})
}

func statusFor(kind domain.Kind) int {
	switch kind {
	case domain.KindInvalid:
		return http.StatusBadRequest
	case domain.KindUnauthenticated:
		return http.StatusUnauthorized
	case domain.KindForbidden:
		return http.StatusForbidden
	case domain.KindNotFound:
		return http.StatusNotFound
	case domain.KindConflict:
		return http.StatusConflict
	case domain.KindLocked:
		return http.StatusLocked
	case domain.KindRateLimited:
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

// respondError maps an error to the envelope. Anything that is not a
// domain.Error is logged and reported as an opaque internal error, so
// internals never reach the client.
func (a *API) respondError(w http.ResponseWriter, r *http.Request, err error) {
	var de *domain.Error
	if !errors.As(err, &de) {
		a.log.Error("unhandled error", "request_id", requestID(r), "path", r.URL.Path, "error", err)
		de = domain.E(domain.KindInternal, "internal_error", "an internal error occurred")
	}
	status := statusFor(de.Kind)
	if de.Code == "payload_too_large" {
		status = http.StatusRequestEntityTooLarge
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="keyora"`)
	}
	if secs := de.Details["retry_after_seconds"]; secs != "" {
		w.Header().Set("Retry-After", secs)
	}
	writeJSON(w, status, envelope{Error: &errorBody{Code: de.Code, Message: de.Message, Details: de.Details},
		Meta: meta{RequestID: requestID(r)}})
}

// decode reads one JSON object, rejecting unknown fields, trailing data,
// oversized bodies and non-JSON content types.
func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			return domain.E(domain.KindInvalid, "unsupported_media_type", "Content-Type must be application/json")
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return domain.E(domain.KindInvalid, "payload_too_large", "request body is too large")
		}
		return domain.E(domain.KindInvalid, "invalid_json", "request body must be a valid JSON object: "+jsonErr(err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return domain.E(domain.KindInvalid, "invalid_json", "request body must contain a single JSON object")
	}
	return nil
}

func jsonErr(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field") {
		return strings.TrimPrefix(msg, "json: ")
	}
	if errors.Is(err, io.EOF) {
		return "body is empty"
	}
	return "malformed JSON"
}

func pageFrom(r *http.Request) (store.Page, error) {
	p := store.Page{Limit: 20}
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			return p, domain.Invalid("limit", "must be an integer between 1 and 100")
		}
		p.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return p, domain.Invalid("offset", "must be a non-negative integer")
		}
		p.Offset = n
	}
	return p, nil
}
