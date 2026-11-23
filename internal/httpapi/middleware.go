package httpapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rabbicse/keyora/internal/domain"
	"github.com/rabbicse/keyora/internal/security"
	"github.com/rabbicse/keyora/internal/service"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxClientIP
)

var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func requestID(r *http.Request) string {
	v, _ := r.Context().Value(ctxRequestID).(string)
	return v
}

func clientIP(r *http.Request) string {
	v, _ := r.Context().Value(ctxClientIP).(string)
	return v
}

func metaFrom(r *http.Request) service.Meta {
	return service.Meta{IP: clientIP(r), UserAgent: r.UserAgent(), RequestID: requestID(r)}
}

// resolveIP returns the peer address, or the address appended by the reverse
// proxy when proxy headers are trusted. Only the right-most X-Forwarded-For
// entry is used: everything to its left is supplied by the client.
func (a *API) resolveIP(r *http.Request) string {
	if a.cfg.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// ServeHTTP is the whole middleware chain: request ID, security headers,
// panic recovery, CORS, rate limiting, routing, metrics and access logging.
func (a *API) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := r.Header.Get("X-Request-ID")
	if !requestIDRe.MatchString(id) {
		id = security.NewID()
	}
	ctx := context.WithValue(r.Context(), ctxRequestID, id)
	ctx = context.WithValue(ctx, ctxClientIP, a.resolveIP(r))
	r = r.WithContext(ctx)

	w := &statusWriter{ResponseWriter: rw}
	h := w.Header()
	h.Set("X-Request-ID", id)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	if a.cfg.HSTS {
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	handler, pattern := a.mux.Handler(r)
	defer func() {
		if rec := recover(); rec != nil {
			a.log.Error("panic recovered", "request_id", id, "panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
			if w.status == 0 {
				a.respondError(w, r, domain.E(domain.KindInternal, "internal_error", "an internal error occurred"))
			}
		}
		route := pattern
		if route == "" {
			route = "unmatched"
		}
		elapsed := time.Since(start)
		a.metrics.observe(r.Method, route, w.status, elapsed)
		a.log.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path, "route", route,
			"status", w.status, "duration_ms", elapsed.Milliseconds(), "ip", clientIP(r))
	}()

	if a.cors(w, r) {
		return
	}
	if pattern == "" {
		// Let the mux decide between 404 and 405, then answer in our envelope.
		probe := httptest.NewRecorder()
		handler.ServeHTTP(probe, r)
		if allow := probe.Header().Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		if probe.Code == http.StatusMethodNotAllowed {
			writeJSON(w, probe.Code, envelope{Error: &errorBody{Code: "method_not_allowed", Message: "method not allowed for this resource"}, Meta: meta{RequestID: id}})
			return
		}
		a.respondError(w, r, domain.E(domain.KindNotFound, "route_not_found", "no such endpoint"))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || strings.HasPrefix(r.URL.Path, "/api/v1/oauth/") || a.legacyPath(r.URL.Path) {
		if ok, wait := a.cfg.Limiter.Allow(clientIP(r)); !ok {
			e := *domain.ErrRateLimited
			e.Details = map[string]string{"retry_after_seconds": strconv.Itoa(int(wait.Seconds()) + 1)}
			a.respondError(w, r, &e)
			return
		}
	}
	a.mux.ServeHTTP(w, r)
}

// cors applies the CORS policy and reports whether it fully answered the
// request (a preflight). Tokens travel in the Authorization header, never in
// cookies, so credentials mode is never enabled.
func (a *API) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	w.Header().Add("Vary", "Origin")
	allowed := a.originAllowed(r.Context(), origin)
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, Retry-After")
	}
	if r.Method != http.MethodOptions || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	if allowed {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

// originCache holds the union of statically configured origins and the
// origins registered on applications, refreshed at most every 30 seconds.
type originCache struct {
	mu      sync.Mutex
	static  map[string]bool
	dynamic map[string]bool
	loaded  time.Time
}

func (a *API) originAllowed(ctx context.Context, origin string) bool {
	c := &a.origins
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.static[origin] {
		return true
	}
	if c.dynamic == nil || time.Since(c.loaded) > 30*time.Second {
		list, err := a.svc.AllowedOrigins(ctx)
		if err != nil {
			a.log.Error("could not load allowed origins", "error", err)
		} else {
			c.dynamic = make(map[string]bool, len(list))
			for _, o := range list {
				c.dynamic[o] = true
			}
			c.loaded = time.Now()
		}
	}
	return c.dynamic[origin]
}

func (a *API) invalidateOrigins() {
	a.origins.mu.Lock()
	a.origins.dynamic = nil
	a.origins.mu.Unlock()
}

// ---- metrics ----

var buckets = []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5}

type routeStat struct {
	counts  map[int]uint64
	buckets []uint64
	sum     float64
	total   uint64
}

// metrics is a tiny Prometheus text-format exporter, enough for request
// rates, error rates and latency without pulling in a client library.
type metrics struct {
	mu     sync.Mutex
	routes map[string]*routeStat
	start  time.Time
}

func newMetrics() *metrics { return &metrics{routes: map[string]*routeStat{}, start: time.Now()} }

func (m *metrics) observe(method, route string, status int, d time.Duration) {
	key := method + " " + strings.TrimPrefix(route, method+" ")
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.routes[key]
	if !ok {
		st = &routeStat{counts: map[int]uint64{}, buckets: make([]uint64, len(buckets))}
		m.routes[key] = st
	}
	st.counts[status]++
	secs := d.Seconds()
	for i, b := range buckets {
		if secs <= b {
			st.buckets[i]++
		}
	}
	st.sum += secs
	st.total++
}

func (m *metrics) write(w http.ResponseWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.routes))
	for k := range m.routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# HELP keyora_uptime_seconds Seconds since the process started.\n# TYPE keyora_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "keyora_uptime_seconds %.0f\n", time.Since(m.start).Seconds())
	b.WriteString("# HELP keyora_http_requests_total HTTP requests by route and status.\n# TYPE keyora_http_requests_total counter\n")
	for _, k := range keys {
		method, route, _ := strings.Cut(k, " ")
		st := m.routes[k]
		codes := make([]int, 0, len(st.counts))
		for c := range st.counts {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Fprintf(&b, "keyora_http_requests_total{method=%q,route=%q,status=\"%d\"} %d\n", method, route, c, st.counts[c])
		}
	}
	b.WriteString("# HELP keyora_http_request_duration_seconds HTTP request latency.\n# TYPE keyora_http_request_duration_seconds histogram\n")
	for _, k := range keys {
		method, route, _ := strings.Cut(k, " ")
		st := m.routes[k]
		for i, le := range buckets {
			fmt.Fprintf(&b, "keyora_http_request_duration_seconds_bucket{method=%q,route=%q,le=\"%g\"} %d\n", method, route, le, st.buckets[i])
		}
		fmt.Fprintf(&b, "keyora_http_request_duration_seconds_bucket{method=%q,route=%q,le=\"+Inf\"} %d\n", method, route, st.total)
		fmt.Fprintf(&b, "keyora_http_request_duration_seconds_sum{method=%q,route=%q} %g\n", method, route, st.sum)
		fmt.Fprintf(&b, "keyora_http_request_duration_seconds_count{method=%q,route=%q} %d\n", method, route, st.total)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
