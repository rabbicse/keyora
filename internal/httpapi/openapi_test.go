package httpapi_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/rabbicse/keyora/api"
	"github.com/rabbicse/keyora/internal/httpapi"
	"github.com/rabbicse/keyora/internal/store/memory"
	"github.com/rabbicse/keyora/internal/testutil"
)

// TestOpenAPIMatchesRoutes keeps the published API description honest: every
// route the server registers must be documented, and nothing may be
// documented that the server does not serve.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	documented := map[string]bool{}
	path := ""
	inPaths := false
	for _, line := range strings.Split(string(api.OpenAPI), "\n") {
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && line != "" && !strings.HasPrefix(line, " "):
			inPaths = false
		case inPaths && strings.HasPrefix(line, "  /"):
			path = strings.TrimSuffix(strings.TrimSpace(line), ":")
		case inPaths && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			method := strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(line), ":"))
			switch method {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
				documented[method+" "+path] = true
			}
		}
	}
	if len(documented) < 40 {
		t.Fatalf("only %d operations parsed from the spec; the parser or the spec is broken", len(documented))
	}

	env := testutil.NewEnv(t, memory.New(), nil)
	served := map[string]bool{}
	for _, r := range httpapi.New(env.Svc, httpapi.Config{MetricsEnabled: true}, testutil.Logger()).Routes() {
		served[r] = true
	}
	var problems []string
	for r := range served {
		if !documented[r] {
			problems = append(problems, "served but not documented: "+r)
		}
	}
	for r := range documented {
		if !served[r] {
			problems = append(problems, "documented but not served: "+r)
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("api/openapi.yaml is out of sync with the router:\n%s", strings.Join(problems, "\n"))
	}
}
