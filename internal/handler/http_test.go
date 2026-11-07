package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
)

func TestAuthRequired(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body := decode[domain.ErrorResponse](t, rec)
	if body.Error.Code != "unauthorized" || body.Error.RequestID == "" {
		t.Errorf("error body = %+v", body.Error)
	}
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id header missing")
	}
}

func TestAuthRejectsWrongToken(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "wrong-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuthAcceptsValidToken(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthRateLimit(t *testing.T) {
	api := newTestAPI(t, func(cfg *config.Config) { cfg.AuthFailLimit = 2 })

	for i := 0; i < 2; i++ {
		if rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "bad"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, rec.Code)
		}
	}
	rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "bad")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit bad token status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
	if code := errCode(t, rec); code != "rate_limited" {
		t.Errorf("code = %q, want rate_limited", code)
	}

	// A valid token always gets through, even while the IP is locked out.
	if rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, testToken); rec.Code != http.StatusOK {
		t.Fatalf("valid token during lockout = %d, want 200", rec.Code)
	}
	// The valid request must not clear the failure counter for the IP.
	if rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "bad"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("bad token after valid request = %d, want 429", rec.Code)
	}

	// After the window expires the limiter allows bad attempts again.
	api.server.limiter.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, "bad"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status after window = %d, want 401", rec.Code)
	}
}

func TestHealthzIsPublic(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodGet, "/healthz", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	health := decode[domain.Health](t, rec)
	if health.Status != "ok" || health.Version != "test-version" || !health.NginxActive {
		t.Errorf("health = %+v", health)
	}

	api.runner.fail = func(string, []string) ([]byte, error) {
		return nil, http.ErrServerClosed
	}
	rec = api.do(http.MethodGet, "/healthz", nil, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded status = %d, want 503", rec.Code)
	}
}

func TestUnknownJSONFieldRejected(t *testing.T) {
	api := newTestAPI(t)
	rec := api.doRaw(http.MethodPost, "/api/v1/nginx/site",
		`{"domain":"api.example.com","proxy_target":"http://127.0.0.1:3000","bogus":true}`, testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := errCode(t, rec); code != "bad_request" {
		t.Errorf("code = %q", code)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	api := newTestAPI(t, func(cfg *config.Config) {
		cfg.MaxBodyBytes = 128
		cfg.MaxEnvBodyBytes = 64
	})
	body := `{"domain":"api.example.com","proxy_target":"http://127.0.0.1:3000","custom_rules":["add_header X ` +
		strings.Repeat("a", 256) + `;"]}`
	rec := api.doRaw(http.MethodPost, "/api/v1/nginx/site", body, testToken)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if code := errCode(t, rec); code != "payload_too_large" {
		t.Errorf("code = %q", code)
	}
}

func TestRequestIDIsEchoed(t *testing.T) {
	api := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nginx/sites", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Request-Id", "client-request-id")
	rec := httptest.NewRecorder()
	api.server.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-Id"); got != "client-request-id" {
		t.Errorf("X-Request-Id = %q, want client-request-id", got)
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	trusted := &Server{cfg: config.Config{TrustedProxy: true}}
	untrusted := &Server{}

	newReq := func(remote, forwarded, realIP string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if forwarded != "" {
			req.Header.Set("X-Forwarded-For", forwarded)
		}
		if realIP != "" {
			req.Header.Set("X-Real-IP", realIP)
		}
		return req
	}

	cases := []struct {
		name    string
		server  *Server
		request *http.Request
		want    string
	}{
		{"last xff hop", trusted, newReq("127.0.0.1:5555", "1.2.3.4, 5.6.7.8", ""), "5.6.7.8"},
		{"x-real-ip fallback", trusted, newReq("127.0.0.1:5555", "", "9.9.9.9"), "9.9.9.9"},
		{"invalid xff falls back", trusted, newReq("127.0.0.1:5555", "not-an-ip", "9.9.9.9"), "9.9.9.9"},
		{"non-loopback ignores headers", trusted, newReq("203.0.113.5:5555", "1.2.3.4", ""), "203.0.113.5"},
		{"trusted proxy off", untrusted, newReq("127.0.0.1:5555", "1.2.3.4", ""), "127.0.0.1"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.server.clientIP(tt.request); got != tt.want {
				t.Errorf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitUsesForwardedClientIP(t *testing.T) {
	api := newTestAPI(t, func(cfg *config.Config) {
		cfg.AuthFailLimit = 1
		cfg.TrustedProxy = true
	})
	send := func(forwarded string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/nginx/sites", nil)
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("Authorization", "Bearer bad")
		rec := httptest.NewRecorder()
		api.server.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send("1.1.1.1"); code != http.StatusUnauthorized {
		t.Fatalf("first client status = %d", code)
	}
	if code := send("1.1.1.1"); code != http.StatusTooManyRequests {
		t.Fatalf("repeat client status = %d, want 429", code)
	}
	if code := send("2.2.2.2"); code != http.StatusUnauthorized {
		t.Fatalf("other client status = %d, want 401 (separate bucket)", code)
	}
}
