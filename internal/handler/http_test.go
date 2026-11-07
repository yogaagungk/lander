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
	rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, testToken)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
	if code := errCode(t, rec); code != "rate_limited" {
		t.Errorf("code = %q, want rate_limited", code)
	}

	// After the window expires the limiter allows the valid token again.
	api.server.limiter.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if rec := api.do(http.MethodGet, "/api/v1/nginx/sites", nil, testToken); rec.Code != http.StatusOK {
		t.Fatalf("status after window = %d, want 200", rec.Code)
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
