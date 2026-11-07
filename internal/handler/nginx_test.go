package handler

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogaagungk/lander/internal/domain"
	"github.com/yogaagungk/lander/internal/service"
)

func proxyRequest() domain.SiteConfig {
	return domain.SiteConfig{Domain: "api.example.com", ProxyTarget: "http://127.0.0.1:3000"}
}

func TestSiteLifecycle(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/v1/nginx/site", proxyRequest(), testToken)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	applied := decode[domain.ApplyResult](t, rec)
	if !applied.Changed || applied.ETag == "" {
		t.Errorf("apply result = %+v", applied)
	}
	if strings.Contains(rec.Body.String(), "Created") {
		t.Error("internal Created field leaked into the response")
	}
	if got := strings.Trim(rec.Header().Get("ETag"), `"`); got != applied.ETag {
		t.Errorf("ETag header = %q, want %q", got, applied.ETag)
	}

	// Identical re-post is a no-op with 200.
	rec = api.do(http.MethodPost, "/api/v1/nginx/site", proxyRequest(), testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent status = %d, want 200", rec.Code)
	}
	if again := decode[domain.ApplyResult](t, rec); again.Changed {
		t.Errorf("identical apply reported a change: %+v", again)
	}

	rec = api.do(http.MethodGet, "/api/v1/nginx/site?domain=api.example.com", nil, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d: %s", rec.Code, rec.Body.String())
	}
	detail := decode[domain.SiteDetail](t, rec)
	if detail.Domain != "api.example.com" || detail.Config.ProxyTarget != "http://127.0.0.1:3000" {
		t.Errorf("detail = %+v", detail)
	}
	if !detail.Managed || !detail.Enabled || detail.SSL {
		t.Errorf("summary flags = %+v", detail.SiteSummary)
	}
	if detail.ETag != service.ETag(detail.RawConfig) {
		t.Error("etag does not hash the returned raw_config")
	}
	if !strings.Contains(detail.RawConfig, "proxy_pass") {
		t.Error("raw_config missing proxy_pass")
	}

	rec = api.do(http.MethodGet, "/api/v1/nginx/sites", nil, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	list := decode[sitesResponse](t, rec)
	if len(list.Sites) != 1 || list.Sites[0].Domain != "api.example.com" {
		t.Errorf("list = %+v", list)
	}

	// Stale If-Match loses with 409.
	changed := proxyRequest()
	changed.ProxyTarget = "http://127.0.0.1:4000"
	rec = api.doWithHeaders(http.MethodPost, "/api/v1/nginx/site", changed, testToken,
		map[string]string{"If-Match": `"stale"`})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale If-Match status = %d, want 409", rec.Code)
	}

	// Current If-Match wins with 200.
	rec = api.doWithHeaders(http.MethodPost, "/api/v1/nginx/site", changed, testToken,
		map[string]string{"If-Match": `"` + detail.ETag + `"`})
	if rec.Code != http.StatusOK {
		t.Fatalf("matching If-Match status = %d: %s", rec.Code, rec.Body.String())
	}
	if !decode[domain.ApplyResult](t, rec).Changed {
		t.Error("matching If-Match update did not report a change")
	}

	rec = api.do(http.MethodDelete, "/api/v1/nginx/site?domain=api.example.com", nil, testToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body.String())
	}
	rec = api.do(http.MethodGet, "/api/v1/nginx/site?domain=api.example.com", nil, testToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", rec.Code)
	}

	audit, err := os.ReadFile(api.cfg.AuditLogPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(audit), `"action":"site.apply"`) || !strings.Contains(string(audit), `"action":"site.delete"`) {
		t.Errorf("audit log missing entries:\n%s", audit)
	}
}

func TestSiteValidationErrors(t *testing.T) {
	api := newTestAPI(t)

	site := proxyRequest()
	site.Domain = "API.example.com"
	rec := api.do(http.MethodPost, "/api/v1/nginx/site", site, testToken)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := decode[domain.ValidationErrorResponse](t, rec)
	if body.Error.Code != "validation_failed" || len(body.Issues) == 0 {
		t.Errorf("body = %+v", body)
	}

	site = proxyRequest()
	site.ProxyTarget = "http://8.8.8.8:80"
	rec = api.do(http.MethodPost, "/api/v1/nginx/site", site, testToken)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("public upstream status = %d, want 422", rec.Code)
	}

	rec = api.do(http.MethodGet, "/api/v1/nginx/site?domain=API.example.com", nil, testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad domain get = %d, want 400", rec.Code)
	}
	rec = api.do(http.MethodGet, "/api/v1/nginx/site", nil, testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing domain get = %d, want 400", rec.Code)
	}
}

func TestSiteCommandErrors(t *testing.T) {
	api := newTestAPI(t)
	api.runner.fail = func(name string, _ []string) ([]byte, error) {
		return []byte("nginx: [emerg] bad config"), errors.New("exit status 1")
	}
	rec := api.do(http.MethodPost, "/api/v1/nginx/site", proxyRequest(), testToken)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := decode[domain.ValidationErrorResponse](t, rec)
	if body.Error.Code != "nginx_test_failed" || !strings.Contains(body.Error.Message, "emerg") {
		t.Errorf("body = %+v", body)
	}
}

func TestSiteUnmanagedConflict(t *testing.T) {
	api := newTestAPI(t)
	if err := os.WriteFile(sitePath(api.cfg, "api.example.com"), []byte("server {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := api.do(http.MethodPost, "/api/v1/nginx/site", proxyRequest(), testToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("apply status = %d, want 409", rec.Code)
	}
	rec = api.do(http.MethodDelete, "/api/v1/nginx/site?domain=api.example.com", nil, testToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete status = %d, want 409", rec.Code)
	}
}

func TestDeleteMissingQueryAndUnknownSite(t *testing.T) {
	api := newTestAPI(t)
	if rec := api.do(http.MethodDelete, "/api/v1/nginx/site", nil, testToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing query = %d, want 400", rec.Code)
	}
	if rec := api.do(http.MethodDelete, "/api/v1/nginx/site?domain=none.example.com", nil, testToken); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown site = %d, want 404", rec.Code)
	}
}

func TestValidateEndpoint(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/v1/nginx/validate", proxyRequest(), testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	result := decode[domain.ValidateResult](t, rec)
	if !result.Valid || result.RenderedConfig == "" {
		t.Errorf("result = %+v", result)
	}

	invalid := proxyRequest()
	invalid.CustomRules = []string{"proxy_pass http://8.8.8.8;"}
	rec = api.do(http.MethodPost, "/api/v1/nginx/validate", invalid, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid config status = %d, want 200", rec.Code)
	}
	result = decode[domain.ValidateResult](t, rec)
	if result.Valid || len(result.Issues) == 0 {
		t.Errorf("invalid result = %+v", result)
	}
}

func TestIssueSSL(t *testing.T) {
	api := newTestAPI(t)

	rec := api.do(http.MethodPost, "/api/v1/nginx/ssl",
		domain.SSLRequest{Domain: "api.example.com", Email: "admin@example.com"}, testToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing site status = %d, want 404", rec.Code)
	}

	if rec := api.do(http.MethodPost, "/api/v1/nginx/site", proxyRequest(), testToken); rec.Code != http.StatusCreated {
		t.Fatalf("create site: %d", rec.Code)
	}

	rec = api.do(http.MethodPost, "/api/v1/nginx/ssl",
		domain.SSLRequest{Domain: "api.example.com", Email: "not-an-email"}, testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad email status = %d, want 400", rec.Code)
	}

	api.runner.fail = func(name string, _ []string) ([]byte, error) {
		if name == api.cfg.CertbotBin {
			return []byte("certbot: rate limited"), errors.New("exit status 1")
		}
		return nil, nil
	}
	rec = api.do(http.MethodPost, "/api/v1/nginx/ssl",
		domain.SSLRequest{Domain: "api.example.com", Email: "admin@example.com"}, testToken)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("certbot failure status = %d, want 422", rec.Code)
	}
	if code := errCode(t, rec); code != "certbot_failed" {
		t.Errorf("code = %q", code)
	}

	api.runner.fail = nil
	rec = api.do(http.MethodPost, "/api/v1/nginx/ssl",
		domain.SSLRequest{Domain: "api.example.com", Email: "admin@example.com"}, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("success status = %d: %s", rec.Code, rec.Body.String())
	}
	if !decode[domain.SSLResult](t, rec).Issued {
		t.Error("issued = false")
	}
}

func TestSystemStats(t *testing.T) {
	api := newTestAPI(t)
	api.nginx.SetStatsProvider(fakeStats{cpu: 12.5, memory: 34.5, uptime: 1000})

	rec := api.do(http.MethodGet, "/api/v1/system/stats", nil, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	status := decode[domain.SystemStatus](t, rec)
	if status.CPUUsage != 12.5 || status.MemoryUsage != 34.5 || status.Uptime != 1000 || !status.NginxActive {
		t.Errorf("status = %+v", status)
	}
}

type failingStats struct{}

func (failingStats) CPUPercent(context.Context, time.Duration) (float64, error) {
	return 0, errors.New("cpu unavailable")
}
func (failingStats) MemoryUsedPercent(context.Context) (float64, error) {
	return 0, nil
}
func (failingStats) Uptime(context.Context) (uint64, error) { return 0, nil }

func TestSystemStatsFailureIsInternal(t *testing.T) {
	api := newTestAPI(t)
	api.nginx.SetStatsProvider(failingStats{})

	rec := api.do(http.MethodGet, "/api/v1/system/stats", nil, testToken)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if code := errCode(t, rec); code != "internal" {
		t.Errorf("code = %q", code)
	}
}

func TestConcurrentSiteApplies(t *testing.T) {
	api := newTestAPI(t)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, name := range []string{"a.example.com", "b.example.com"} {
		site := domain.SiteConfig{Domain: name, ProxyTarget: "http://127.0.0.1:3000"}
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- api.do(http.MethodPost, "/api/v1/nginx/site", site, testToken).Code
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusCreated {
			t.Errorf("status = %d, want 201", status)
		}
	}
}
