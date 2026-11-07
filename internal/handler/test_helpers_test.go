package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
	"github.com/yogaagungk/lander/internal/service"
)

const testToken = "0123456789abcdef0123456789abcdef"

type runnerCall struct {
	name string
	args []string
}

type fakeRunner struct {
	mu    sync.Mutex
	calls []runnerCall
	fail  func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, runnerCall{name: name, args: append([]string(nil), args...)})
	fail := f.fail
	f.mu.Unlock()
	if fail != nil {
		if out, err := fail(name, args); err != nil {
			return out, err
		}
	}
	return nil, nil
}

type fakeStats struct {
	cpu, memory float64
	uptime      uint64
}

func (f fakeStats) CPUPercent(context.Context, time.Duration) (float64, error) {
	return f.cpu, nil
}

func (f fakeStats) MemoryUsedPercent(context.Context) (float64, error) { return f.memory, nil }
func (f fakeStats) Uptime(context.Context) (uint64, error)             { return f.uptime, nil }

type testAPI struct {
	server *Server
	nginx  *service.Nginx
	cfg    config.Config
	runner *fakeRunner
}

func newTestAPI(t *testing.T, mutators ...func(*config.Config)) *testAPI {
	t.Helper()
	root := t.TempDir()
	runner := &fakeRunner{}
	cfg := config.Config{
		ListenAddr:      "127.0.0.1:8080",
		SecretToken:     testToken,
		Version:         "test",
		SitesAvailable:  filepath.Join(root, "sites-available"),
		SitesEnabled:    filepath.Join(root, "sites-enabled"),
		NginxConfPath:   filepath.Join(root, "nginx.conf"),
		NginxBin:        "/usr/sbin/nginx",
		SystemctlBin:    "/usr/bin/systemctl",
		CertbotBin:      config.DefaultCertbotBin,
		WebRootBase:     filepath.Join(root, "www"),
		LetsEncryptDir:  filepath.Join(root, "letsencrypt"),
		EnvDir:          filepath.Join(root, "env"),
		AuditLogPath:    filepath.Join(root, "audit.log"),
		MaxBodyBytes:    1 << 20,
		MaxEnvBodyBytes: 256 << 10,
		AuthFailLimit:   10,
		AuthFailWindow:  time.Minute,
		ShutdownTimeout: 10 * time.Second,
		CommandTimeout:  15 * time.Second,
	}
	for _, mutate := range mutators {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid test config: %v", err)
	}
	for _, dir := range []string{cfg.SitesAvailable, cfg.SitesEnabled, cfg.WebRootBase, cfg.LetsEncryptDir, cfg.EnvDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(cfg.NginxConfPath, []byte("events {}\n"), 0o600); err != nil {
		t.Fatalf("write nginx.conf: %v", err)
	}

	nginx := service.NewNginx(cfg, runner)
	env := service.NewEnvStore(cfg.EnvDir)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(cfg, nginx, env, "test-version", logger)
	server.authDelay = 0
	return &testAPI{server: server, nginx: nginx, cfg: cfg, runner: runner}
}

func (a *testAPI) do(method, target string, body any, token string) *httptest.ResponseRecorder {
	return a.doWithHeaders(method, target, body, token, nil)
}

func (a *testAPI) doWithHeaders(method, target string, body any, token string, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, target, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	a.server.Handler().ServeHTTP(rec, req)
	return rec
}

func (a *testAPI) doRaw(method, target, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.server.Handler().ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(rec.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return value
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[domain.ErrorResponse](t, rec).Error.Code
}

func sitePath(cfg config.Config, domainName string) string {
	return filepath.Join(cfg.SitesAvailable, domainName+".conf")
}
