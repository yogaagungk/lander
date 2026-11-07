package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
)

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

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRunner) callsOf(name string) []runnerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []runnerCall
	for _, call := range f.calls {
		if call.name == name {
			out = append(out, call)
		}
	}
	return out
}

func newTestService(t *testing.T, runner CommandRunner, mutators ...func(*config.Config)) (*Nginx, config.Config) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Config{
		ListenAddr:      "127.0.0.1:8080",
		SecretToken:     strings.Repeat("t", 32),
		SitesAvailable:  filepath.Join(root, "sites-available"),
		SitesEnabled:    filepath.Join(root, "sites-enabled"),
		NginxConfPath:   filepath.Join(root, "nginx.conf"),
		NginxBin:        "/usr/sbin/nginx",
		SystemctlBin:    "/usr/bin/systemctl",
		CertbotBin:      config.DefaultCertbotBin,
		WebRootBase:     filepath.Join(root, "www"),
		LetsEncryptDir:  filepath.Join(root, "letsencrypt"),
		EnvDir:          filepath.Join(root, "env"),
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
	return NewNginx(cfg, runner), cfg
}

func sitePath(cfg config.Config, domainName string) string {
	return filepath.Join(cfg.SitesAvailable, domainName+".conf")
}

func linkPath(cfg config.Config, domainName string) string {
	return filepath.Join(cfg.SitesEnabled, domainName+".conf")
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- test helper reads paths built by the test itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestApplyCreatesSiteAndIsIdempotent(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	result, err := svc.Apply(ctx, proxySite())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Changed || !result.Reloaded {
		t.Errorf("result = %+v, want changed and reloaded", result)
	}
	if result.ETag == "" {
		t.Error("etag must be returned")
	}

	content := mustRead(t, sitePath(cfg, "api.example.com"))
	if !strings.Contains(content, "proxy_pass http://127.0.0.1:3000;") {
		t.Errorf("site config missing proxy_pass:\n%s", content)
	}
	target, err := os.Readlink(linkPath(cfg, "api.example.com"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != filepath.Join("..", "sites-available", "api.example.com.conf") {
		t.Errorf("symlink target = %q", target)
	}
	if _, err := os.Stat(sitePath(cfg, "api.example.com") + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Error("backup file must be removed after a successful apply")
	}

	if got := len(runner.callsOf(cfg.NginxBin)); got != 1 {
		t.Errorf("nginx -t calls = %d, want 1", got)
	}
	testCall := runner.callsOf(cfg.NginxBin)[0]
	if strings.Join(testCall.args, " ") != "-t -c "+cfg.NginxConfPath {
		t.Errorf("nginx args = %v", testCall.args)
	}
	if got := len(runner.callsOf(cfg.SystemctlBin)); got != 1 {
		t.Errorf("reload calls = %d, want 1", got)
	}

	// Identical re-post: no rewrite and no reload.
	before := runner.callCount()
	result, err = svc.Apply(ctx, proxySite())
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if result.Changed || result.Reloaded {
		t.Errorf("identical apply reported a change: %+v", result)
	}
	if runner.callCount() != before {
		t.Errorf("identical apply ran commands: %d -> %d", before, runner.callCount())
	}

	// Changed target: rewrite and reload.
	changed := proxySite()
	changed.ProxyTarget = "http://127.0.0.1:4000"
	result, err = svc.Apply(ctx, changed)
	if err != nil {
		t.Fatalf("changed Apply: %v", err)
	}
	if !result.Changed || !result.Reloaded {
		t.Errorf("changed apply result = %+v", result)
	}
	if !strings.Contains(mustRead(t, sitePath(cfg, "api.example.com")), "127.0.0.1:4000") {
		t.Error("updated config not written")
	}
}

func TestApplyRollsBackOnNginxTestFailure(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	previous := mustRead(t, sitePath(cfg, "api.example.com"))

	runner.fail = func(name string, args []string) ([]byte, error) {
		if name == cfg.NginxBin {
			return []byte("nginx: [emerg] invalid parameter\n"), errors.New("exit status 1")
		}
		return nil, nil
	}

	changed := proxySite()
	changed.ProxyTarget = "http://127.0.0.1:4000"
	_, err := svc.Apply(ctx, changed)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("error = %v, want *CommandError", err)
	}
	if cmdErr.Op != "nginx -t" || !strings.Contains(cmdErr.Output, "emerg") {
		t.Errorf("command error = %+v", cmdErr)
	}

	if current := mustRead(t, sitePath(cfg, "api.example.com")); current != previous {
		t.Errorf("config was not rolled back:\n%s", current)
	}
	if _, err := os.Lstat(linkPath(cfg, "api.example.com")); err != nil {
		t.Errorf("symlink was not preserved: %v", err)
	}
	if _, err := os.Stat(sitePath(cfg, "api.example.com") + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Error("backup left behind after rollback")
	}
}

func TestApplyFailureLeavesNoNewSite(t *testing.T) {
	runner := &fakeRunner{fail: func(name string, _ []string) ([]byte, error) {
		return []byte("nginx: [emerg] bad config"), errors.New("exit status 1")
	}}
	svc, cfg := newTestService(t, runner)

	if _, err := svc.Apply(context.Background(), proxySite()); err == nil {
		t.Fatal("expected apply to fail")
	}
	if _, err := os.Stat(sitePath(cfg, "api.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Error("failed apply left a config file behind")
	}
	if _, err := os.Lstat(linkPath(cfg, "api.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Error("failed apply left a symlink behind")
	}
}

func TestApplyRollsBackOnReloadFailure(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)

	if _, err := svc.Apply(context.Background(), proxySite()); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	previous := mustRead(t, sitePath(cfg, "api.example.com"))

	runner.fail = func(name string, _ []string) ([]byte, error) {
		if name == cfg.SystemctlBin {
			return []byte("Job for nginx.service failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	changed := proxySite()
	changed.ProxyTarget = "http://127.0.0.1:4000"
	_, err := svc.Apply(context.Background(), changed)
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.Op != "systemctl reload nginx" {
		t.Fatalf("error = %v, want reload CommandError", err)
	}
	if current := mustRead(t, sitePath(cfg, "api.example.com")); current != previous {
		t.Error("config was not rolled back after reload failure")
	}
}

func TestApplyRejectsUnmanagedFile(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)

	unmanaged := []byte("# hand-written config\nserver {\n    listen 80;\n}\n")
	if err := os.WriteFile(sitePath(cfg, "api.example.com"), unmanaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Apply(context.Background(), proxySite()); !errors.Is(err, ErrUnmanaged) {
		t.Fatalf("error = %v, want ErrUnmanaged", err)
	}
	if got := mustRead(t, sitePath(cfg, "api.example.com")); got != string(unmanaged) {
		t.Error("unmanaged config was modified")
	}
	if runner.callCount() != 0 {
		t.Error("no commands should run for an unmanaged file")
	}
}

func TestApplyRejectsInvalidInput(t *testing.T) {
	runner := &fakeRunner{}
	svc, _ := newTestService(t, runner)

	site := proxySite()
	site.ProxyTarget = "http://8.8.8.8:80"
	_, err := svc.Apply(context.Background(), site)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %v, want *ValidationError", err)
	}
	if len(validationErr.Issues) == 0 {
		t.Error("expected issues")
	}
	if runner.callCount() != 0 {
		t.Error("validation failure must not run commands")
	}
}

func TestDeleteRemovesSite(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := svc.Delete(ctx, "api.example.com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(sitePath(cfg, "api.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Error("config file still exists after delete")
	}
	if _, err := os.Lstat(linkPath(cfg, "api.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Error("symlink still exists after delete")
	}
	if err := svc.Delete(ctx, "api.example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete error = %v, want ErrNotFound", err)
	}
}

func TestDeleteRollsBackOnReloadFailure(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	previous := mustRead(t, sitePath(cfg, "api.example.com"))

	runner.fail = func(name string, _ []string) ([]byte, error) {
		if name == cfg.SystemctlBin {
			return []byte("reload failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	if err := svc.Delete(ctx, "api.example.com"); err == nil {
		t.Fatal("expected delete to fail")
	}
	if got := mustRead(t, sitePath(cfg, "api.example.com")); got != previous {
		t.Error("config was not restored after failed delete reload")
	}
	if _, err := os.Lstat(linkPath(cfg, "api.example.com")); err != nil {
		t.Errorf("symlink was not restored: %v", err)
	}
}

func TestDeleteRejectsUnmanagedFile(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)

	if err := os.WriteFile(sitePath(cfg, "api.example.com"), []byte("server {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(context.Background(), "api.example.com"); !errors.Is(err, ErrUnmanaged) {
		t.Fatalf("error = %v, want ErrUnmanaged", err)
	}
	if _, err := os.Stat(sitePath(cfg, "api.example.com")); err != nil {
		t.Error("unmanaged config must not be deleted")
	}
}

func TestValidateDryRun(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)

	var wrapperContent string
	runner.fail = func(name string, args []string) ([]byte, error) {
		if name == cfg.NginxBin && len(args) >= 3 {
			if data, err := os.ReadFile(args[2]); err == nil {
				wrapperContent = string(data)
			}
		}
		return nil, nil
	}

	result, err := svc.Validate(context.Background(), proxySite())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !result.Valid {
		t.Errorf("valid result = %+v", result)
	}
	if !strings.Contains(result.RenderedConfig, "proxy_pass") {
		t.Error("rendered config missing from result")
	}
	if !strings.Contains(wrapperContent, "access_log off;") {
		t.Errorf("validation wrapper must disable access logs:\n%s", wrapperContent)
	}
	entries, err := os.ReadDir(cfg.SitesAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("validate wrote to sites-available: %v", entries)
	}
	calls := runner.callsOf(cfg.NginxBin)
	if len(calls) != 1 {
		t.Fatalf("nginx calls = %d, want 1", len(calls))
	}
	if calls[0].args[0] != "-t" || calls[0].args[2] == cfg.NginxConfPath {
		t.Errorf("validate did not use a temporary -c: %v", calls[0].args)
	}

	bad := proxySite()
	bad.ProxyTarget = "http://8.8.8.8:80"
	result, err = svc.Validate(context.Background(), bad)
	if err != nil {
		t.Fatalf("Validate invalid: %v", err)
	}
	if result.Valid || len(result.Issues) == 0 {
		t.Errorf("invalid result = %+v", result)
	}
	if runner.callCount() != 1 {
		t.Error("invalid input must not invoke nginx")
	}
}

func TestValidateReportsNginxFailure(t *testing.T) {
	runner := &fakeRunner{fail: func(string, []string) ([]byte, error) {
		return []byte("nginx: [emerg] unknown directive"), errors.New("exit status 1")
	}}
	svc, _ := newTestService(t, runner)

	result, err := svc.Validate(context.Background(), proxySite())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Valid {
		t.Error("invalid nginx output must set valid=false")
	}
	if !strings.Contains(result.NginxOutput, "unknown directive") {
		t.Errorf("nginx output = %q", result.NginxOutput)
	}
}

func TestNginxActive(t *testing.T) {
	runner := &fakeRunner{}
	svc, _ := newTestService(t, runner)
	if !svc.NginxActive(context.Background()) {
		t.Error("NginxActive should be true when systemctl succeeds")
	}

	failing := &fakeRunner{fail: func(string, []string) ([]byte, error) {
		return nil, errors.New("inactive")
	}}
	svc, _ = newTestService(t, failing)
	if svc.NginxActive(context.Background()) {
		t.Error("NginxActive should be false when systemctl fails")
	}
}

func TestApplyConcurrentDifferentDomains(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, domainName := range []string{"a.example.com", "b.example.com"} {
		site := domain.SiteConfig{Domain: domainName, ProxyTarget: "http://127.0.0.1:3000"}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Apply(context.Background(), site); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Apply: %v", err)
	}
	for _, domainName := range []string{"a.example.com", "b.example.com"} {
		if _, err := os.Stat(sitePath(cfg, domainName)); err != nil {
			t.Errorf("%s not created: %v", domainName, err)
		}
	}
}

func TestPrivilegedCommandsUseSudo(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner, func(c *config.Config) { c.UseSudo = true })

	if _, err := svc.Apply(context.Background(), proxySite()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := runner.callsOf("sudo")
	if len(calls) != 2 {
		t.Fatalf("sudo calls = %d, want 2", len(calls))
	}
	want := [][]string{
		{"-n", cfg.NginxBin, "-t", "-c", cfg.NginxConfPath},
		{"-n", cfg.SystemctlBin, "reload", "nginx"},
	}
	for i, expected := range want {
		if got := strings.Join(calls[i].args, " "); got != strings.Join(expected, " ") {
			t.Errorf("sudo call %d = %q, want %q", i, got, strings.Join(expected, " "))
		}
	}

	// Status probes are unprivileged and must not need the sudoers entry.
	_ = svc.NginxActive(context.Background())
	if got := len(runner.callsOf("sudo")); got != 2 {
		t.Errorf("NginxActive used sudo: %d calls", got)
	}
	if got := len(runner.callsOf(cfg.SystemctlBin)); got != 1 {
		t.Errorf("unprivileged systemctl is-active calls = %d, want 1", got)
	}
}
