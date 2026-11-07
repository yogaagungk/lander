package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogaagungk/lander/internal/domain"
)

func TestApplyWithETag(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	detail, err := svc.GetSite(ctx, "api.example.com")
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if detail.ETag != ETag(detail.RawConfig) {
		t.Error("etag does not hash raw_config")
	}
	if detail.Config.ProxyTarget != "http://127.0.0.1:3000" {
		t.Errorf("parsed proxy target = %q", detail.Config.ProxyTarget)
	}

	changed := proxySite()
	changed.ProxyTarget = "http://127.0.0.1:4000"

	if _, err := svc.ApplyWithETag(ctx, changed, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale etag error = %v, want ErrConflict", err)
	}
	result, err := svc.ApplyWithETag(ctx, changed, `"`+detail.ETag+`"`)
	if err != nil {
		t.Fatalf("matching etag apply: %v", err)
	}
	if !result.Changed || result.Created {
		t.Errorf("result = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(cfg.SitesAvailable, "api.example.com.conf.bak")); !errors.Is(err, os.ErrNotExist) {
		t.Error("backup left behind")
	}
}

func TestGetSiteAndListSites(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	b := domain.SiteConfig{Domain: "b.example.com", ProxyTarget: "http://127.0.0.1:3001"}
	a := domain.SiteConfig{Domain: "a.example.com", ProxyTarget: "http://127.0.0.1:3000"}
	for _, site := range []domain.SiteConfig{b, a} {
		if _, err := svc.Apply(ctx, site); err != nil {
			t.Fatalf("apply %s: %v", site.Domain, err)
		}
	}
	// Junk files must be ignored by the listing.
	if err := os.WriteFile(filepath.Join(cfg.SitesAvailable, "junk.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	sites, err := svc.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(sites) != 2 || sites[0].Domain != "a.example.com" || sites[1].Domain != "b.example.com" {
		t.Fatalf("sites = %+v", sites)
	}
	if !sites[0].Enabled || sites[0].SSL {
		t.Errorf("summary = %+v", sites[0])
	}

	if _, err := svc.GetSite(ctx, "missing.example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site error = %v", err)
	}
	if _, err := svc.GetSite(ctx, "BAD Domain"); err == nil {
		t.Error("invalid domain was accepted")
	}

	unmanaged := filepath.Join(cfg.SitesAvailable, "hand.example.com.conf")
	if err := os.WriteFile(unmanaged, []byte("server {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	detail, err := svc.GetSite(ctx, "hand.example.com")
	if err != nil {
		t.Fatalf("unmanaged GetSite: %v", err)
	}
	if detail.Managed {
		t.Error("unmanaged file reported as managed")
	}
}

func TestEmptyDirectoryList(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	if err := os.RemoveAll(cfg.SitesAvailable); err != nil {
		t.Fatal(err)
	}
	sites, err := svc.ListSites(context.Background())
	if err != nil || len(sites) != 0 {
		t.Fatalf("ListSites = %v, %v", sites, err)
	}
}

func TestGetSiteWithCertificate(t *testing.T) {
	runner := &fakeRunner{}
	svc, cfg := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("apply: %v", err)
	}
	writeTestCertificate(t, filepath.Join(cfg.LetsEncryptDir, "api.example.com"), "api.example.com")

	detail, err := svc.GetSite(ctx, "api.example.com")
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if !detail.SSL || !detail.Config.EnableSSL {
		t.Errorf("certificate not reflected: %+v", detail.SiteSummary)
	}
	if detail.CertExpiresAt == "" {
		t.Error("cert expiry missing")
	}
	if _, err := time.Parse(time.RFC3339, detail.CertExpiresAt); err != nil {
		t.Errorf("cert expiry format: %v", err)
	}
}

func TestIssueSSL(t *testing.T) {
	runner := &fakeRunner{}
	svc, _ := newTestService(t, runner)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, proxySite()); err != nil {
		t.Fatalf("apply: %v", err)
	}

	result, err := svc.IssueSSL(ctx, domain.SSLRequest{Domain: "api.example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("IssueSSL: %v", err)
	}
	if !result.Issued || result.Domain != "api.example.com" {
		t.Errorf("result = %+v", result)
	}
	calls := runner.callsOf("/usr/bin/certbot")
	if len(calls) != 1 {
		t.Fatalf("certbot calls = %d", len(calls))
	}
	joined := strings.Join(calls[0].args, " ")
	for _, want := range []string{"certonly", "--nginx", "-d api.example.com", "--email admin@example.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("certbot args missing %q: %s", want, joined)
		}
	}

	if _, err := svc.IssueSSL(ctx, domain.SSLRequest{Domain: "missing.example.com", Email: "a@b.co"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing site error = %v", err)
	}
	if _, err := svc.IssueSSL(ctx, domain.SSLRequest{Domain: "api.example.com", Email: "bad"}); err == nil {
		t.Error("invalid email was accepted")
	}

	runner.fail = func(name string, _ []string) ([]byte, error) {
		if name == "/usr/bin/certbot" {
			return []byte("certbot failed"), errors.New("exit status 1")
		}
		return nil, nil
	}
	_, err = svc.IssueSSL(ctx, domain.SSLRequest{Domain: "api.example.com", Email: "admin@example.com"})
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Op != "certbot" {
		t.Fatalf("error = %v, want certbot CommandError", err)
	}
}

func TestEnvStoreLifecycle(t *testing.T) {
	store := NewEnvStore(t.TempDir())
	ctx := context.Background()

	result, err := store.Write(ctx, domain.EnvRequest{
		App:  "my-api",
		Vars: map[string]string{"B": "2", "A": "1"},
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if strings.Join(result.Keys, ",") != "A,B" {
		t.Errorf("keys = %v", result.Keys)
	}
	path := filepath.Join(store.dir, "my-api.env")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", info.Mode().Perm())
	}

	result, err = store.Write(ctx, domain.EnvRequest{
		App:        "my-api",
		Vars:       map[string]string{"C": "3"},
		DeleteKeys: []string{"A"},
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if strings.Join(result.Keys, ",") != "B,C" {
		t.Errorf("merge keys = %v", result.Keys)
	}

	result, err = store.Write(ctx, domain.EnvRequest{
		App:  "my-api",
		Mode: "replace",
		Vars: map[string]string{"D": "4"},
	})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if strings.Join(result.Keys, ",") != "D" {
		t.Errorf("replace keys = %v", result.Keys)
	}

	_, err = store.Write(ctx, domain.EnvRequest{App: "my-api", Vars: map[string]string{"bad": "x"}})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("invalid env error = %v, want ValidationError", err)
	}
}

func TestEnvFileParsingSkipsJunk(t *testing.T) {
	vars := parseEnvFile([]byte("# comment\nA=1\n\nbad line\nB=\nlower=x\n"))
	if len(vars) != 2 || vars["A"] != "1" || vars["B"] != "" {
		t.Errorf("vars = %v", vars)
	}
}

func TestSystemStatus(t *testing.T) {
	runner := &fakeRunner{}
	svc, _ := newTestService(t, runner)
	svc.SetStatsProvider(fakeStatsProvider{cpu: 10, memory: 20, uptime: 30})

	status, err := svc.SystemStatus(context.Background())
	if err != nil {
		t.Fatalf("SystemStatus: %v", err)
	}
	if status.CPUUsage != 10 || status.MemoryUsage != 20 || status.Uptime != 30 || !status.NginxActive {
		t.Errorf("status = %+v", status)
	}
}

type fakeStatsProvider struct {
	cpu, memory float64
	uptime      uint64
	err         error
}

func (f fakeStatsProvider) CPUPercent(context.Context, time.Duration) (float64, error) {
	return f.cpu, f.err
}
func (f fakeStatsProvider) MemoryUsedPercent(context.Context) (float64, error) {
	return f.memory, f.err
}
func (f fakeStatsProvider) Uptime(context.Context) (uint64, error) { return f.uptime, f.err }

func TestExecRunner(t *testing.T) {
	out, err := (ExecRunner{}).Run(context.Background(), "/bin/echo", "hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("output = %q", out)
	}
}

func TestNormalizeETag(t *testing.T) {
	for _, value := range []string{"abc", `"abc"`, `W/"abc"`, "  abc  "} {
		if got := normalizeETag(value); got != "abc" {
			t.Errorf("normalizeETag(%q) = %q", value, got)
		}
	}
}

func TestServiceErrorStrings(t *testing.T) {
	if got := (&ValidationError{}).Error(); got == "" {
		t.Error("empty ValidationError has no message")
	}
	inner := errors.New("boom")
	commandErr := &CommandError{Op: "nginx -t", Output: "bad", Err: inner}
	if !strings.Contains(commandErr.Error(), "nginx -t") || !errors.Is(commandErr, inner) {
		t.Errorf("CommandError = %q", commandErr.Error())
	}
}

func writeTestCertificate(t *testing.T, dir, domainName string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domainName},
		DNSNames:     []string{domainName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnvStoreConcurrentWrites(t *testing.T) {
	store := NewEnvStore(t.TempDir())
	const writers = 20

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		key := fmt.Sprintf("KEY_%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Write(context.Background(), domain.EnvRequest{
				App:  "app",
				Vars: map[string]string{key: "v"},
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	data, err := os.ReadFile(filepath.Join(store.dir, "app.env"))
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	for i := 0; i < writers; i++ {
		if key := fmt.Sprintf("KEY_%02d=", i); !strings.Contains(string(data), key) {
			t.Errorf("lost concurrent write %s:\n%s", key, data)
		}
	}
}
