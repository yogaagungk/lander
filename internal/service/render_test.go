package service

import (
	"strings"
	"testing"

	"github.com/yogaagungk/lander/internal/domain"
)

func TestRenderProxySite(t *testing.T) {
	cfg := domain.SiteConfig{
		Domain:      "api.example.com",
		ProxyTarget: "http://127.0.0.1:3000",
		CustomRules: []string{"client_max_body_size 10m;", "add_header X-Frame-Options DENY;"},
	}
	out, warnings, err := Render(cfg, RenderOptions{CertDir: "/etc/letsencrypt/live"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	t.Logf("rendered:\n%s", out)

	for _, want := range []string{
		managedMarker,
		"server_name api.example.com;",
		"listen 80;",
		"listen [::]:80;",
		"proxy_pass http://127.0.0.1:3000;",
		"proxy_set_header Host $host;",
		"client_max_body_size 10m;",
		"add_header X-Frame-Options DENY;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}
	if strings.Contains(out, "443") {
		t.Error("non-SSL config must not contain a 443 listener")
	}
}

func TestRenderSSLWhenCertificateExists(t *testing.T) {
	cfg := domain.SiteConfig{
		Domain:      "api.example.com",
		ProxyTarget: "http://127.0.0.1:3000",
		EnableSSL:   true,
	}
	out, warnings, err := Render(cfg, RenderOptions{CertExists: true, CertDir: "/etc/letsencrypt/live"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	for _, want := range []string{
		"return 301 https://$host$request_uri;",
		"listen 443 ssl http2;",
		"listen [::]:443 ssl http2;",
		"ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;",
		"ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered SSL config missing %q", want)
		}
	}
}

func TestRenderSSLWithoutCertificateWarns(t *testing.T) {
	cfg := domain.SiteConfig{
		Domain:      "api.example.com",
		ProxyTarget: "http://127.0.0.1:3000",
		EnableSSL:   true,
	}
	out, warnings, err := Render(cfg, RenderOptions{CertExists: false})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no certificate") {
		t.Fatalf("warnings = %v, want one certificate warning", warnings)
	}
	if strings.Contains(out, "443") {
		t.Error("config without a certificate must render HTTP only")
	}
}

func TestRenderStaticAndProxyFallback(t *testing.T) {
	cfg := domain.SiteConfig{
		Domain:      "app.example.com",
		ProxyTarget: "http://127.0.0.1:8081",
		WebRoot:     "/var/www/app",
	}
	out, _, err := Render(cfg, RenderOptions{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"root /var/www/app;",
		"try_files $uri $uri/ @lander_upstream;",
		"location @lander_upstream {",
		"proxy_pass http://127.0.0.1:8081;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}
}

func TestRenderStaticOnly(t *testing.T) {
	cfg := domain.SiteConfig{Domain: "static.example.com", WebRoot: "/var/www/static"}
	out, _, err := Render(cfg, RenderOptions{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "try_files $uri $uri/ =404;") {
		t.Errorf("static config missing try_files fallback:\n%s", out)
	}
	if strings.Contains(out, "proxy_pass") {
		t.Error("static-only config must not proxy")
	}
}

func TestRenderRawConfigKeepsMarker(t *testing.T) {
	raw := "server {\n    listen 80;\n    server_name raw.example.com;\n}\n"
	out, _, err := Render(domain.SiteConfig{Domain: "raw.example.com", RawConfig: raw}, RenderOptions{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.HasPrefix(out, managedMarker) {
		t.Errorf("raw config must start with the managed marker:\n%s", out)
	}
	if !strings.Contains(out, raw) {
		t.Errorf("raw config body was altered:\n%s", out)
	}
}

func TestETagIsStableAndSensitive(t *testing.T) {
	a := ETag("one")
	if len(a) != 64 {
		t.Fatalf("etag length = %d, want 64", len(a))
	}
	if a != ETag("one") {
		t.Error("etag must be deterministic")
	}
	if a == ETag("two") {
		t.Error("different configs must produce different etags")
	}
}
