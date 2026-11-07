package config

import (
	"strings"
	"testing"
	"time"
)

func validEnv() map[string]string {
	return map[string]string{
		"LANDER_SECRET_TOKEN": strings.Repeat("t", MinSecretTokenLength),
	}
}

func getenv(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(getenv(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.SitesAvailable != DefaultSitesAvailable {
		t.Errorf("SitesAvailable = %q", cfg.SitesAvailable)
	}
	if cfg.AllowPublicUpstream {
		t.Error("AllowPublicUpstream should default to false")
	}
	if cfg.TrustedProxy {
		t.Error("TrustedProxy should default to false")
	}
	if cfg.AuthFailWindow != time.Minute {
		t.Errorf("AuthFailWindow = %v", cfg.AuthFailWindow)
	}
	if cfg.MaxEnvBodyBytes > cfg.MaxBodyBytes {
		t.Error("env body limit must not exceed the global body limit")
	}
}

func TestLoadOverrides(t *testing.T) {
	env := validEnv()
	env["LANDER_LISTEN_ADDR"] = "0.0.0.0:9090"
	env["LANDER_ALLOW_PUBLIC_UPSTREAM"] = "true"
	env["LANDER_TRUSTED_PROXY"] = "true"
	env["LANDER_AUTH_FAIL_LIMIT"] = "3"
	env["LANDER_AUTH_FAIL_WINDOW"] = "30s"
	env["LANDER_WEB_ROOT_BASE"] = "/srv/www"

	cfg, err := Load(getenv(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:9090" || !cfg.AllowPublicUpstream {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if !cfg.TrustedProxy {
		t.Error("TrustedProxy override not applied")
	}
	if cfg.AuthFailLimit != 3 || cfg.AuthFailWindow != 30*time.Second {
		t.Errorf("rate limit overrides not applied: %+v", cfg)
	}
	if cfg.WebRootBase != "/srv/www" {
		t.Errorf("WebRootBase = %q", cfg.WebRootBase)
	}
}

func TestLoadTokenValidation(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "missing", env: map[string]string{}},
		{name: "too short", env: map[string]string{"LANDER_SECRET_TOKEN": "short"}},
		{name: "whitespace", env: map[string]string{"LANDER_SECRET_TOKEN": strings.Repeat("a", 32) + " x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(getenv(tt.env)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := map[string]string{
		"LANDER_ALLOW_PUBLIC_UPSTREAM": "not-a-bool",
		"LANDER_LISTEN_ADDR":           "8080",
		"LANDER_WEB_ROOT_BASE":         "relative/path",
		"LANDER_AUTH_FAIL_LIMIT":       "0",
		"LANDER_AUTH_FAIL_WINDOW":      "-1s",
		"LANDER_MAX_ENV_BODY_BYTES":    "9999999999",
	}
	for key, value := range tests {
		t.Run(key, func(t *testing.T) {
			env := validEnv()
			env[key] = value
			if _, err := Load(getenv(env)); err == nil {
				t.Fatalf("expected an error for %s=%q", key, value)
			}
		})
	}
}
