// Package config loads lander's runtime configuration from environment
// variables. It deliberately uses only the standard library: the PRD asks for
// a minimal dependency set.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for every knob. Values are overridable through Load.
const (
	DefaultListenAddr      = "127.0.0.1:8080"
	DefaultSitesAvailable  = "/etc/nginx/sites-available"
	DefaultSitesEnabled    = "/etc/nginx/sites-enabled"
	DefaultNginxConf       = "/etc/nginx/nginx.conf"
	DefaultNginxBin        = "/usr/sbin/nginx"
	DefaultSystemctlBin    = "/usr/bin/systemctl"
	DefaultCertbotBin      = "/usr/local/sbin/lander-certbot"
	DefaultWebRootBase     = "/var/www"
	DefaultLetsEncryptDir  = "/etc/letsencrypt/live"
	DefaultEnvDir          = "/var/lib/lander/env"
	DefaultAuditLog        = "/var/log/lander/audit.log"
	DefaultMaxBodyBytes    = 1 << 20 // 1 MiB
	DefaultMaxEnvBodyBytes = 256 << 10
	DefaultAuthFailLimit   = 10
	DefaultAuthFailWindow  = time.Minute
	DefaultShutdownTimeout = 10 * time.Second
	DefaultCommandTimeout  = 15 * time.Second
	MinSecretTokenLength   = 32
)

// Config is lander's fully resolved runtime configuration.
type Config struct {
	ListenAddr          string
	SecretToken         string
	Version             string
	SitesAvailable      string
	SitesEnabled        string
	NginxConfPath       string
	NginxBin            string
	SystemctlBin        string
	CertbotBin          string
	WebRootBase         string
	LetsEncryptDir      string
	EnvDir              string
	AuditLogPath        string
	AllowPublicUpstream bool
	UseSudo             bool
	TrustedProxy        bool

	MaxBodyBytes    int64
	MaxEnvBodyBytes int64

	AuthFailLimit  int
	AuthFailWindow time.Duration

	ShutdownTimeout time.Duration
	CommandTimeout  time.Duration
}

// Load resolves the configuration. getenv may be nil, in which case
// os.Getenv is used; tests pass a map-backed function.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg := Config{
		ListenAddr:     envOr(getenv, "LANDER_LISTEN_ADDR", DefaultListenAddr),
		SecretToken:    getenv("LANDER_SECRET_TOKEN"),
		Version:        envOr(getenv, "LANDER_VERSION", "dev"),
		SitesAvailable: envOr(getenv, "LANDER_SITES_AVAILABLE", DefaultSitesAvailable),
		SitesEnabled:   envOr(getenv, "LANDER_SITES_ENABLED", DefaultSitesEnabled),
		NginxConfPath:  envOr(getenv, "LANDER_NGINX_CONF", DefaultNginxConf),
		NginxBin:       envOr(getenv, "LANDER_NGINX_BIN", DefaultNginxBin),
		SystemctlBin:   envOr(getenv, "LANDER_SYSTEMCTL_BIN", DefaultSystemctlBin),
		CertbotBin:     envOr(getenv, "LANDER_CERTBOT_BIN", DefaultCertbotBin),
		WebRootBase:    envOr(getenv, "LANDER_WEB_ROOT_BASE", DefaultWebRootBase),
		LetsEncryptDir: envOr(getenv, "LANDER_LETSENCRYPT_DIR", DefaultLetsEncryptDir),
		EnvDir:         envOr(getenv, "LANDER_ENV_DIR", DefaultEnvDir),
		AuditLogPath:   envOr(getenv, "LANDER_AUDIT_LOG", DefaultAuditLog),
	}

	var err error
	if cfg.AllowPublicUpstream, err = parseBool(getenv, "LANDER_ALLOW_PUBLIC_UPSTREAM", false); err != nil {
		return Config{}, err
	}
	if cfg.UseSudo, err = parseBool(getenv, "LANDER_SUDO", false); err != nil {
		return Config{}, err
	}
	if cfg.TrustedProxy, err = parseBool(getenv, "LANDER_TRUSTED_PROXY", false); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBytes, err = parseInt64(getenv, "LANDER_MAX_BODY_BYTES", DefaultMaxBodyBytes); err != nil {
		return Config{}, err
	}
	if cfg.MaxEnvBodyBytes, err = parseInt64(getenv, "LANDER_MAX_ENV_BODY_BYTES", DefaultMaxEnvBodyBytes); err != nil {
		return Config{}, err
	}
	if cfg.AuthFailLimit, err = parseInt(getenv, "LANDER_AUTH_FAIL_LIMIT", DefaultAuthFailLimit); err != nil {
		return Config{}, err
	}
	if cfg.AuthFailWindow, err = parseDuration(getenv, "LANDER_AUTH_FAIL_WINDOW", DefaultAuthFailWindow); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = parseDuration(getenv, "LANDER_SHUTDOWN_TIMEOUT", DefaultShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.CommandTimeout, err = parseDuration(getenv, "LANDER_COMMAND_TIMEOUT", DefaultCommandTimeout); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the assembled configuration and is also used after tests
// build a Config literal directly.
func (c Config) Validate() error {
	if err := validateToken(c.SecretToken); err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("config: LANDER_LISTEN_ADDR %q is not host:port: %w", c.ListenAddr, err)
	}
	for name, path := range map[string]string{
		"LANDER_SITES_AVAILABLE": c.SitesAvailable,
		"LANDER_SITES_ENABLED":   c.SitesEnabled,
		"LANDER_NGINX_CONF":      c.NginxConfPath,
		"LANDER_NGINX_BIN":       c.NginxBin,
		"LANDER_SYSTEMCTL_BIN":   c.SystemctlBin,
		"LANDER_CERTBOT_BIN":     c.CertbotBin,
		"LANDER_WEB_ROOT_BASE":   c.WebRootBase,
		"LANDER_LETSENCRYPT_DIR": c.LetsEncryptDir,
		"LANDER_ENV_DIR":         c.EnvDir,
	} {
		if !strings.HasPrefix(path, "/") {
			return fmt.Errorf("config: %s must be an absolute path, got %q", name, path)
		}
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: LANDER_MAX_BODY_BYTES must be positive")
	}
	if c.MaxEnvBodyBytes <= 0 || c.MaxEnvBodyBytes > c.MaxBodyBytes {
		return fmt.Errorf("config: LANDER_MAX_ENV_BODY_BYTES must be positive and <= LANDER_MAX_BODY_BYTES")
	}
	if c.AuthFailLimit < 1 {
		return fmt.Errorf("config: LANDER_AUTH_FAIL_LIMIT must be >= 1")
	}
	if c.AuthFailWindow <= 0 {
		return fmt.Errorf("config: LANDER_AUTH_FAIL_WINDOW must be positive")
	}
	if c.CommandTimeout <= 0 {
		return fmt.Errorf("config: LANDER_COMMAND_TIMEOUT must be positive")
	}
	return nil
}

func validateToken(token string) error {
	if token == "" {
		return fmt.Errorf("config: LANDER_SECRET_TOKEN is required")
	}
	if len(token) < MinSecretTokenLength {
		return fmt.Errorf("config: LANDER_SECRET_TOKEN must be at least %d bytes", MinSecretTokenLength)
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("config: LANDER_SECRET_TOKEN must not contain whitespace")
	}
	return nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseBool(getenv func(string) string, key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: %s: %w", key, err)
	}
	return v, nil
}

func parseInt(getenv func(string) string, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return v, nil
}

func parseInt64(getenv func(string) string, key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return v, nil
}

func parseDuration(getenv func(string) string, key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return v, nil
}
