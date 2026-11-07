// Package domain holds the data models shared by lander's services and
// HTTP handlers. The JSON tags are the public API contract (see openapi.yaml).
package domain

// SiteConfig is the structured request body for creating or updating a
// managed Nginx site. RawConfig, when set, is mutually exclusive with every
// other field except Domain.
type SiteConfig struct {
	Domain      string   `json:"domain"`
	ProxyTarget string   `json:"proxy_target,omitempty"`
	EnableSSL   bool     `json:"enable_ssl,omitempty"`
	WebRoot     string   `json:"web_root,omitempty"`
	CustomRules []string `json:"custom_rules,omitempty"`
	RawConfig   string   `json:"raw_config,omitempty"`
}

// SystemStatus is returned by GET /api/v1/system/stats.
type SystemStatus struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	NginxActive bool    `json:"nginx_active"`
	Uptime      uint64  `json:"uptime"`
}

// SiteSummary describes a managed site without its full configuration.
type SiteSummary struct {
	Domain        string `json:"domain"`
	ProxyTarget   string `json:"proxy_target,omitempty"`
	Enabled       bool   `json:"enabled"`
	SSL           bool   `json:"ssl"`
	CertExpiresAt string `json:"cert_expires_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
	Managed       bool   `json:"managed"`
}

// SiteDetail is a SiteSummary plus the structured and raw configuration.
type SiteDetail struct {
	SiteSummary
	Config    SiteConfig `json:"config"`
	RawConfig string     `json:"raw_config"`
	ETag      string     `json:"etag"`
}

// ApplyResult is returned by POST /api/v1/nginx/site.
type ApplyResult struct {
	Domain   string   `json:"domain"`
	Changed  bool     `json:"changed"`
	Reloaded bool     `json:"reloaded"`
	ETag     string   `json:"etag,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// Created is internal-only and selects 201 vs 200.
	Created bool `json:"-"`
}

// ValidateResult is returned by POST /api/v1/nginx/validate.
type ValidateResult struct {
	Valid          bool    `json:"valid"`
	Issues         []Issue `json:"issues,omitempty"`
	NginxOutput    string  `json:"nginx_output,omitempty"`
	RenderedConfig string  `json:"rendered_config,omitempty"`
}

// Issue is a single validation problem.
type Issue struct {
	Field   string `json:"field,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

// SSLRequest is the body of POST /api/v1/nginx/ssl.
type SSLRequest struct {
	Domain string `json:"domain"`
	Email  string `json:"email"`
}

// SSLResult is returned by POST /api/v1/nginx/ssl.
type SSLResult struct {
	Domain    string `json:"domain"`
	Issued    bool   `json:"issued"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// EnvRequest is the write-only body of POST /api/v1/env.
type EnvRequest struct {
	App        string            `json:"app"`
	Mode       string            `json:"mode,omitempty"`
	Vars       map[string]string `json:"vars"`
	DeleteKeys []string          `json:"delete_keys,omitempty"`
}

// EnvResult acknowledges an env write with sorted key names only.
type EnvResult struct {
	App  string   `json:"app"`
	Keys []string `json:"keys"`
}

// Health is returned by GET /healthz.
type Health struct {
	Status      string `json:"status"`
	Version     string `json:"version,omitempty"`
	NginxActive bool   `json:"nginx_active"`
}

// ErrorBody is the inner object of every error response.
type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// ErrorResponse is the uniform error envelope.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ValidationErrorResponse adds per-field issues to ErrorResponse.
type ValidationErrorResponse struct {
	Error  ErrorBody `json:"error"`
	Issues []Issue   `json:"issues,omitempty"`
}
