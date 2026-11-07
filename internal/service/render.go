package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/yogaagungk/lander/internal/domain"
)

// managedMarker is written into every file lander owns. Files without it are
// treated as user-managed and never overwritten or deleted.
const managedMarker = "# Managed by lander"

// RenderOptions controls optional parts of the generated configuration.
type RenderOptions struct {
	CertExists bool
	CertDir    string
}

var siteTemplate = template.Must(template.New("site").Parse(`# Managed by lander — generated file; manual edits will be overwritten.
# domain: {{.Domain}}

{{if .SSL}}server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}};
    return 301 https://$host$request_uri;
}

{{end}}server {
    listen {{.Listen}};
{{if .SSL}}    listen {{.ListenTLS}};
    ssl_certificate {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};
{{else}}    listen [::]:80;
{{end}}    server_name {{.Domain}};
{{range .Rules}}    {{.}}
{{end}}{{if .WebRoot}}    root {{.WebRoot}};
    index index.html index.htm;
{{end}}{{.Location}}}
`))

type renderData struct {
	Domain    string
	SSL       bool
	Listen    string
	ListenTLS string
	CertPath  string
	KeyPath   string
	WebRoot   string
	Rules     []string
	Location  string
}

// Render generates the Nginx configuration for a validated SiteConfig.
// A raw_config is passed through with the managed marker prepended; callers
// must validate it first. Warnings describe conditions that did not block the
// apply (for example enable_ssl without an issued certificate).
func Render(sc domain.SiteConfig, opts RenderOptions) (string, []string, error) {
	if sc.RawConfig != "" {
		return managedMarker + " — raw config\n" + ensureTrailingNewline(sc.RawConfig), nil, nil
	}

	data := renderData{
		Domain:   sc.Domain,
		WebRoot:  sc.WebRoot,
		Rules:    sc.CustomRules,
		Location: buildLocation(sc),
	}
	var warnings []string

	if sc.EnableSSL {
		if opts.CertExists {
			data.SSL = true
			data.Listen = "443 ssl http2"
			data.ListenTLS = "[::]:443 ssl http2"
			certDir := opts.CertDir
			if certDir == "" {
				certDir = "/etc/letsencrypt/live"
			}
			data.CertPath = filepath.Join(certDir, sc.Domain, "fullchain.pem")
			data.KeyPath = filepath.Join(certDir, sc.Domain, "privkey.pem")
		} else {
			warnings = append(warnings, fmt.Sprintf("no certificate found for %s; rendered HTTP only (use POST /api/v1/nginx/ssl)", sc.Domain))
		}
	}
	if data.Listen == "" {
		data.Listen = "80"
	}

	var buf bytes.Buffer
	if err := siteTemplate.Execute(&buf, data); err != nil {
		return "", nil, fmt.Errorf("render site config: %w", err)
	}
	return buf.String(), warnings, nil
}

func buildLocation(sc domain.SiteConfig) string {
	var b strings.Builder
	switch {
	case sc.ProxyTarget != "" && sc.WebRoot != "":
		b.WriteString("\n    location / {\n")
		b.WriteString("        try_files $uri $uri/ @lander_upstream;\n")
		b.WriteString("    }\n\n    location @lander_upstream {\n")
		writeProxyDirectives(&b, sc.ProxyTarget)
		b.WriteString("    }\n")
	case sc.ProxyTarget != "":
		b.WriteString("\n    location / {\n")
		writeProxyDirectives(&b, sc.ProxyTarget)
		b.WriteString("    }\n")
	case sc.WebRoot != "":
		b.WriteString("\n    location / {\n")
		b.WriteString("        try_files $uri $uri/ =404;\n")
		b.WriteString("    }\n")
	}
	return b.String()
}

func writeProxyDirectives(b *strings.Builder, target string) {
	fmt.Fprintf(b, "        proxy_pass %s;\n", target)
	b.WriteString("        proxy_http_version 1.1;\n")
	b.WriteString("        proxy_set_header Host $host;\n")
	b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	b.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
	b.WriteString("        proxy_read_timeout 60s;\n")
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// ETag returns the sha256 of a rendered config as lowercase hex. Clients send
// it back as If-Match to detect concurrent edits.
func ETag(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}
