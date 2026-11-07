package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yogaagungk/lander/internal/domain"
)

// normalizeETag accepts a quoted or unquoted If-Match value.
func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	return strings.Trim(value, `"`)
}

// GetSite returns the stored configuration for one site.
func (s *Nginx) GetSite(ctx context.Context, domainName string) (domain.SiteDetail, error) {
	if issues := validateDomain(domainName); len(issues) > 0 {
		return domain.SiteDetail{}, &ValidationError{Issues: issues}
	}
	_ = ctx

	final := s.sitePath(domainName)
	content, exists, err := readFileIfExists(final)
	if err != nil {
		return domain.SiteDetail{}, err
	}
	if !exists {
		return domain.SiteDetail{}, ErrNotFound
	}

	raw := string(content)
	detail := domain.SiteDetail{
		SiteSummary: domain.SiteSummary{
			Domain:        domainName,
			Enabled:       s.siteEnabled(final, s.linkPath(domainName)),
			SSL:           s.CertExists(domainName),
			CertExpiresAt: s.certExpiry(domainName),
			Managed:       isManagedConfig(content),
		},
		Config:    parseStructuredConfig(domainName, raw),
		RawConfig: raw,
		ETag:      ETag(raw),
	}
	detail.Config.EnableSSL = detail.SSL
	if info, err := os.Stat(final); err == nil {
		detail.UpdatedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	return detail, nil
}

// ListSites returns summaries for every *.conf file in sites-available.
func (s *Nginx) ListSites(ctx context.Context) ([]domain.SiteSummary, error) {
	entries, err := os.ReadDir(s.cfg.SitesAvailable)
	if errors.Is(err, os.ErrNotExist) {
		return []domain.SiteSummary{}, nil
	}
	if err != nil {
		return nil, err
	}

	sites := make([]domain.SiteSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		domainName := strings.TrimSuffix(entry.Name(), ".conf")
		if len(validateDomain(domainName)) > 0 {
			continue
		}
		detail, err := s.GetSite(ctx, domainName)
		if err != nil {
			continue
		}
		sites = append(sites, detail.SiteSummary)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites, nil
}

// parseStructuredConfig recovers the fields lander can infer from a stored
// file. custom_rules cannot be reconstructed and are left empty.
func parseStructuredConfig(domainName, raw string) domain.SiteConfig {
	config := domain.SiteConfig{Domain: domainName}
	tokens, err := tokenize(raw)
	if err != nil {
		return config
	}
	directives, err := parseDirectives(tokens)
	if err != nil {
		return config
	}
	for _, d := range directives {
		switch d.name {
		case "proxy_pass":
			if config.ProxyTarget == "" && len(d.args) == 1 {
				config.ProxyTarget = d.args[0]
			}
		case "root":
			if config.WebRoot == "" && len(d.args) == 1 {
				config.WebRoot = d.args[0]
			}
		}
	}
	return config
}

func (s *Nginx) siteEnabled(final, link string) bool {
	linkInfo, err := os.Stat(link)
	if err != nil {
		return false
	}
	finalInfo, err := os.Stat(final)
	if err != nil {
		return false
	}
	return os.SameFile(linkInfo, finalInfo)
}

// certExpiry reads the NotAfter of the first certificate in fullchain.pem.
func (s *Nginx) certExpiry(domainName string) string {
	if s.cfg.LetsEncryptDir == "" {
		return ""
	}
	path := filepath.Join(s.cfg.LetsEncryptDir, domainName, "fullchain.pem")
	// #nosec G304 -- path is built from a validated domain and configured root.
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return ""
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return ""
			}
			return cert.NotAfter.UTC().Format(time.RFC3339)
		}
		rest = remaining
	}
}
