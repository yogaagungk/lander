package service

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/yogaagungk/lander/internal/domain"
)

// Policy carries the deployment-specific limits used by validation.
type Policy struct {
	AllowPublicUpstream bool
	WebRootBase         string
	LetsEncryptDir      string
}

const (
	maxDomainLength   = 253
	maxProxyTargetLen = 2048
	maxRuleLength     = 512
	maxRules          = 32
	maxRawConfigLen   = 262144
)

var (
	domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	// hostRE accepts a single DNS label (docker service name) or an FQDN.
	hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// allowedDirectives is the ADR-002 allow-list for custom_rules.
var allowedDirectives = map[string]bool{
	"add_header":            true,
	"client_max_body_size":  true,
	"proxy_read_timeout":    true,
	"proxy_send_timeout":    true,
	"proxy_connect_timeout": true,
	"proxy_set_header":      true,
	"rewrite":               true,
	"return":                true,
	"expires":               true,
	"limit_req":             true,
	"limit_req_status":      true,
	"limit_req_log_level":   true,
	"limit_conn":            true,
	"limit_conn_status":     true,
	"limit_conn_log_level":  true,
	"gzip":                  true,
	"gzip_types":            true,
	"gzip_min_length":       true,
	"gzip_comp_level":       true,
	"gzip_proxied":          true,
	"gzip_vary":             true,
	"gzip_disable":          true,
	"gzip_buffers":          true,
	"gzip_http_version":     true,
	"gzip_static":           true,
}

// rawAllowedStructural are the additional directives a raw server block may
// use. Everything not listed here or in allowedDirectives is rejected.
var rawAllowedStructural = map[string]bool{
	"server":      true,
	"location":    true,
	"if":          true,
	"listen":      true,
	"server_name": true,
	"root":        true,
	"index":       true,
	"try_files":   true,
	"error_page":  true,
	"set":         true,
	"charset":     true,
	"allow":       true,
	"deny":        true,
}

// rawForbiddenProxyParts keeps proxy_* surface small: no file writes, cache
// paths or certificate overrides.
var rawForbiddenProxyParts = []string{
	"store", "temp", "cache", "ssl_certificate", "ssl_password",
	"ssl_trusted", "ssl_crl", "ssl_verify",
}

// allowedListenAddresses prevents raw_config from creating files such as
// unix:/etc/cron.d/x (the nginx master runs as root).
var allowedListenAddresses = map[string]bool{
	"80":          true,
	"443":         true,
	"[::]:80":     true,
	"[::]:443":    true,
	"0.0.0.0:80":  true,
	"0.0.0.0:443": true,
}

var allowedListenFlags = map[string]bool{
	"ssl":            true,
	"http2":          true,
	"default_server": true,
	"reuseport":      true,
}

// rawAllowedSSL is the tuning set houston may round-trip for an HTTPS site.
// Certificate paths are checked separately against the managed cert dir.
var rawAllowedSSL = map[string]bool{
	"ssl_certificate":           true,
	"ssl_certificate_key":       true,
	"ssl_protocols":             true,
	"ssl_ciphers":               true,
	"ssl_prefer_server_ciphers": true,
	"ssl_session_cache":         true,
	"ssl_session_timeout":       true,
	"ssl_session_tickets":       true,
	"ssl_stapling":              true,
}

// ValidateSite validates a SiteConfig against ADR-002. It returns an empty
// slice when the request is safe to render and apply. Validation never
// "repairs" input: callers must reject the request.
func ValidateSite(sc domain.SiteConfig, policy Policy) []domain.Issue {
	var issues []domain.Issue

	issues = append(issues, validateDomain(sc.Domain)...)

	rawSet := sc.RawConfig != ""
	structuredSet := sc.ProxyTarget != "" || sc.WebRoot != "" || sc.EnableSSL || len(sc.CustomRules) > 0
	if rawSet && structuredSet {
		issues = append(issues, domain.Issue{
			Field:   "raw_config",
			Message: "raw_config is mutually exclusive with proxy_target, web_root, enable_ssl and custom_rules",
		})
		return issues
	}

	if rawSet {
		return append(issues, validateRawConfig(sc.RawConfig, sc.Domain, policy)...)
	}

	if sc.ProxyTarget == "" && sc.WebRoot == "" {
		issues = append(issues, domain.Issue{
			Field:   "proxy_target",
			Message: "either proxy_target or web_root is required",
		})
	}
	if sc.ProxyTarget != "" {
		issues = append(issues, validateProxyTarget(sc.ProxyTarget, policy)...)
	}
	if sc.WebRoot != "" {
		issues = append(issues, validateWebRoot(sc.WebRoot, policy.WebRootBase)...)
	}
	issues = append(issues, validateCustomRules(sc.CustomRules)...)

	return issues
}

func validateDomain(domainName string) []domain.Issue {
	switch {
	case domainName == "":
		return []domain.Issue{{Field: "domain", Message: "domain is required"}}
	case len(domainName) > maxDomainLength:
		return []domain.Issue{{Field: "domain", Message: fmt.Sprintf("domain must be at most %d characters", maxDomainLength)}}
	case !domainRE.MatchString(domainName):
		return []domain.Issue{{Field: "domain", Message: "domain must be a lowercase RFC-1123 hostname without wildcards, paths or whitespace"}}
	}
	return nil
}

func validateProxyTarget(raw string, policy Policy) []domain.Issue {
	field := "proxy_target"
	switch {
	case len(raw) > maxProxyTargetLen:
		return []domain.Issue{{Field: field, Message: fmt.Sprintf("proxy_target must be at most %d characters", maxProxyTargetLen)}}
	case strings.TrimSpace(raw) != raw:
		return []domain.Issue{{Field: field, Message: "proxy_target must not contain leading or trailing whitespace"}}
	}
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune(";{}\\'\"`", r) {
			return []domain.Issue{{Field: field, Message: "proxy_target contains a forbidden character"}}
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return []domain.Issue{{Field: field, Message: "proxy_target is not a valid URL: " + err.Error()}}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return []domain.Issue{{Field: field, Message: "proxy_target must use http or https"}}
	}
	if u.User != nil {
		return []domain.Issue{{Field: field, Message: "proxy_target must not contain userinfo"}}
	}
	if u.Host == "" || u.Hostname() == "" {
		return []domain.Issue{{Field: field, Message: "proxy_target must include a host"}}
	}
	if u.Fragment != "" {
		return []domain.Issue{{Field: field, Message: "proxy_target must not contain a fragment"}}
	}
	if u.Scheme == "http" && u.Port() == "" {
		return []domain.Issue{{Field: field, Message: "proxy_target must include an explicit port for http"}}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return []domain.Issue{{Field: field, Message: "proxy_target port must be between 1 and 65535"}}
		}
	}
	if strings.Contains(u.Path, "..") || strings.Contains(u.RawPath, "..") {
		return []domain.Issue{{Field: field, Message: "proxy_target path must not contain '..'"}}
	}

	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) == nil && (!hostRE.MatchString(host) || len(host) > maxDomainLength) {
		return []domain.Issue{{Field: field, Message: "proxy_target host must be an IP address or a valid hostname"}}
	}
	if !policy.AllowPublicUpstream && !isLocalUpstream(host) {
		return []domain.Issue{{Field: field, Message: "proxy_target host must be loopback or RFC1918 when LANDER_ALLOW_PUBLIC_UPSTREAM is false"}}
	}
	return nil
}

func isLocalUpstream(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // a public DNS name cannot be verified offline
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func validateWebRoot(raw, base string) []domain.Issue {
	field := "web_root"
	if raw == "" {
		return nil
	}
	if !filepath.IsAbs(raw) {
		return []domain.Issue{{Field: field, Message: "web_root must be an absolute path"}}
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(";{}\\'\"`#", r) {
			return []domain.Issue{{Field: field, Message: "web_root contains a forbidden character"}}
		}
	}
	if base == "" {
		base = "/var/www"
	}
	cleanBase := filepath.Clean(base)
	cleanRoot := filepath.Clean(raw)
	if !withinBase(cleanRoot, cleanBase) {
		return []domain.Issue{{Field: field, Message: fmt.Sprintf("web_root must be under %s", cleanBase)}}
	}

	// Guard against symlink escapes. Missing paths are resolved through their
	// nearest existing ancestor so the check also works before mkdir.
	evalBase, err := evalAllowMissing(cleanBase)
	if err != nil {
		return []domain.Issue{{Field: field, Message: "cannot resolve web_root base: " + err.Error()}}
	}
	evalRoot, err := evalAllowMissing(cleanRoot)
	if err != nil {
		return []domain.Issue{{Field: field, Message: "cannot resolve web_root: " + err.Error()}}
	}
	if !withinBase(evalRoot, evalBase) {
		return []domain.Issue{{Field: field, Message: "web_root resolves outside the allowed base directory"}}
	}
	return nil
}

func withinBase(path, base string) bool {
	if path == base {
		return true
	}
	return strings.HasPrefix(path, base+string(filepath.Separator))
}

// evalAllowMissing resolves symlinks for the longest existing prefix and
// re-appends the missing components.
func evalAllowMissing(path string) (string, error) {
	eval, err := filepath.EvalSymlinks(path)
	if err == nil {
		return eval, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	evalParent, err := evalAllowMissing(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(evalParent, filepath.Base(path)), nil
}

func validateCustomRules(rules []string) []domain.Issue {
	var issues []domain.Issue
	if len(rules) > maxRules {
		issues = append(issues, domain.Issue{Field: "custom_rules", Message: fmt.Sprintf("at most %d custom rules are allowed", maxRules)})
		return issues
	}
	for i, rule := range rules {
		field := fmt.Sprintf("custom_rules[%d]", i)
		if msg := checkCustomRule(rule); msg != "" {
			issues = append(issues, domain.Issue{Field: field, Message: msg})
		}
	}
	return issues
}

// checkCustomRule tokenizes the rule with Nginx semantics so an embedded
// ';', comment or quoted separator cannot smuggle a second directive.
func checkCustomRule(rule string) string {
	if len(rule) > maxRuleLength {
		return fmt.Sprintf("rule must be at most %d bytes", maxRuleLength)
	}
	if strings.TrimSpace(rule) != rule || rule == "" {
		return "rule must be a single directive without surrounding whitespace"
	}
	if strings.ContainsAny(rule, "\r\n") {
		return "rule must be a single line without newlines"
	}
	if !strings.HasSuffix(rule, ";") {
		return "rule must end with ';'"
	}

	tokens, err := tokenize(rule)
	if err != nil {
		return "rule is not valid nginx syntax: " + err.Error()
	}
	semicolons := 0
	for _, tok := range tokens {
		switch tok.kind {
		case tokenSemicolon:
			semicolons++
		case tokenLBrace, tokenRBrace:
			return "rule must not open or close a block"
		}
	}
	if len(tokens) == 0 {
		return "rule is empty"
	}
	if semicolons != 1 || tokens[len(tokens)-1].kind != tokenSemicolon {
		return "rule must be exactly one directive ending with ';'"
	}

	fields := make([]string, 0, len(tokens)-1)
	for _, tok := range tokens[:len(tokens)-1] {
		if tok.kind != tokenWord {
			return "rule contains an unexpected token"
		}
		fields = append(fields, tok.value)
	}
	if len(fields) == 0 {
		return "rule is empty"
	}
	name := strings.ToLower(fields[0])
	if !allowedDirectives[name] {
		return fmt.Sprintf("directive %q is not allowed", name)
	}
	if name == "return" {
		if len(fields) < 2 {
			return "return requires an explicit 3xx status code"
		}
		if !isRedirectCode(fields[1]) {
			return "return is only allowed with a 3xx status code"
		}
	}
	return ""
}

func isRedirectCode(code string) bool {
	switch code {
	case "301", "302", "303", "307", "308":
		return true
	default:
		return false
	}
}

func checkListenArgs(args []string) string {
	if len(args) == 0 {
		return "listen requires an address"
	}
	if !allowedListenAddresses[args[0]] {
		return fmt.Sprintf("listen address %q is not allowed; use 80 or 443 on 0.0.0.0/[::]", args[0])
	}
	for _, flag := range args[1:] {
		if !allowedListenFlags[flag] {
			return fmt.Sprintf("listen flag %q is not allowed", flag)
		}
	}
	return ""
}

func letsEncryptDir(policy Policy) string {
	if policy.LetsEncryptDir == "" {
		return "/etc/letsencrypt/live"
	}
	return policy.LetsEncryptDir
}

// rawDirectiveAllowed is a strict allow-list for raw_config. It is a superset
// of the custom_rules list plus the directives a server/location block needs.
func rawDirectiveAllowed(name string) bool {
	if rawAllowedStructural[name] || allowedDirectives[name] || rawAllowedSSL[name] {
		return true
	}
	if strings.HasPrefix(name, "proxy_") {
		for _, forbidden := range rawForbiddenProxyParts {
			if strings.Contains(name, forbidden) {
				return false
			}
		}
		return true
	}
	return false
}

func validateRawConfig(raw, domainName string, policy Policy) []domain.Issue {
	if len(raw) > maxRawConfigLen {
		return []domain.Issue{{Field: "raw_config", Message: fmt.Sprintf("raw_config must be at most %d bytes", maxRawConfigLen)}}
	}
	if strings.ContainsRune(raw, 0) {
		return []domain.Issue{{Field: "raw_config", Message: "raw_config must not contain NUL bytes"}}
	}
	if strings.TrimSpace(raw) == "" {
		return []domain.Issue{{Field: "raw_config", Message: "raw_config must not be empty"}}
	}

	tokens, err := tokenize(raw)
	if err != nil {
		return []domain.Issue{{Field: "raw_config", Message: err.Error()}}
	}
	directives, err := parseDirectives(tokens)
	if err != nil {
		return []domain.Issue{{Field: "raw_config", Message: err.Error()}}
	}

	var issues []domain.Issue
	topLevel := 0
	topLevelValid := true
	sawServerName := false

	for _, d := range directives {
		if d.depth == 0 {
			topLevel++
			if d.name != "server" || !d.block || len(d.args) != 0 {
				topLevelValid = false
			}
		}
		if d.name == "server" && d.depth > 0 {
			issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "nested server blocks are not allowed"})
			continue
		}
		if !rawDirectiveAllowed(d.name) {
			issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: fmt.Sprintf("directive %q is not allowed", d.name)})
			continue
		}

		switch d.name {
		case "server_name":
			sawServerName = true
			if len(d.args) != 1 || d.args[0] != domainName {
				issues = append(issues, domain.Issue{
					Field:   "raw_config",
					Line:    d.line,
					Message: fmt.Sprintf("server_name must be exactly %q", domainName),
				})
			}
		case "listen":
			if msg := checkListenArgs(d.args); msg != "" {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: msg})
			}
		case "ssl_certificate", "ssl_certificate_key":
			file := "fullchain.pem"
			if d.name == "ssl_certificate_key" {
				file = "privkey.pem"
			}
			want := filepath.Join(letsEncryptDir(policy), domainName, file)
			if len(d.args) != 1 || d.args[0] != want {
				issues = append(issues, domain.Issue{
					Field:   "raw_config",
					Line:    d.line,
					Message: fmt.Sprintf("%s must be exactly %q", d.name, want),
				})
			}
		case "proxy_pass":
			if len(d.args) != 1 || strings.ContainsRune(d.args[0], '$') {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "proxy_pass must use a single literal, validated URL"})
				continue
			}
			for _, issue := range validateProxyTarget(d.args[0], policy) {
				issue.Field = "raw_config"
				issue.Line = d.line
				issues = append(issues, issue)
			}
		case "root":
			if len(d.args) != 1 || strings.ContainsRune(d.args[0], '$') {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "root must be a single literal path"})
				continue
			}
			for _, issue := range validateWebRoot(d.args[0], policy.WebRootBase) {
				issue.Field = "raw_config"
				issue.Line = d.line
				issues = append(issues, issue)
			}
		case "try_files", "error_page":
			if len(d.args) < 2 {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: d.name + " requires at least two arguments"})
			}
			for _, arg := range d.args {
				if strings.Contains(arg, "..") {
					issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: d.name + " must not contain '..'"})
					break
				}
			}
		case "index":
			if len(d.args) < 1 {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "index requires at least one argument"})
			}
			for _, arg := range d.args {
				if strings.Contains(arg, "..") {
					issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "index must not contain '..'"})
					break
				}
			}
		case "return":
			if len(d.args) < 2 || !isRedirectCode(d.args[0]) {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "return is only allowed with an explicit 3xx status code"})
			}
		}
	}

	if topLevel < 1 || topLevel > 2 || !topLevelValid {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: "raw_config must contain one or two top-level server blocks for the domain and nothing else"})
	}
	if !sawServerName {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: fmt.Sprintf("server_name is required and must be exactly %q", domainName)})
	}
	return issues
}
