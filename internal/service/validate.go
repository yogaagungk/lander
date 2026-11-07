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
	// directiveRE finds directives inside the config; arguments stop at ; { }.
	// \s includes newlines so a directive may wrap onto the next line.
	directiveRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s+([^;{}]*)`)
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

// deniedInRaw lists directives that must never appear in a user-supplied
// server block. Lua/JS prefixes are additionally matched by name.
var deniedInRaw = map[string]bool{
	"include":                       true,
	"load_module":                   true,
	"alias":                         true,
	"ssl_certificate":               true,
	"ssl_certificate_key":           true,
	"ssl_trusted_certificate":       true,
	"ssl_client_certificate":        true,
	"ssl_crl":                       true,
	"ssl_dhparam":                   true,
	"ssl_password_file":             true,
	"ssl_session_ticket_key":        true,
	"ssl_stapling_file":             true,
	"proxy_ssl_certificate":         true,
	"proxy_ssl_certificate_key":     true,
	"proxy_ssl_trusted_certificate": true,
	"proxy_ssl_crl":                 true,
	"proxy_ssl_password_file":       true,
	"fastcgi_pass":                  true,
	"uwsgi_pass":                    true,
	"scgi_pass":                     true,
	"grpc_pass":                     true,
	"perl":                          true,
	"perl_set":                      true,
	"perl_modules":                  true,
	"js_import":                     true,
	"js_set":                        true,
	"js_content":                    true,
	"js_access":                     true,
	"js_body_filter":                true,
	"js_header_filter":              true,
	"access_log":                    true,
	"error_log":                     true,
	"auth_basic_user_file":          true,
	"env":                           true,
	"user":                          true,
	"pid":                           true,
	"daemon":                        true,
	"master_process":                true,
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
		return []domain.Issue{{Field: field, Message: "proxy_target host must be loopback, private or link-local when LANDER_ALLOW_PUBLIC_UPSTREAM is false"}}
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
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
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

func checkCustomRule(rule string) string {
	if len(rule) > maxRuleLength {
		return fmt.Sprintf("rule must be at most %d bytes", maxRuleLength)
	}
	if strings.TrimSpace(rule) != rule || rule == "" {
		return "rule must be a single directive without surrounding whitespace"
	}
	if strings.ContainsAny(rule, "\r\n{}#") {
		return "rule must not contain newlines, braces or comments"
	}
	if !strings.HasSuffix(rule, ";") {
		return "rule must end with ';'"
	}

	fields := strings.Fields(strings.TrimSuffix(rule, ";"))
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
		switch fields[1] {
		case "301", "302", "303", "307", "308":
		default:
			return "return is only allowed with a 3xx status code"
		}
	}
	return ""
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

	var issues []domain.Issue
	// The marker comment is prepended on render; bare input is expected here.
	stripped := stripComments(raw)
	trimmed := strings.TrimSpace(stripped)
	if !regexp.MustCompile(`^server\s*\{`).MatchString(trimmed) {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: "raw_config must contain a single top-level server block"})
	}
	if depth, ok := braceBalance(stripped); !ok || depth != 0 {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: "raw_config has unbalanced braces"})
	}
	if n := regexp.MustCompile(`(?m)^\s*server\s*\{`).FindAllStringIndex(stripped, -1); len(n) != 1 {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: "raw_config must contain exactly one top-level server block"})
	}

	serverNames := map[string]bool{}
	for _, d := range scanDirectives(stripped) {
		switch {
		case deniedInRaw[d.name] || strings.Contains(d.name, "lua"):
			issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: fmt.Sprintf("directive %q is not allowed", d.name)})
		case d.name == "proxy_pass":
			target := strings.TrimSpace(d.args)
			if target == "" || strings.ContainsRune(target, '$') {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "proxy_pass must use a literal, validated URL"})
				continue
			}
			for _, issue := range validateProxyTarget(target, policy) {
				issue.Field = "raw_config"
				issue.Line = d.line
				issues = append(issues, issue)
			}
		case d.name == "root":
			value := strings.TrimSpace(d.args)
			if value == "" || strings.ContainsRune(value, '$') {
				issues = append(issues, domain.Issue{Field: "raw_config", Line: d.line, Message: "root must be a literal path"})
				continue
			}
			for _, issue := range validateWebRoot(value, policy.WebRootBase) {
				issue.Field = "raw_config"
				issue.Line = d.line
				issues = append(issues, issue)
			}
		case d.name == "server_name":
			for _, name := range strings.Fields(d.args) {
				serverNames[strings.Trim(name, `"'`)] = true
			}
		}
	}
	if !serverNames[domainName] {
		issues = append(issues, domain.Issue{Field: "raw_config", Message: fmt.Sprintf("server_name must include %q", domainName)})
	}
	return issues
}

func stripComments(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// braceBalance reports the final nesting depth and whether it ever went
// negative. Quotes and escapes are skipped so literal braces do not count.
func braceBalance(text string) (int, bool) {
	depth := 0
	var quote rune
	escaped := false
	for _, r := range text {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && quote != 0:
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '{':
			depth++
		case r == '}':
			depth--
			if depth < 0 {
				return depth, false
			}
		}
	}
	return depth, true
}

type scannedDirective struct {
	name string
	args string
	line int
}

func scanDirectives(text string) []scannedDirective {
	var out []scannedDirective
	for _, match := range directiveRE.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, scannedDirective{
			name: strings.ToLower(text[match[2]:match[3]]),
			args: strings.TrimSpace(text[match[4]:match[5]]),
			line: 1 + strings.Count(text[:match[0]], "\n"),
		})
	}
	return out
}
