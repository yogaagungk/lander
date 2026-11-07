package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogaagungk/lander/internal/domain"
)

func basePolicy(t *testing.T) Policy {
	t.Helper()
	return Policy{WebRootBase: filepath.Join(t.TempDir(), "www")}
}

func proxySite() domain.SiteConfig {
	return domain.SiteConfig{Domain: "api.example.com", ProxyTarget: "http://127.0.0.1:3000"}
}

func TestValidateSiteAcceptsValidConfigs(t *testing.T) {
	policy := basePolicy(t)
	webRoot := filepath.Join(policy.WebRootBase, "site")

	tests := map[string]domain.SiteConfig{
		"proxy":           proxySite(),
		"static":          {Domain: "static.example.com", WebRoot: webRoot},
		"static+proxy":    {Domain: "mixed.example.com", WebRoot: webRoot, ProxyTarget: "http://127.0.0.1:8081"},
		"private 10/8":    {Domain: "a.example.com", ProxyTarget: "http://10.1.2.3:8080"},
		"private 192.168": {Domain: "a.example.com", ProxyTarget: "http://192.168.1.10:8080"},
		"ipv6 loopback":   {Domain: "a.example.com", ProxyTarget: "http://[::1]:8080"},
		"localhost":       {Domain: "a.example.com", ProxyTarget: "http://localhost:8080"},
		"https no port":   {Domain: "a.example.com", ProxyTarget: "https://127.0.0.1"},
		"rules": {Domain: "a.example.com", ProxyTarget: "http://127.0.0.1:1", CustomRules: []string{
			"add_header X-Frame-Options DENY;",
			"proxy_set_header X-Real-IP $remote_addr;",
			"client_max_body_size 20m;",
			"gzip on;",
			"gzip_types text/plain application/json;",
			"limit_req zone=one burst=5;",
			"return 301 https://example.com$request_uri;",
			"expires 1d;",
			"add_header X-Quoted \"a;b\";",
		}},
		"raw": {Domain: "raw.example.com", RawConfig: "server {\n    listen 80;\n    server_name raw.example.com;\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n"},
	}

	for name, site := range tests {
		t.Run(name, func(t *testing.T) {
			if issues := ValidateSite(site, policy); len(issues) != 0 {
				t.Fatalf("unexpected issues: %+v", issues)
			}
		})
	}
}

func TestValidateSiteRejectsDomainInjection(t *testing.T) {
	policy := basePolicy(t)
	bad := []string{
		"",
		"API.example.com",
		"api_example.com",
		"*.example.com",
		"api.example.com; rm -rf /",
		"../api.example.com",
		"api.example.com/other",
		"api example.com",
		"-api.example.com",
		"api..example.com",
		strings.Repeat("a", 64) + ".example.com",
	}
	for _, domainName := range bad {
		site := domain.SiteConfig{Domain: domainName, ProxyTarget: "http://127.0.0.1:3000"}
		if issues := ValidateSite(site, policy); len(issues) == 0 {
			t.Errorf("domain %q was accepted", domainName)
		}
	}
}

func TestValidateProxyTargetPolicy(t *testing.T) {
	policy := basePolicy(t)

	rejected := []string{
		"http://127.0.0.1:3000;rm -rf /",
		"http://127.0.0.1:3000/{x}",
		"ftp://127.0.0.1:21",
		"file:///etc/passwd",
		"http://user:pass@127.0.0.1:3000",
		"http://127.0.0.1",
		"http://127.0.0.1:99999",
		"http://8.8.8.8:80",
		"http://example.com:80",
		"http://169.254.169.254:80",
		"http://127.0.0.1:3000/path/../secret",
		"http://127.0.0.1:3000/\ninclude",
		"",
	}
	for _, target := range rejected {
		site := domain.SiteConfig{Domain: "api.example.com", ProxyTarget: target}
		if issues := ValidateSite(site, policy); len(issues) == 0 {
			t.Errorf("proxy_target %q was accepted", target)
		}
	}

	allowPublic := Policy{WebRootBase: policy.WebRootBase, AllowPublicUpstream: true}
	public := domain.SiteConfig{Domain: "api.example.com", ProxyTarget: "https://example.com"}
	if issues := ValidateSite(public, allowPublic); len(issues) != 0 {
		t.Errorf("public upstream rejected with AllowPublicUpstream: %+v", issues)
	}
}

func TestValidateWebRoot(t *testing.T) {
	policy := basePolicy(t)
	if err := os.MkdirAll(policy.WebRootBase, 0o750); err != nil {
		t.Fatal(err)
	}

	valid := []string{
		filepath.Join(policy.WebRootBase, "site"),
		filepath.Join(policy.WebRootBase, "nested", "dir"),
	}
	for _, root := range valid {
		site := domain.SiteConfig{Domain: "static.example.com", WebRoot: root}
		if issues := ValidateSite(site, policy); len(issues) != 0 {
			t.Errorf("web_root %q rejected: %+v", root, issues)
		}
	}

	rejected := []string{
		"/etc",
		"/var/www",
		"relative/dir",
		policy.WebRootBase + "/../escape",
		policy.WebRootBase + "/site;include /etc/passwd",
	}
	for _, root := range rejected {
		site := domain.SiteConfig{Domain: "static.example.com", WebRoot: root}
		if issues := ValidateSite(site, policy); len(issues) == 0 {
			t.Errorf("web_root %q was accepted", root)
		}
	}

	// A symlink inside the base that points outside must be rejected.
	outside := t.TempDir()
	link := filepath.Join(policy.WebRootBase, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	site := domain.SiteConfig{Domain: "static.example.com", WebRoot: link}
	if issues := ValidateSite(site, policy); len(issues) == 0 {
		t.Error("symlink escaping the web root base was accepted")
	}
}

func TestValidateCustomRules(t *testing.T) {
	policy := basePolicy(t)
	rejected := map[string]string{ //nolint:gosec // deliberately invalid nginx fixtures
		"proxy_pass":            "proxy_pass http://8.8.8.8;",
		"root":                  "root /etc;",
		"alias":                 "alias /etc/;",
		"include":               "include /etc/nginx/conf.d/*.conf;",
		"load_module":           "load_module modules/x.so;",
		"lua":                   "content_by_lua_block { os.execute('id') }",
		"braces":                "add_header X {;",
		"newline":               "add_header X ok;\nroot /etc;",
		"missing semicolon":     "add_header X ok",
		"comment":               "add_header X ok; # comment",
		"non-3xx return":        "return 200;",
		"return without status": "return https://example.com;",
		"ssl override":          "ssl_certificate /tmp/cert.pem;",
		"embedded semicolon":    "add_header X a; include /etc/passwd;",
		"embedded directive":    "gzip on; proxy_pass http://8.8.8.8;",
	}
	for name, rule := range rejected {
		t.Run(name, func(t *testing.T) {
			site := proxySite()
			site.CustomRules = []string{rule}
			if issues := ValidateSite(site, policy); len(issues) == 0 {
				t.Errorf("rule %q was accepted", rule)
			}
		})
	}

	tooMany := proxySite()
	for i := 0; i < maxRules+1; i++ {
		tooMany.CustomRules = append(tooMany.CustomRules, "gzip on;")
	}
	if issues := ValidateSite(tooMany, policy); len(issues) == 0 {
		t.Error("more than the maximum number of rules was accepted")
	}

	tooLong := proxySite()
	tooLong.CustomRules = []string{"add_header X " + strings.Repeat("a", maxRuleLength) + ";"}
	if issues := ValidateSite(tooLong, policy); len(issues) == 0 {
		t.Error("oversized rule was accepted")
	}
}

func TestValidateSiteRequiresTarget(t *testing.T) {
	site := domain.SiteConfig{Domain: "empty.example.com"}
	if issues := ValidateSite(site, basePolicy(t)); len(issues) == 0 {
		t.Error("site without proxy_target or web_root was accepted")
	}
}

func TestValidateRawConfig(t *testing.T) {
	policy := basePolicy(t)
	valid := "server {\n    listen 80;\n    server_name raw.example.com;\n    add_header X \"a;b\";\n    location / {\n        proxy_pass http://127.0.0.1:3000;\n    }\n}\n"
	site := domain.SiteConfig{Domain: "raw.example.com", RawConfig: valid}
	if issues := ValidateSite(site, policy); len(issues) != 0 {
		t.Fatalf("valid raw config rejected: %+v", issues)
	}

	rejected := map[string]string{
		"missing server_name":  "server {\n    listen 80;\n}\n",
		"include":              "server {\n    server_name raw.example.com;\n    include /etc/passwd;\n}\n",
		"alias":                "server {\n    server_name raw.example.com;\n    location / { alias /etc/; }\n}\n",
		"lua":                  "server {\n    server_name raw.example.com;\n    access_by_lua_block { os.execute('id') }\n}\n",
		"ssl override":         "server {\n    server_name raw.example.com;\n    ssl_certificate /tmp/x.pem;\n}\n",
		"fastcgi":              "server {\n    server_name raw.example.com;\n    location / { fastcgi_pass 8.8.8.8:9000; }\n}\n",
		"public proxy":         "server {\n    server_name raw.example.com;\n    location / { proxy_pass http://8.8.8.8:80; }\n}\n",
		"variable proxy":       "server {\n    server_name raw.example.com;\n    location / { proxy_pass http://$backend; }\n}\n",
		"newline include":      "server {\n    server_name raw.example.com;\n    include\n    /etc/passwd;\n}\n",
		"newline proxy":        "server {\n    server_name raw.example.com;\n    location / {\n        proxy_pass\n        http://8.8.8.8:80;\n    }\n}\n",
		"access log":           "server {\n    server_name raw.example.com;\n    access_log /var/log/nginx/x.log;\n}\n",
		"comment bypass":       "server {\n    server_name raw.example.com;\n    add_header X a#b; include /etc/passwd;\n}\n",
		"extra server_name":    "server {\n    server_name raw.example.com victim.com;\n}\n",
		"proxy_store":          "server {\n    server_name raw.example.com;\n    proxy_store /etc/cron.d/x;\n}\n",
		"proxy_temp_path":      "server {\n    server_name raw.example.com;\n    proxy_temp_path /etc/cron.d;\n}\n",
		"dav_methods":          "server {\n    server_name raw.example.com;\n    dav_methods PUT;\n}\n",
		"create_full_put_path": "server {\n    server_name raw.example.com;\n    create_full_put_path on;\n}\n",
		"auth_request":         "server {\n    server_name raw.example.com;\n    auth_request /internal;\n}\n",
		"mirror":               "server {\n    server_name raw.example.com;\n    mirror /copy;\n}\n",
		"ssi":                  "server {\n    server_name raw.example.com;\n    ssi on;\n}\n",
		"js prefix":            "server {\n    server_name raw.example.com;\n    js_preload_object foo from foo.js;\n}\n",
		"perl prefix":          "server {\n    server_name raw.example.com;\n    perl_set $x 'sub { 1 }';\n}\n",
		"root escape":          "server {\n    server_name raw.example.com;\n    root /etc;\n}\n",
		"unbalanced":           "server {\n    server_name raw.example.com;\n",
		"two servers":          valid + "server {\n    server_name other.example.com;\n}\n",
		"not a server":         "http {\n}\n",
		"empty":                "",
	}
	for name, raw := range rejected {
		t.Run(name, func(t *testing.T) {
			site := domain.SiteConfig{Domain: "raw.example.com", RawConfig: raw}
			if issues := ValidateSite(site, policy); len(issues) == 0 {
				t.Errorf("raw config was accepted: %q", raw)
			}
		})
	}
}

func TestValidateRawAndStructuredAreExclusive(t *testing.T) {
	site := proxySite()
	site.RawConfig = "server {\n    server_name api.example.com;\n}\n"
	if issues := ValidateSite(site, basePolicy(t)); len(issues) == 0 {
		t.Error("raw_config combined with structured fields was accepted")
	}
}
