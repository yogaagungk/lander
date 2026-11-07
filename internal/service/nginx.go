// Package service implements lander's Nginx management: config rendering,
// validation, atomic apply with rollback, and safe command execution.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
)

// Command timeouts from ADR-002.
const (
	nginxTestTimeout = 10 * time.Second
	reloadTimeout    = 15 * time.Second
	systemctlTimeout = 5 * time.Second
	maxCommandOutput = 4096
	fileMode         = 0o644
)

// Sentinel errors mapped to HTTP responses by the handler layer.
var (
	ErrNotFound  = errors.New("site not found")
	ErrUnmanaged = errors.New("site config is not managed by lander")
)

// ValidationError reports rejected input.
type ValidationError struct {
	Issues []domain.Issue
}

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "validation failed"
	}
	return "validation failed: " + e.Issues[0].Message
}

// CommandError reports a failed privileged command. Output is truncated and
// never contains tokens or env values.
type CommandError struct {
	Op     string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	msg := e.Op + " failed"
	if e.Output != "" {
		msg += ": " + e.Output
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *CommandError) Unwrap() error { return e.Err }

// CommandRunner abstracts process execution so tests can simulate nginx.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with an argument slice; no shell is involved.
type ExecRunner struct{}

// Run implements CommandRunner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	// #nosec G204 -- the binary is from trusted config and args are never
	// concatenated into a shell string.
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// Nginx manages lander-owned site files under sites-available/sites-enabled.
type Nginx struct {
	cfg    config.Config
	runner CommandRunner

	// cmdMu serialises nginx -t and reload across all domains.
	cmdMu sync.Mutex

	locksMu     sync.Mutex
	domainLocks map[string]*sync.Mutex
}

// NewNginx builds the service. A nil runner falls back to ExecRunner.
func NewNginx(cfg config.Config, runner CommandRunner) *Nginx {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Nginx{
		cfg:         cfg,
		runner:      runner,
		domainLocks: make(map[string]*sync.Mutex),
	}
}

// Policy returns the validation policy implied by the configuration.
func (s *Nginx) Policy() Policy {
	return Policy{
		AllowPublicUpstream: s.cfg.AllowPublicUpstream,
		WebRootBase:         s.cfg.WebRootBase,
	}
}

// CertExists reports whether a Let's Encrypt certificate directory with a
// fullchain exists for domain.
func (s *Nginx) CertExists(domainName string) bool {
	if s.cfg.LetsEncryptDir == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(s.cfg.LetsEncryptDir, domainName, "fullchain.pem"))
	return err == nil && !info.IsDir()
}

// NginxActive reports whether the nginx systemd unit is active.
func (s *Nginx) NginxActive(ctx context.Context) bool {
	_, err := s.runCommand(ctx, s.cfg.SystemctlBin, systemctlTimeout, "is-active", "--quiet", "nginx")
	return err == nil
}

// Apply renders and atomically installs a site configuration. The previous
// file is restored and the symlink reverted if nginx -t or the reload fails.
func (s *Nginx) Apply(ctx context.Context, sc domain.SiteConfig) (domain.ApplyResult, error) {
	result := domain.ApplyResult{Domain: sc.Domain}

	if issues := ValidateSite(sc, s.Policy()); len(issues) > 0 {
		return result, &ValidationError{Issues: issues}
	}

	unlock := s.lockDomain(sc.Domain)
	defer unlock()

	// Hold the global command lock from before the file swap until the reload
	// completes, so a concurrent apply cannot make nginx -t read a
	// half-applied configuration tree.
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	content, warnings, err := Render(sc, RenderOptions{
		CertExists: s.CertExists(sc.Domain),
		CertDir:    s.cfg.LetsEncryptDir,
	})
	if err != nil {
		return result, err
	}
	result.ETag = ETag(content)
	result.Warnings = warnings

	final := s.sitePath(sc.Domain)
	link := s.linkPath(sc.Domain)
	// TODO(L3): recover an orphan .bak left by a crash when final is absent.
	backup := final + ".bak"

	existing, exists, err := readFileIfExists(final)
	if err != nil {
		return result, fmt.Errorf("read existing site config: %w", err)
	}
	if exists && !isManagedConfig(existing) {
		return result, ErrUnmanaged
	}
	linkState, err := inspectLink(link)
	if err != nil {
		return result, err
	}
	if linkState.exists && !linkState.isSymlink {
		return result, ErrUnmanaged
	}

	// Re-posting an identical configuration is a no-op unless the symlink
	// itself is missing or stale.
	if exists && bytes.Equal(existing, []byte(content)) {
		linkChanged, err := s.ensureLink(link, final)
		if err != nil {
			return result, err
		}
		if !linkChanged {
			return result, nil
		}
		if err := s.testAndReloadLocked(ctx); err != nil {
			_ = os.Remove(link)
			if linkState.exists {
				_ = os.Symlink(linkState.target, link)
			}
			return result, err
		}
		result.Changed = true
		result.Reloaded = true
		return result, nil
	}

	stored, err := writeTempFile(s.cfg.SitesAvailable, content)
	if err != nil {
		return result, err
	}
	defer func() { _ = os.Remove(stored) }() // no-op after a successful rename

	restore := func() {
		_ = os.Remove(final)
		if exists {
			if err := os.Rename(backup, final); err != nil {
				_ = os.WriteFile(final, existing, fileMode)
			}
		}
		_ = os.Remove(link)
		if linkState.exists {
			_ = os.Symlink(linkState.target, link)
		}
	}

	if exists {
		_ = os.Remove(backup)
		if err := os.Rename(final, backup); err != nil {
			return result, fmt.Errorf("back up existing site config: %w", err)
		}
	}
	if err := os.Rename(stored, final); err != nil {
		restore()
		return result, fmt.Errorf("install site config: %w", err)
	}
	if err := os.Chmod(final, fileMode); err != nil {
		restore()
		return result, fmt.Errorf("set site config mode: %w", err)
	}
	if _, err := s.ensureLink(link, final); err != nil {
		restore()
		return result, err
	}

	if err := s.testAndReloadLocked(ctx); err != nil {
		restore()
		return result, err
	}
	if exists {
		_ = os.Remove(backup)
	}

	result.Changed = true
	result.Reloaded = true
	return result, nil
}

// Validate is a dry run: it renders the candidate into a temporary include
// root, runs nginx -t against it and removes it. It never writes to the real
// sites directories and never reloads.
//
// The wrapper contains only the candidate block, so cross-file references
// (for example a limit_req zone declared in another file) are not visible
// here; a successful Validate is advisory and the real Apply remains the
// authority.
func (s *Nginx) Validate(ctx context.Context, sc domain.SiteConfig) (domain.ValidateResult, error) {
	result := domain.ValidateResult{}

	if issues := ValidateSite(sc, s.Policy()); len(issues) > 0 {
		result.Issues = issues
		return result, nil
	}

	content, _, err := Render(sc, RenderOptions{
		CertExists: s.CertExists(sc.Domain),
		CertDir:    s.cfg.LetsEncryptDir,
	})
	if err != nil {
		result.Issues = []domain.Issue{{Message: err.Error()}}
		return result, nil
	}
	result.RenderedConfig = content

	dir, err := os.MkdirTemp("", "lander-validate-*")
	if err != nil {
		return result, fmt.Errorf("create validation dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	candidate := filepath.Join(dir, "candidate.conf")
	if err := os.WriteFile(candidate, []byte(content), fileMode); err != nil {
		return result, fmt.Errorf("write candidate config: %w", err)
	}
	wrapper := filepath.Join(dir, "nginx.conf")
	wrapperConfig := fmt.Sprintf(
		"worker_processes 1;\nerror_log stderr;\npid \"%s\";\nevents { worker_connections 64; }\nhttp {\n    access_log off;\n    include \"%s\";\n}\n",
		filepath.Join(dir, "nginx.pid"), candidate,
	)
	if err := os.WriteFile(wrapper, []byte(wrapperConfig), fileMode); err != nil {
		return result, fmt.Errorf("write validation wrapper: %w", err)
	}

	s.cmdMu.Lock()
	out, testErr := s.runPrivileged(ctx, s.cfg.NginxBin, nginxTestTimeout, "-t", "-c", wrapper)
	s.cmdMu.Unlock()

	result.NginxOutput = truncateOutput(out)
	result.Valid = testErr == nil
	if !result.Valid && result.NginxOutput == "" && testErr != nil {
		result.NginxOutput = testErr.Error()
	}
	return result, nil
}

// Delete removes the site symlink and config, then reloads. A failed reload
// restores the previous state.
func (s *Nginx) Delete(ctx context.Context, domainName string) error {
	if issues := validateDomain(domainName); len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}

	unlock := s.lockDomain(domainName)
	defer unlock()

	// Keep the global lock across removal, nginx -t and reload (same reason
	// as Apply).
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	final := s.sitePath(domainName)
	link := s.linkPath(domainName)
	backup := final + ".bak"

	existing, exists, err := readFileIfExists(final)
	if err != nil {
		return fmt.Errorf("read site config: %w", err)
	}
	if exists && !isManagedConfig(existing) {
		return ErrUnmanaged
	}
	linkState, err := inspectLink(link)
	if err != nil {
		return err
	}
	if linkState.exists && !linkState.isSymlink {
		return ErrUnmanaged
	}
	if !exists && !linkState.exists {
		return ErrNotFound
	}

	restore := func() {
		if exists {
			_ = os.Rename(backup, final)
		}
		if linkState.exists {
			_ = os.Symlink(linkState.target, link)
		}
	}

	if linkState.exists {
		if err := os.Remove(link); err != nil {
			return fmt.Errorf("remove site symlink: %w", err)
		}
	}
	if exists {
		if err := os.Rename(final, backup); err != nil {
			restore()
			return fmt.Errorf("back up site config: %w", err)
		}
	}

	if err := s.testAndReloadLocked(ctx); err != nil {
		restore()
		return err
	}
	if exists {
		_ = os.Remove(backup)
	}
	return nil
}

func (s *Nginx) sitePath(domainName string) string {
	return filepath.Join(s.cfg.SitesAvailable, domainName+".conf")
}

func (s *Nginx) linkPath(domainName string) string {
	return filepath.Join(s.cfg.SitesEnabled, domainName+".conf")
}

// testAndReloadLocked validates the full Nginx configuration and reloads it.
// The caller must hold cmdMu for the whole install+test+reload window.
func (s *Nginx) testAndReloadLocked(ctx context.Context) error {
	out, err := s.runPrivileged(ctx, s.cfg.NginxBin, nginxTestTimeout, "-t", "-c", s.cfg.NginxConfPath)
	if err != nil {
		return &CommandError{Op: "nginx -t", Output: truncateOutput(out), Err: err}
	}
	out, err = s.runPrivileged(ctx, s.cfg.SystemctlBin, reloadTimeout, "reload", "nginx")
	if err != nil {
		return &CommandError{Op: "systemctl reload nginx", Output: truncateOutput(out), Err: err}
	}
	return nil
}

// runPrivileged prefixes "sudo -n" when LANDER_SUDO is enabled. The sudoers
// drop-in must allow only the exact command forms lander uses.
func (s *Nginx) runPrivileged(ctx context.Context, name string, timeout time.Duration, args ...string) ([]byte, error) {
	if s.cfg.UseSudo {
		args = append([]string{"-n", name}, args...)
		name = "sudo"
	}
	return s.runCommand(ctx, name, timeout, args...)
}

func (s *Nginx) runCommand(ctx context.Context, name string, timeout time.Duration, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.runner.Run(cmdCtx, name, args...)
}

func (s *Nginx) lockDomain(domainName string) func() {
	s.locksMu.Lock()
	mu, ok := s.domainLocks[domainName]
	if !ok {
		mu = &sync.Mutex{}
		s.domainLocks[domainName] = mu
	}
	s.locksMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

type linkInfo struct {
	exists    bool
	isSymlink bool
	target    string
}

func inspectLink(path string) (linkInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return linkInfo{}, nil
	}
	if err != nil {
		return linkInfo{}, fmt.Errorf("inspect symlink: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return linkInfo{exists: true}, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return linkInfo{}, fmt.Errorf("read symlink: %w", err)
	}
	return linkInfo{exists: true, isSymlink: true, target: target}, nil
}

// ensureLink makes link point at final and reports whether it changed.
func (s *Nginx) ensureLink(link, final string) (bool, error) {
	want, err := filepath.Rel(s.cfg.SitesEnabled, final)
	if err != nil {
		return false, fmt.Errorf("compute symlink target: %w", err)
	}
	state, err := inspectLink(link)
	if err != nil {
		return false, err
	}
	if state.exists && !state.isSymlink {
		return false, ErrUnmanaged
	}
	if state.exists && state.target == want {
		return false, nil
	}
	if state.exists {
		if err := os.Remove(link); err != nil {
			return false, fmt.Errorf("replace site symlink: %w", err)
		}
	}
	if err := os.Symlink(want, link); err != nil {
		return false, fmt.Errorf("create site symlink: %w", err)
	}
	return true, nil
}

func writeTempFile(dir, content string) (string, error) {
	f, err := os.CreateTemp(dir, ".lander-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp site config: %w", err)
	}
	name := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(name)
	}
	if err := f.Chmod(fileMode); err != nil {
		cleanup()
		return "", fmt.Errorf("set temp site config mode: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		cleanup()
		return "", fmt.Errorf("write temp site config: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync temp site config: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("close temp site config: %w", err)
	}
	return name, nil
}

func readFileIfExists(path string) ([]byte, bool, error) {
	// #nosec G304 -- path is built from a validated domain and configured root.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func isManagedConfig(content []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(content, " \t\r\n"), []byte(managedMarker))
}

func truncateOutput(out []byte) string {
	text := strings.TrimSpace(string(out))
	if len(out) <= maxCommandOutput {
		return text
	}
	return strings.TrimSpace(string(out[:maxCommandOutput])) + "\n... (truncated)"
}
