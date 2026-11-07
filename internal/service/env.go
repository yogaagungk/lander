package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yogaagungk/lander/internal/domain"
)

const (
	maxEnvVars  = 256
	maxEnvValue = 8192
	maxEnvFile  = 256 << 10
	envFileMode = 0o640
	envDirMode  = 0o750
	deployGroup = "deploy"
)

var (
	appNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	envKeyRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// EnvStore manages write-only app env files under one directory.
type EnvStore struct {
	dir string
}

// NewEnvStore builds an env store rooted at dir.
func NewEnvStore(dir string) *EnvStore {
	return &EnvStore{dir: dir}
}

// ValidateEnvRequest checks the request shape. Values are never logged.
func ValidateEnvRequest(req domain.EnvRequest) []domain.Issue {
	var issues []domain.Issue
	if !appNameRE.MatchString(req.App) {
		issues = append(issues, domain.Issue{Field: "app", Message: "app must match ^[a-z0-9][a-z0-9-]{0,62}$"})
	}
	switch req.Mode {
	case "", "merge", "replace":
	default:
		issues = append(issues, domain.Issue{Field: "mode", Message: "mode must be merge or replace"})
	}
	if len(req.Vars) > maxEnvVars {
		issues = append(issues, domain.Issue{Field: "vars", Message: fmt.Sprintf("at most %d vars are allowed", maxEnvVars)})
	}
	total := 0
	for key, value := range req.Vars {
		if !envKeyRE.MatchString(key) {
			issues = append(issues, domain.Issue{Field: "vars", Message: fmt.Sprintf("invalid key %q", key)})
			continue
		}
		if len(value) > maxEnvValue {
			issues = append(issues, domain.Issue{Field: "vars." + key, Message: fmt.Sprintf("value must be at most %d bytes", maxEnvValue)})
			continue
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			issues = append(issues, domain.Issue{Field: "vars." + key, Message: "value must not contain newlines or NUL bytes"})
			continue
		}
		total += len(key) + len(value) + 2
	}
	for _, key := range req.DeleteKeys {
		if !envKeyRE.MatchString(key) {
			issues = append(issues, domain.Issue{Field: "delete_keys", Message: fmt.Sprintf("invalid key %q", key)})
		}
	}
	if total > maxEnvFile {
		issues = append(issues, domain.Issue{Field: "vars", Message: "environment payload is too large"})
	}
	return issues
}

// Write merges or replaces an app's env file and returns sorted key names.
func (e *EnvStore) Write(_ context.Context, req domain.EnvRequest) (domain.EnvResult, error) {
	result := domain.EnvResult{App: req.App}
	if issues := ValidateEnvRequest(req); len(issues) > 0 {
		return result, &ValidationError{Issues: issues}
	}

	if err := os.MkdirAll(e.dir, envDirMode); err != nil {
		return result, fmt.Errorf("create env dir: %w", err)
	}

	path := filepath.Join(e.dir, req.App+".env")
	vars := map[string]string{}
	if req.Mode != "replace" {
		existing, err := os.ReadFile(path) // #nosec G304 -- app is validated and dir is configured.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("read env file: %w", err)
		}
		vars = parseEnvFile(existing)
	}
	for _, key := range req.DeleteKeys {
		delete(vars, key)
	}
	for key, value := range req.Vars {
		vars[key] = value
	}

	keys := make([]string, 0, len(vars))
	var buf strings.Builder
	for _, key := range sortedKeys(vars) {
		keys = append(keys, key)
		buf.WriteString(key)
		buf.WriteByte('=')
		buf.WriteString(vars[key])
		buf.WriteByte('\n')
	}
	if buf.Len() > maxEnvFile {
		return result, &ValidationError{Issues: []domain.Issue{{Field: "vars", Message: "resulting env file is too large"}}}
	}

	if err := writeEnvFile(path, buf.String()); err != nil {
		return result, err
	}
	result.Keys = keys
	return result, nil
}

func parseEnvFile(data []byte) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !envKeyRE.MatchString(key) {
			continue
		}
		vars[key] = value
	}
	return vars
}

func sortedKeys(vars map[string]string) []string {
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func writeEnvFile(path, content string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".env-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp env file: %w", err)
	}
	name := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(name)
	}
	if err := f.Chmod(envFileMode); err != nil {
		cleanup()
		return fmt.Errorf("set env file mode: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		cleanup()
		return fmt.Errorf("write env file: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync env file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close env file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("install env file: %w", err)
	}
	chownDeploy(path)
	return nil
}

// chownDeploy is best effort: it needs group membership or root.
func chownDeploy(path string) {
	group, err := user.LookupGroup(deployGroup)
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, -1, gid)
}
