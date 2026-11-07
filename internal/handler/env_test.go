package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
)

func TestEnvWriteMergeAndReplace(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodPost, "/api/v1/env", domain.EnvRequest{
		App:  "my-api",
		Vars: map[string]string{"B": "2", "A": "1"},
	}, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	result := decode[domain.EnvResult](t, rec)
	if strings.Join(result.Keys, ",") != "A,B" {
		t.Errorf("keys = %v", result.Keys)
	}

	path := filepath.Join(api.cfg.EnvDir, "my-api.env")
	// #nosec G304 -- path is built by the test itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if string(data) != "A=1\nB=2\n" {
		t.Errorf("env file = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", info.Mode().Perm())
	}

	rec = api.do(http.MethodPost, "/api/v1/env", domain.EnvRequest{
		App:        "my-api",
		Vars:       map[string]string{"C": "3"},
		DeleteKeys: []string{"A"},
	}, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("merge status = %d: %s", rec.Code, rec.Body.String())
	}
	if keys := decode[domain.EnvResult](t, rec).Keys; strings.Join(keys, ",") != "B,C" {
		t.Errorf("merge keys = %v", keys)
	}

	rec = api.do(http.MethodPost, "/api/v1/env", domain.EnvRequest{
		App:  "my-api",
		Mode: "replace",
		Vars: map[string]string{"D": "4"},
	}, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace status = %d: %s", rec.Code, rec.Body.String())
	}
	if keys := decode[domain.EnvResult](t, rec).Keys; strings.Join(keys, ",") != "D" {
		t.Errorf("replace keys = %v", keys)
	}
	// #nosec G304 -- path is built by the test itself.
	data, _ = os.ReadFile(path)
	if string(data) != "D=4\n" {
		t.Errorf("replaced env file = %q", data)
	}
}

func TestEnvValuesAreNeverReturned(t *testing.T) {
	api := newTestAPI(t)
	rec := api.do(http.MethodPost, "/api/v1/env", domain.EnvRequest{
		App:  "my-api",
		Vars: map[string]string{"SECRET_TOKEN": "super-secret-value"},
	}, testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "super-secret-value") {
		t.Errorf("response leaked an env value: %s", rec.Body.String())
	}
}

func TestEnvValidationErrors(t *testing.T) {
	api := newTestAPI(t)

	cases := []domain.EnvRequest{
		{App: "Bad App", Vars: map[string]string{"A": "1"}},
		{App: "my-api", Vars: map[string]string{"bad-key": "1"}},
		{App: "my-api", Mode: "upsert", Vars: map[string]string{"A": "1"}},
		{App: "my-api", Vars: map[string]string{"A": "line1\nline2"}},
		{App: "my-api", DeleteKeys: []string{"bad key"}},
	}
	for _, req := range cases {
		rec := api.do(http.MethodPost, "/api/v1/env", req, testToken)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%+v status = %d, want 400", req, rec.Code)
		}
	}
}

func TestEnvOversizedBodyRejected(t *testing.T) {
	api := newTestAPI(t, func(cfg *config.Config) {
		cfg.MaxEnvBodyBytes = 64
	})
	rec := api.do(http.MethodPost, "/api/v1/env", domain.EnvRequest{
		App:  "my-api",
		Vars: map[string]string{"A": strings.Repeat("x", 256)},
	}, testToken)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
}

func TestEnvUnknownFieldRejected(t *testing.T) {
	api := newTestAPI(t)
	rec := api.doRaw(http.MethodPost, "/api/v1/env",
		`{"app":"my-api","vars":{"A":"1"},"bogus":true}`, testToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
