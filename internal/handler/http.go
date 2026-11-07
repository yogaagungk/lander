// Package handler exposes lander's HTTP API and authentication middleware.
package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yogaagungk/lander/internal/config"
	"github.com/yogaagungk/lander/internal/domain"
	"github.com/yogaagungk/lander/internal/service"
)

type contextKey uint8

const requestIDKey contextKey = iota

// Server wires the HTTP API to the service layer.
type Server struct {
	cfg       config.Config
	nginx     *service.Nginx
	env       *service.EnvStore
	version   string
	logger    *slog.Logger
	limiter   *failureLimiter
	tokenHash [32]byte
	authDelay time.Duration
	audit     *auditor
}

// New builds the API server. logger may be nil.
func New(cfg config.Config, nginx *service.Nginx, env *service.EnvStore, version string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:       cfg,
		nginx:     nginx,
		env:       env,
		version:   version,
		logger:    logger,
		limiter:   newFailureLimiter(cfg.AuthFailLimit, cfg.AuthFailWindow),
		tokenHash: sha256Sum(cfg.SecretToken),
		authDelay: 200 * time.Millisecond,
		audit:     newAuditor(cfg.AuditLogPath, logger),
	}
}

// Handler returns the fully wired HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", http.HandlerFunc(s.healthz))
	mux.Handle("GET /api/v1/system/stats", s.api(http.HandlerFunc(s.systemStats)))
	mux.Handle("GET /api/v1/nginx/sites", s.api(http.HandlerFunc(s.listSites)))
	mux.Handle("GET /api/v1/nginx/site", s.api(http.HandlerFunc(s.getSite)))
	mux.Handle("POST /api/v1/nginx/site", s.api(http.HandlerFunc(s.upsertSite)))
	mux.Handle("DELETE /api/v1/nginx/site", s.api(http.HandlerFunc(s.deleteSite)))
	mux.Handle("POST /api/v1/nginx/validate", s.api(http.HandlerFunc(s.validateSite)))
	mux.Handle("POST /api/v1/nginx/ssl", s.api(http.HandlerFunc(s.issueSSL)))
	mux.Handle("POST /api/v1/env", s.api(http.HandlerFunc(s.putEnv)))
	return s.withRequestID(s.withLogging(mux))
}

func (s *Server) api(next http.Handler) http.Handler {
	return s.authenticate(next)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	Healthz(s.version, s.nginx.NginxActive).ServeHTTP(w, r)
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", requestIDFrom(r.Context()),
			"remote", s.clientIP(r),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	return r.ResponseWriter.Write(data)
}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func newRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(buf[:])
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	s.writeJSON(w, status, domain.ErrorResponse{Error: domain.ErrorBody{
		Code:      code,
		Message:   message,
		RequestID: requestIDFrom(r.Context()),
	}})
}

func (s *Server) writeValidationError(w http.ResponseWriter, r *http.Request, status int, code, message string, issues []domain.Issue) {
	s.writeJSON(w, status, domain.ValidationErrorResponse{
		Error: domain.ErrorBody{
			Code:      code,
			Message:   message,
			RequestID: requestIDFrom(r.Context()),
		},
		Issues: issues,
	})
}

// respondServiceError maps service errors to the API error envelope.
// validationStatus is the status used for *service.ValidationError.
func (s *Server) respondServiceError(w http.ResponseWriter, r *http.Request, err error, validationStatus int) {
	var validationErr *service.ValidationError
	var commandErr *service.CommandError

	switch {
	case errors.Is(err, service.ErrNotFound):
		s.writeError(w, r, http.StatusNotFound, "not_found", "site not found")
	case errors.Is(err, service.ErrUnmanaged):
		s.writeError(w, r, http.StatusConflict, "conflict", "site config is not managed by lander")
	case errors.Is(err, service.ErrConflict):
		s.writeError(w, r, http.StatusConflict, "conflict", "site changed since the supplied etag; retry")
	case errors.Is(err, service.ErrTimeout):
		s.writeError(w, r, http.StatusGatewayTimeout, "timeout", "command timed out")
	case errors.As(err, &validationErr):
		if validationStatus == 0 {
			validationStatus = http.StatusUnprocessableEntity
		}
		s.writeValidationError(w, r, validationStatus, "validation_failed", validationErr.Error(), validationErr.Issues)
	case errors.As(err, &commandErr):
		code := "nginx_test_failed"
		if commandErr.Op == "certbot" {
			code = "certbot_failed"
		}
		var issues []domain.Issue
		if commandErr.Output != "" {
			issues = []domain.Issue{{Message: commandErr.Output}}
		}
		s.writeValidationError(w, r, http.StatusUnprocessableEntity, code, commandErr.Error(), issues)
	default:
		s.logger.Error("request failed", "error", err, "path", r.URL.Path, "request_id", requestIDFrom(r.Context()))
		s.writeError(w, r, http.StatusInternalServerError, "internal", "internal error")
	}
}

// decodeJSON enforces a size limit, unknown-field rejection and exactly one
// JSON value.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	if err := decodeJSON(w, r, dst, limit); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
			return false
		}
		s.writeError(w, r, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}

func auditOutcome(err error) string {
	if err != nil {
		return "error"
	}
	return "ok"
}

// auditor appends JSON lines to the audit log. Failures are non-fatal.
type auditor struct {
	path   string
	logger *slog.Logger
	mu     sync.Mutex
}

func newAuditor(path string, logger *slog.Logger) *auditor {
	return &auditor{path: path, logger: logger}
}

func (a *auditor) record(action, target, outcome, requestID string) {
	if a.path == "" {
		return
	}
	line, err := json.Marshal(map[string]string{
		"time":       time.Now().UTC().Format(time.RFC3339Nano),
		"action":     action,
		"target":     target,
		"outcome":    outcome,
		"request_id": requestID,
	})
	if err != nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// #nosec G304 -- audit path comes from trusted configuration.
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		a.logger.Warn("audit log unavailable", "error", err)
		return
	}
	defer func() { _ = file.Close() }()
	_, _ = file.Write(append(line, '\n'))
}

// clientIP resolves the caller for logging and the auth rate limit. When
// LANDER_TRUSTED_PROXY is enabled and the request comes from loopback (the
// nginx vhost), the last X-Forwarded-For hop or X-Real-IP is used. Otherwise
// headers are ignored so a direct client cannot spoof its address.
func (s *Server) clientIP(r *http.Request) string {
	remote := remoteHost(r.RemoteAddr)
	if !s.cfg.TrustedProxy || net.ParseIP(remote) == nil || !net.ParseIP(remote).IsLoopback() {
		return remote
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if net.ParseIP(last) != nil {
			return last
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(realIP) != nil {
		return realIP
	}
	return remote
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}
