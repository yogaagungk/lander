// Package handler exposes lander's HTTP API. L1 ships the unauthenticated
// health endpoint; the authenticated site, SSL, env and stats routes land in
// L3.
package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yogaagungk/lander/internal/domain"
)

// NginxStatusFunc reports whether nginx is currently active.
type NginxStatusFunc func(context.Context) bool

// Healthz serves GET /healthz. It returns 503 when nginx is not usable so a
// load balancer can take the instance out of rotation.
func Healthz(version string, nginxActive NginxStatusFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		active := false
		if nginxActive != nil {
			active = nginxActive(r.Context())
		}

		body := domain.Health{Status: "ok", Version: version, NginxActive: active}
		code := http.StatusOK
		if !active {
			body.Status = "degraded"
			code = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
}
