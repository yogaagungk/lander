package handler

import (
	"net/http"

	"github.com/yogaagungk/lander/internal/domain"
)

type sitesResponse struct {
	Sites []domain.SiteSummary `json:"sites"`
}

func (s *Server) systemStats(w http.ResponseWriter, r *http.Request) {
	status, err := s.nginx.SystemStatus(r.Context())
	if err != nil {
		s.respondServiceError(w, r, err, 0)
		return
	}
	s.writeJSON(w, http.StatusOK, status)
}

func (s *Server) listSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.nginx.ListSites(r.Context())
	if err != nil {
		s.respondServiceError(w, r, err, 0)
		return
	}
	if sites == nil {
		sites = []domain.SiteSummary{}
	}
	s.writeJSON(w, http.StatusOK, sitesResponse{Sites: sites})
}

func (s *Server) getSite(w http.ResponseWriter, r *http.Request) {
	domainName := r.URL.Query().Get("domain")
	if domainName == "" {
		s.writeError(w, r, http.StatusBadRequest, "bad_request", "domain query parameter is required")
		return
	}
	detail, err := s.nginx.GetSite(r.Context(), domainName)
	if err != nil {
		s.respondServiceError(w, r, err, http.StatusBadRequest)
		return
	}
	s.writeJSON(w, http.StatusOK, detail)
}

func (s *Server) upsertSite(w http.ResponseWriter, r *http.Request) {
	var site domain.SiteConfig
	if !s.decode(w, r, &site, s.cfg.MaxBodyBytes) {
		return
	}

	result, err := s.nginx.ApplyWithETag(r.Context(), site, r.Header.Get("If-Match"))
	s.audit.record("site.apply", site.Domain, auditOutcome(err), requestIDFrom(r.Context()))
	if err != nil {
		s.respondServiceError(w, r, err, http.StatusUnprocessableEntity)
		return
	}

	if result.ETag != "" {
		w.Header().Set("ETag", `"`+result.ETag+`"`)
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	s.writeJSON(w, status, result)
}

func (s *Server) deleteSite(w http.ResponseWriter, r *http.Request) {
	domainName := r.URL.Query().Get("domain")
	if domainName == "" {
		s.writeError(w, r, http.StatusBadRequest, "bad_request", "domain query parameter is required")
		return
	}

	err := s.nginx.Delete(r.Context(), domainName)
	s.audit.record("site.delete", domainName, auditOutcome(err), requestIDFrom(r.Context()))
	if err != nil {
		s.respondServiceError(w, r, err, http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validateSite(w http.ResponseWriter, r *http.Request) {
	var site domain.SiteConfig
	if !s.decode(w, r, &site, s.cfg.MaxBodyBytes) {
		return
	}
	result, err := s.nginx.Validate(r.Context(), site)
	if err != nil {
		s.respondServiceError(w, r, err, 0)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) issueSSL(w http.ResponseWriter, r *http.Request) {
	var req domain.SSLRequest
	if !s.decode(w, r, &req, s.cfg.MaxBodyBytes) {
		return
	}
	result, err := s.nginx.IssueSSL(r.Context(), req)
	s.audit.record("site.ssl", req.Domain, auditOutcome(err), requestIDFrom(r.Context()))
	if err != nil {
		s.respondServiceError(w, r, err, http.StatusBadRequest)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) putEnv(w http.ResponseWriter, r *http.Request) {
	var req domain.EnvRequest
	if !s.decode(w, r, &req, s.cfg.MaxEnvBodyBytes) {
		return
	}
	result, err := s.env.Write(r.Context(), req)
	s.audit.record("env.write", req.App, auditOutcome(err), requestIDFrom(r.Context()))
	if err != nil {
		s.respondServiceError(w, r, err, http.StatusBadRequest)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
