package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/yogaagungk/lander/internal/domain"
)

const certbotTimeout = 120 * time.Second

// IssueSSL requests a certificate through the configured certbot wrapper.
// The wrapper accepts exactly <domain> <email>, owns the certbot flags, and is
// the only path named in sudoers, so lander never passes arbitrary options.
func (s *Nginx) IssueSSL(ctx context.Context, req domain.SSLRequest) (domain.SSLResult, error) {
	result := domain.SSLResult{Domain: req.Domain}

	if issues := validateDomain(req.Domain); len(issues) > 0 {
		return result, &ValidationError{Issues: issues}
	}
	if msg := validateEmail(req.Email); msg != "" {
		return result, &ValidationError{Issues: []domain.Issue{{Field: "email", Message: msg}}}
	}

	unlock := s.lockDomain(req.Domain)
	defer unlock()

	// Re-check under the domain lock so a concurrent DELETE cannot slip in
	// between the existence check and certbot.
	if _, exists, err := readFileIfExists(s.sitePath(req.Domain)); err != nil {
		return result, fmt.Errorf("read site config: %w", err)
	} else if !exists {
		return result, ErrNotFound
	}

	// certbot talks to nginx and may reload it; keep applies out of the way.
	s.cmdMu.Lock()
	defer s.cmdMu.Unlock()

	args := []string{req.Domain, req.Email}
	out, err := s.runPrivileged(ctx, s.cfg.CertbotBin, certbotTimeout, args...)
	if err != nil {
		if errors.Is(err, ErrTimeout) {
			return result, ErrTimeout
		}
		return result, &CommandError{Op: "certbot", Output: truncateOutput(out), Err: err}
	}

	result.Issued = true
	result.ExpiresAt = s.certExpiry(req.Domain)
	return result, nil
}

func validateEmail(email string) string {
	if email == "" {
		return "email is required"
	}
	if len(email) > 254 {
		return "email must be at most 254 characters"
	}
	if strings.TrimSpace(email) != email {
		return "email must not contain surrounding whitespace"
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "email is not a valid address"
	}
	return ""
}
