package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func sha256Sum(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// authenticate enforces the bearer token with a constant-time digest compare
// and a per-IP failed-attempt rate limit. The token is checked first so a
// valid caller is never locked out by another client behind the same proxy IP.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)

		token, hasToken := bearerToken(r)
		if hasToken && constantTimeEqual(token, s.tokenHash) {
			next.ServeHTTP(w, r)
			return
		}

		if !s.limiter.allowed(ip) {
			retry := s.limiter.retryAfter(ip)
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds()+0.5)))
			s.writeError(w, r, http.StatusTooManyRequests, "rate_limited", "too many failed authentication attempts")
			return
		}

		s.limiter.fail(ip)
		if s.authDelay > 0 {
			time.Sleep(s.authDelay)
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.writeError(w, r, http.StatusUnauthorized, "unauthorized", "unauthorized")
	})
}

func bearerToken(r *http.Request) (string, bool) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", false
	}
	return fields[1], true
}

func constantTimeEqual(token string, want [32]byte) bool {
	got := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

type failureEntry struct {
	count int
	reset time.Time
}

// failureLimiter counts failed auth attempts per IP in a fixed window.
type failureLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*failureEntry
	now     func() time.Time
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &failureLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*failureEntry),
		now:     time.Now,
	}
}

func (l *failureLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok {
		return true
	}
	if l.now().After(entry.reset) {
		delete(l.entries, ip)
		return true
	}
	return entry.count < l.limit
}

func (l *failureLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, ok := l.entries[ip]
	if !ok || now.After(entry.reset) {
		if len(l.entries) > 4096 {
			l.pruneLocked(now)
		}
		l.entries[ip] = &failureEntry{count: 1, reset: now.Add(l.window)}
		return
	}
	entry.count++
}

func (l *failureLimiter) retryAfter(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[ip]
	if !ok || l.now().After(entry.reset) {
		return l.window
	}
	return entry.reset.Sub(l.now())
}

func (l *failureLimiter) pruneLocked(now time.Time) {
	for ip, entry := range l.entries {
		if now.After(entry.reset) {
			delete(l.entries, ip)
		}
	}
}
