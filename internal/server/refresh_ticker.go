package server

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/mcpshim/mcpshim/internal/mcp"
)

const (
	defaultTokenRefreshInterval = 5 * time.Minute
	defaultTokenRefreshBuffer   = 30 * time.Minute
	tokenRefreshCallTimeout     = 30 * time.Second
)

// runTokenRefreshTicker periodically scans configured servers and pre-emptively
// refreshes any OAuth tokens whose access_token is missing, expired, or within
// the configured buffer of expiry. Errors are logged but never fatal — one
// flaky upstream must not stop the ticker.
func (s *Server) runTokenRefreshTicker(ctx context.Context) {
	interval := time.Duration(s.cfg.Server.TokenRefreshIntervalSec) * time.Second
	if interval <= 0 {
		interval = defaultTokenRefreshInterval
	}
	buffer := time.Duration(s.cfg.Server.TokenRefreshBufferSec) * time.Second
	if buffer <= 0 {
		buffer = defaultTokenRefreshBuffer
	}

	if s.debug {
		log.Printf("token-refresh ticker: interval=%s buffer=%s", interval, buffer)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once at startup so a freshly-launched daemon doesn't wait an entire
	// interval before its first refresh sweep.
	s.refreshAllTokens(ctx, buffer)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshAllTokens(ctx, buffer)
		}
	}
}

func (s *Server) refreshAllTokens(ctx context.Context, buffer time.Duration) {
	if s.store == nil {
		return
	}
	// Snapshot servers under no lock — Server.cfg is reassigned wholesale on
	// reload and we don't mutate the slice header here.
	servers := s.cfg.Servers
	for _, srv := range servers {
		if ctx.Err() != nil {
			return
		}
		callCtx, cancel := context.WithTimeout(ctx, tokenRefreshCallTimeout)
		refreshed, err := mcp.RefreshTokenIfStale(callCtx, srv, s.store, buffer)
		cancel()

		switch {
		case errors.Is(err, mcp.ErrNoToken), errors.Is(err, mcp.ErrNoRefreshToken):
			// Quiet skip — server isn't OAuth-managed by mcpshim, or stored
			// token can't be refreshed without user interaction.
			if s.debug {
				log.Printf("token-refresh %s: skipped (%v)", srv.Name, err)
			}
		case errors.Is(err, mcp.ErrRefreshNotImplemented):
			// Stale token detected but the non-interactive refresh
			// primitive isn't shipped yet. Surface as a warning so the
			// user knows to re-login.
			log.Printf("token-refresh %s: STALE — run `mcpshim login --server %s`", srv.Name, srv.Name)
		case err != nil:
			log.Printf("token-refresh %s: error: %v", srv.Name, err)
		case refreshed:
			log.Printf("token-refresh %s: refreshed", srv.Name)
		default:
			if s.debug {
				log.Printf("token-refresh %s: still fresh", srv.Name)
			}
		}
	}
}
