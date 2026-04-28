package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mcpshim/mcpshim/internal/config"
	"github.com/mcpshim/mcpshim/internal/store"
)

// ErrNoToken is returned when no token is stored for a server.
var ErrNoToken = errors.New("no stored token")

// ErrNoRefreshToken is returned when the stored token has no refresh_token,
// so background refresh isn't possible without user interaction.
var ErrNoRefreshToken = errors.New("stored token has no refresh_token")

// ErrRefreshNotImplemented is returned while the proper refresh primitive
// is being designed. The ticker should still scan and surface stale tokens
// so users know they need to re-login, even if mcpshim can't yet refresh
// non-interactively. See TODO below.
var ErrRefreshNotImplemented = errors.New("background refresh not yet implemented; run `mcpshim login --server <name>`")

// RefreshTokenIfStale checks the stored OAuth token for a server and
// reports whether it's stale enough to warrant refresh. The actual
// non-interactive refresh primitive is still in design.
//
// TODO(refresh): mark3labs/mcp-go's OAuthHandler.RefreshToken needs an
// OAuthHandler that's been initialized via the same path
// NewOAuthStreamableHttpClient uses internally — naive construction +
// SetBaseURL(s.URL) is rejected by Granola/Notion's OAuth providers
// with 403. The working pattern is to trigger an Initialize() failure,
// catch the OAuthAuthorizationRequiredError, and use the Handler
// attached to that error (which has proper discovery state). That
// handler is opaque to us today; building one from scratch needs
// either ClientID persistence (see oauth_tokens schema) or replicating
// the StreamableHTTPClient handler-setup path.
//
// Until then this function reports staleness without attempting
// network refresh. The ticker logs the stale state once per tick so
// the user has visible signal that re-login is needed.
//
// Returns:
//   - (false, ErrNoToken)         no token stored
//   - (false, ErrNoRefreshToken)  stored token can't be refreshed
//   - (false, nil)                token still well within validity
//   - (true,  ErrRefreshNotImplemented)  stale, would refresh, but stub
func RefreshTokenIfStale(ctx context.Context, s config.MCPServer, dbStore *store.Store, buffer time.Duration) (bool, error) {
	if dbStore == nil {
		return false, errors.New("nil store")
	}

	token, err := dbStore.GetToken(s.Name)
	if err != nil {
		return false, fmt.Errorf("read token: %w", err)
	}
	if token == nil {
		return false, ErrNoToken
	}
	if token.RefreshToken == "" {
		return false, ErrNoRefreshToken
	}

	// Still well within validity — nothing to do.
	if !token.ExpiresAt.IsZero() && time.Until(token.ExpiresAt) > buffer {
		return false, nil
	}

	return true, ErrRefreshNotImplemented
}
