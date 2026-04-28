package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcpproto "github.com/mark3labs/mcp-go/mcp"
	"github.com/mcpshim/mcpshim/internal/config"
	"github.com/mcpshim/mcpshim/internal/store"
)

// ErrNoToken is returned when no token is stored for a server.
var ErrNoToken = errors.New("no stored token")

// ErrNoRefreshToken is returned when the stored token has no refresh_token,
// so background refresh isn't possible.
var ErrNoRefreshToken = errors.New("stored token has no refresh_token")

// RefreshTokenIfStale checks the stored OAuth token for a server and triggers
// a refresh via mark3labs/mcp-go's built-in refresh path if the token is
// missing, already expired, or expires within `buffer`. Returns whether a
// refresh was attempted.
//
// The mark3labs/mcp-go client refreshes on Initialize() / on each request when
// the access_token has expired but a valid refresh_token is present, then
// writes the new token through the configured TokenStore. We piggyback on that
// by simply running an Initialize() with an OAuth-aware client; if the token
// was already fresh, it's a cheap no-op call.
//
// Returns (false, nil) when the token is fresh, missing, or has no
// refresh_token to use. Returns (true, err) when refresh was attempted; err
// is non-nil only if the refresh path itself failed (e.g. revoked token).
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

	// If we know expiry and we're still well within it, skip.
	if !token.ExpiresAt.IsZero() && time.Until(token.ExpiresAt) > buffer {
		return false, nil
	}

	oauthClient, closeFn, err := newOAuthClient(s, mcpclient.OAuthConfig{
		// RedirectURI is unused for the refresh-only path but required by the
		// client constructor — point at a placeholder that's never actually hit.
		RedirectURI: "http://127.0.0.1:53685/oauth/callback",
		TokenStore:  newSQLiteTokenStore(dbStore, s.Name),
		PKCEEnabled: true,
	})
	if err != nil {
		return true, fmt.Errorf("build oauth client: %w", err)
	}
	defer closeFn()

	if err := oauthClient.Start(ctx); err != nil {
		return true, fmt.Errorf("start client: %w", err)
	}
	initReq := mcpproto.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpproto.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpproto.Implementation{Name: "mcpshimd-refresh", Version: "dev"}
	if _, err := oauthClient.Initialize(ctx, initReq); err != nil {
		return true, fmt.Errorf("initialize for refresh: %w", err)
	}
	return true, nil
}
