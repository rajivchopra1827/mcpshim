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
// so background refresh isn't possible without user interaction.
var ErrNoRefreshToken = errors.New("stored token has no refresh_token")

// ErrNoClientID is returned when the stored token has no captured client_id.
// This happens for tokens issued before mcpshim started persisting client_ids;
// the user needs to re-run `mcpshim login --server <name>` once to capture it.
var ErrNoClientID = errors.New("stored token has no captured client_id; re-login required")

// RefreshTokenIfStale checks the stored OAuth token for a server and, if
// it's expired or expires within `buffer`, attempts a non-interactive
// refresh using the persisted client_id and the OAuthHandler that
// mark3labs constructs internally for the streamable HTTP client.
//
// Strategy:
//  1. Read token + client_id from SQLite. Skip if no token, no
//     refresh_token, or no client_id (the last requires re-login once).
//  2. Build an OAuth-aware streamable HTTP client with ClientID set on
//     the OAuthConfig. Call Initialize().
//  3. If Initialize succeeds, the access_token is still server-valid —
//     return success. mark3labs may have auto-refreshed via getValidToken
//     during the call when local expiry says expired (it writes the new
//     token through SaveToken).
//  4. If Initialize returns OAuthAuthorizationRequiredError, extract the
//     handler from the error (now correctly configured by mark3labs with
//     baseURL/discovery state and our ClientID) and call RefreshToken on
//     it directly. This POSTs to the token endpoint with the right
//     client_id and persists the new token via SaveToken.
//
// Returns:
//   - (false, ErrNoToken | ErrNoRefreshToken | ErrNoClientID)
//   - (false, nil)                token still well within validity
//   - (true,  nil)                refresh succeeded or wasn't needed
//   - (true,  err)                refresh attempted and failed
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

	clientID, err := dbStore.GetClientID(s.Name)
	if err != nil {
		return false, fmt.Errorf("read client_id: %w", err)
	}
	if clientID == "" {
		return false, ErrNoClientID
	}

	storedRefreshToken := token.RefreshToken

	oauthClient, closeFn, err := newOAuthClient(s, mcpclient.OAuthConfig{
		ClientID:    clientID,
		RedirectURI: "http://127.0.0.1:53685/oauth/callback",
		TokenStore:  newSQLiteTokenStore(dbStore, s.Name),
		PKCEEnabled: true,
	})
	if err != nil {
		return true, fmt.Errorf("build oauth client: %w", err)
	}
	defer closeFn()

	if err := oauthClient.Start(ctx); err != nil {
		return true, fmt.Errorf("start: %w", err)
	}

	initReq := mcpproto.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpproto.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpproto.Implementation{Name: "mcpshimd-refresh", Version: "dev"}

	_, initErr := oauthClient.Initialize(ctx, initReq)
	if initErr == nil {
		// access_token still server-valid; mark3labs may have auto-refreshed
		// during the call if local expiry said stale.
		return true, nil
	}

	if !mcpclient.IsOAuthAuthorizationRequiredError(initErr) {
		return true, fmt.Errorf("initialize: %w", initErr)
	}

	handler := mcpclient.GetOAuthHandler(initErr)
	if handler == nil {
		return true, fmt.Errorf("auth required but no handler attached to error")
	}

	// The handler from the error has proper discovery state. Combined with
	// our persisted ClientID, RefreshToken POSTs cleanly to the token
	// endpoint and writes the new token via SaveToken.
	if _, refreshErr := handler.RefreshToken(ctx, storedRefreshToken); refreshErr != nil {
		return true, fmt.Errorf("refresh: %w", refreshErr)
	}
	return true, nil
}
