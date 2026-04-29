package mcp

import (
	"context"
	"fmt"
	"log"
	"time"

	mcpproto "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mcpshim/mcpshim/internal/config"
	"github.com/mcpshim/mcpshim/internal/store"
)

const (
	serveName    = "mcpshim"
	serveVersion = "dev"

	// Per-server tool list timeout at startup. A flaky upstream shouldn't
	// block startup beyond this; the server is just skipped with a warning.
	serveListTimeout = 30 * time.Second

	// Per-tool-call timeout. Matches the daemon's existing call timeout
	// in internal/server/server.go ("call" handler).
	serveCallTimeout = 60 * time.Second
)

// RunServe starts the stdio MCP server that aggregates every tool from
// every configured upstream MCP into one flat-namespaced server. Tools
// are exposed as `<server-alias>_<tool-name>` so that when registered in
// a Claude Code config as `mcpshim`, the model sees them as
// `mcp__mcpshim__<server-alias>_<tool-name>`.
//
// All upstream calls go through runWithOAuthFallback with interactive=false:
// stdio servers must never trigger an interactive OAuth browser callback
// since there's no visible window for that flow from a parent CLI's
// perspective. If a token is dead, the call fails with a clear error and
// the user resolves by running `mcpshim login --server <name>` separately.
//
// Logging goes to stderr (Go's `log` default) so it never pollutes stdout
// where the JSON-RPC traffic flows.
func RunServe(ctx context.Context, cfg *config.Config, dbStore *store.Store) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}

	srv := mcpserver.NewMCPServer(serveName, serveVersion)

	totalRegistered := 0
	for _, s := range cfg.Servers {
		s := s // capture loop var

		listCtx, cancel := context.WithTimeout(ctx, serveListTimeout)
		upstreamTools, err := fetchToolsRaw(listCtx, s, dbStore, false)
		cancel()
		if err != nil {
			log.Printf("serve: skipping %s — failed to list tools: %v", s.Name, err)
			continue
		}

		prefix := s.Alias
		if prefix == "" {
			prefix = s.Name
		}

		for _, t := range upstreamTools {
			t := t // capture loop var

			meta := mcpproto.Tool{
				Name:        prefix + "_" + t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			}

			handler := func(callCtx context.Context, req mcpproto.CallToolRequest) (*mcpproto.CallToolResult, error) {
				args := req.GetArguments()
				if args == nil {
					args = map[string]interface{}{}
				}

				timeoutCtx, cancelCall := context.WithTimeout(callCtx, serveCallTimeout)
				defer cancelCall()

				result, err := runWithOAuthFallback(timeoutCtx, s, dbStore, false, func(cli compatibleClient) (*mcpproto.CallToolResult, error) {
					inner := mcpproto.CallToolRequest{}
					inner.Params.Name = t.Name
					inner.Params.Arguments = args
					return cli.CallTool(timeoutCtx, inner)
				})
				if err != nil {
					return nil, fmt.Errorf("%s_%s: %w", prefix, t.Name, err)
				}
				return result, nil
			}

			srv.AddTool(meta, handler)
			totalRegistered++
		}

		log.Printf("serve: registered %d tools from %s under prefix %q", len(upstreamTools), s.Name, prefix)
	}

	log.Printf("serve: %d total tools across %d servers — starting stdio MCP server", totalRegistered, len(cfg.Servers))
	return mcpserver.ServeStdio(srv)
}
