// Package mock contains only synthetic downstream services, never real credentials.
package mock

import (
	"context"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Input struct {
	Message string `json:"message"`
}
type Output struct {
	System  string `json:"system"`
	User    string `json:"user"`
	Message string `json:"message"`
}

func Handler(system string, tokens map[string]string) http.Handler {
	handlers := map[string]http.Handler{}
	for token, user := range tokens {
		server := mcp.NewServer(&mcp.Implementation{Name: "mock-" + system, Version: "0.1.0"}, nil)
		mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Synthetic echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in Input) (*mcp.CallToolResult, Output, error) {
			return nil, Output{system, user, in.Message}, nil
		})
		handlers["Bearer "+token] = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser access disabled", 403)
			return
		}
		if h, ok := handlers[r.Header.Get("Authorization")]; ok {
			h.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", 401)
	})
}
