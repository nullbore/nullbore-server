// nullbore-mcp is an MCP (Model Context Protocol) server that exposes
// NullBore tunnel management as tools for AI agents.
//
// It speaks JSON-RPC over stdio and wraps the NullBore REST API.
//
// Usage:
//   nullbore-mcp --server http://localhost:8080 --api-key nbk_...
//
// MCP Tools:
//   - create_tunnel: Create a new tunnel
//   - list_tunnels: List active tunnels
//   - close_tunnel: Close a tunnel
//   - tunnel_status: Get tunnel details
//   - extend_tunnel: Extend a tunnel's TTL
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	serverURL string
	apiKey    string
	client    = &http.Client{Timeout: 15 * time.Second}
)

// MCP JSON-RPC types
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ToolDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func main() {
	flag.StringVar(&serverURL, "server", envOr("NULLBORE_SERVER", "http://localhost:8080"), "NullBore server URL")
	flag.StringVar(&apiKey, "api-key", envOr("NULLBORE_API_KEY", ""), "API key")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		resp := handleRequest(req)
		out, _ := json.Marshal(resp)
		fmt.Fprintln(os.Stdout, string(out))
	}
}

func handleRequest(req Request) Response {
	switch req.Method {
	case "initialize":
		return Response{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities":   map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":     map[string]string{"name": "nullbore-mcp", "version": "0.1.0"},
			},
		}

	case "notifications/initialized":
		return Response{JSONRPC: "2.0", ID: req.ID}

	case "tools/list":
		return Response{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]interface{}{"tools": getToolDefs()},
		}

	case "tools/call":
		return handleToolCall(req)

	default:
		return Response{
			JSONRPC: "2.0", ID: req.ID,
			Error: &RPCError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

func getToolDefs() []ToolDef {
	return []ToolDef{
		{
			Name:        "create_tunnel",
			Description: "Create a new tunnel to expose a local port through the NullBore server. Returns the public URL.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"port": map[string]interface{}{"type": "integer", "description": "Local port to expose (1-65535)"},
					"name": map[string]interface{}{"type": "string", "description": "Optional tunnel name for a stable slug URL"},
					"ttl":  map[string]interface{}{"type": "string", "description": "Time-to-live (e.g. '30m', '2h'). Default: 1h. Max: 24h"},
				},
				"required": []string{"port"},
			},
		},
		{
			Name:        "list_tunnels",
			Description: "List all active tunnels on the NullBore server.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "close_tunnel",
			Description: "Close an active tunnel by its ID or slug name.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{"type": "string", "description": "Tunnel ID or slug name"},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "tunnel_status",
			Description: "Get detailed status of a specific tunnel including traffic stats.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{"type": "string", "description": "Tunnel ID"},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "extend_tunnel",
			Description: "Extend a tunnel's time-to-live before it expires.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id":  map[string]interface{}{"type": "string", "description": "Tunnel ID"},
					"ttl": map[string]interface{}{"type": "string", "description": "Additional time (e.g. '30m', '1h')"},
				},
				"required": []string{"id", "ttl"},
			},
		},
	}
}

func handleToolCall(req Request) Response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	json.Unmarshal(req.Params, &params)

	var args map[string]interface{}
	json.Unmarshal(params.Arguments, &args)

	var result string
	var err error

	switch params.Name {
	case "create_tunnel":
		result, err = toolCreateTunnel(args)
	case "list_tunnels":
		result, err = toolListTunnels()
	case "close_tunnel":
		result, err = toolCloseTunnel(args)
	case "tunnel_status":
		result, err = toolTunnelStatus(args)
	case "extend_tunnel":
		result, err = toolExtendTunnel(args)
	default:
		return Response{
			JSONRPC: "2.0", ID: req.ID,
			Error: &RPCError{Code: -32602, Message: "unknown tool: " + params.Name},
		}
	}

	if err != nil {
		return Response{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]interface{}{
				"content": []TextContent{{Type: "text", Text: "Error: " + err.Error()}},
				"isError": true,
			},
		}
	}

	return Response{
		JSONRPC: "2.0", ID: req.ID,
		Result: map[string]interface{}{
			"content": []TextContent{{Type: "text", Text: result}},
		},
	}
}

// --- Tool implementations ---

func toolCreateTunnel(args map[string]interface{}) (string, error) {
	body := map[string]interface{}{"local_port": args["port"]}
	if v, ok := args["name"]; ok {
		body["name"] = v
	}
	if v, ok := args["ttl"]; ok {
		body["ttl"] = v
	}

	resp, err := apiCall("POST", "/v1/tunnels", body)
	if err != nil {
		return "", err
	}

	slug := resp["slug"].(string)
	return fmt.Sprintf("Tunnel created!\n  ID: %s\n  URL: %s/t/%s\n  Slug: %s\n  TTL: %s\n  Mode: %s",
		resp["id"], serverURL, slug, slug, resp["ttl"], resp["mode"]), nil
}

func toolListTunnels() (string, error) {
	data, err := apiCallRaw("GET", "/v1/tunnels", nil)
	if err != nil {
		return "", err
	}

	var tunnels []map[string]interface{}
	json.Unmarshal(data, &tunnels)

	if len(tunnels) == 0 {
		return "No active tunnels.", nil
	}

	var result string
	for _, t := range tunnels {
		result += fmt.Sprintf("• %s (port %v) — %s/t/%s — TTL: %s\n",
			t["id"].(string)[:8], t["local_port"], serverURL, t["slug"], t["ttl"])
	}
	return result, nil
}

func toolCloseTunnel(args map[string]interface{}) (string, error) {
	id := args["id"].(string)
	_, err := apiCall("DELETE", "/v1/tunnels/"+id, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Tunnel %s closed.", id), nil
}

func toolTunnelStatus(args map[string]interface{}) (string, error) {
	id := args["id"].(string)
	resp, err := apiCall("GET", "/v1/tunnels/"+id, nil)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Tunnel: %s\n  Slug: %s\n  Port: %v\n  Mode: %s\n  Requests: %v\n  Bytes In: %v\n  Bytes Out: %v\n  Created: %s\n  Expires: %s",
		resp["id"], resp["slug"], resp["local_port"], resp["mode"],
		resp["requests"], resp["bytes_in"], resp["bytes_out"],
		resp["created_at"], resp["expires_at"]), nil
}

func toolExtendTunnel(args map[string]interface{}) (string, error) {
	id := args["id"].(string)
	resp, err := apiCall("POST", "/v1/tunnels/"+id+"/extend", map[string]interface{}{"ttl": args["ttl"]})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Tunnel %s extended. New expiry: %s", id, resp["expires_at"]), nil
}

// --- HTTP helpers ---

func apiCall(method, path string, body interface{}) (map[string]interface{}, error) {
	data, err := apiCallRaw(method, path, body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

func apiCallRaw(method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, serverURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
