package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"uwu.cpp/config"
	"uwu.cpp/uwu"
)

// JSON-RPC 2.0 

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
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP TYPES

type InitializeResult struct {
	ProtocolVersion string     `json:"protocolVersion"`
	Capabilities    ServerCaps `json:"capabilities"`
	ServerInfo      ServerInfo `json:"serverInfo"`
	Instructions    string     `json:"instructions,omitempty"`
}

type ServerCaps struct {
	Tools   *struct{ ListChanged bool } `json:"tools,omitempty"`
	Prompts *struct{ ListChanged bool } `json:"prompts,omitempty"`
	Logging *struct{}                   `json:"logging,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ListToolsResult struct {
	Tools []MCPTool `json:"tools"`
}

type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type CallToolResult struct {
	Content []map[string]interface{} `json:"content"`
	IsError bool                     `json:"isError,omitempty"`
}

type ListPromptsResult struct {
	Prompts []PromptMeta `json:"prompts"`
}

type PromptMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type PromptMessage struct {
	Role    string                 `json:"role"`
	Content map[string]interface{} `json:"content"`
}

// SERVER

type Server struct {
	cfg      *config.Config
	registry *uwu.Registry
	mu       sync.Mutex
	writer   io.Writer
}

func NewServer(cfg *config.Config, registry *uwu.Registry) *Server {
	return &Server{cfg: cfg, registry: registry}
}

// ServeStdio runs the MCP server on stdin/stdout (for Claude Desktop / MCP clients)
func (s *Server) ServeStdio() error {
	s.writer = os.Stdout
	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("stdin: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s.log("debug", "recv: "+line)

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.sendErr(nil, -32700, "parse error", err.Error())
			continue
		}

		go s.dispatch(&req)
	}
}

// ServeHTTP runs the MCP server over HTTP
func (s *Server) ServeHTTP(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.httpHandler)
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/config/prompt", s.updatePromptHandler)
	mux.HandleFunc("/", s.indexHandler)

	s.log("info", fmt.Sprintf("http server at %s", addr))
	return http.ListenAndServe(addr, mux)
}

// DISPATCH 

func (s *Server) dispatch(req *Request) {
	var (
		result interface{}
		rpcErr *RPCError
	)

	switch req.Method {
	case "initialize":
		result, rpcErr = s.handleInitialize(req)
	case "initialized":
		s.log("info", "client initialized")
		return
	case "tools/list":
		result, rpcErr = s.handleListTools()
	case "tools/call":
		result, rpcErr = s.handleCallTool(req)
	case "prompts/list":
		result = ListPromptsResult{Prompts: []PromptMeta{
			{Name: "system", Description: "system prompt for this server"},
		}}
	case "prompts/get":
		result = GetPromptResult{
			Description: "uwu-agent system prompt",
			Messages: []PromptMessage{{
				Role:    "user",
				Content: map[string]interface{}{"type": "text", "text": s.cfg.SystemPrompt},
			}},
		}
	case "ping":
		result = map[string]interface{}{}
	case "notifications/cancelled":
		return
	default:
		rpcErr = &RPCError{Code: -32601, Message: "method not found: " + req.Method}
	}

	resp := Response{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	s.send(&resp)
}

func (s *Server) handleInitialize(req *Request) (interface{}, *RPCError) {
	var params struct {
		ProtocolVersion string     `json:"protocolVersion"`
		ClientInfo      ServerInfo `json:"clientInfo"`
	}
	if req.Params != nil {
		json.Unmarshal(req.Params, &params)
	}
	s.log("info", fmt.Sprintf("client: %s %s", params.ClientInfo.Name, params.ClientInfo.Version))

	return &InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: ServerCaps{
			Tools:   &struct{ ListChanged bool }{false},
			Prompts: &struct{ ListChanged bool }{false},
			Logging: &struct{}{},
		},
		ServerInfo:   ServerInfo{Name: s.cfg.Server.Name, Version: s.cfg.Server.Version},
		Instructions: s.cfg.SystemPrompt,
	}, nil
}

func (s *Server) handleListTools() (interface{}, *RPCError) {
	tools := s.registry.GetTools()
	result := make([]MCPTool, 0, len(tools))
	for _, t := range tools {
		result = append(result, MCPTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return &ListToolsResult{Tools: result}, nil
}

func (s *Server) handleCallTool(req *Request) (interface{}, *RPCError) {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &RPCError{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	s.log("info", fmt.Sprintf("call: %s", params.Name))
	t0 := time.Now()

	result, err := s.registry.CallTool(params.Name, params.Arguments)
	if err != nil {
		return nil, &RPCError{Code: -32603, Message: err.Error()}
	}

	s.log("debug", fmt.Sprintf("done: %s (%.0fms, isError=%v)",
		params.Name, float64(time.Since(t0).Microseconds())/1000, result.IsError))

	content := make([]map[string]interface{}, 0, len(result.Content))
	for _, c := range result.Content {
		block := map[string]interface{}{"type": c.Type}
		if c.Text != "" {
			block["text"] = c.Text
		}
		if c.Data != "" {
			block["data"] = c.Data
			block["mimeType"] = c.MimeType
		}
		content = append(content, block)
	}

	return &CallToolResult{Content: content, IsError: result.IsError}, nil
}

// HTTP HANDLERS 

func (s *Server) httpHandler(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

	if r.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{JSONRPC: "2.0",
			Error: &RPCError{Code: -32700, Message: "parse error"}})
		return
	}

	var result interface{}
	var rpcErr *RPCError

	switch req.Method {
	case "initialize":
		result, rpcErr = s.handleInitialize(&req)
	case "tools/list":
		result, rpcErr = s.handleListTools()
	case "tools/call":
		result, rpcErr = s.handleCallTool(&req)
	case "prompts/list":
		result = ListPromptsResult{Prompts: []PromptMeta{{Name: "system"}}}
	case "prompts/get":
		result = GetPromptResult{Messages: []PromptMessage{{
			Role:    "user",
			Content: map[string]interface{}{"type": "text", "text": s.cfg.SystemPrompt},
		}}}
	case "ping":
		result = map[string]interface{}{}
	default:
		rpcErr = &RPCError{Code: -32601, Message: "method not found: " + req.Method}
	}

	resp := Response{JSONRPC: "2.0", ID: req.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else {
		resp.Result = result
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"tools":     s.registry.ToolCount(),
		"provider":  s.cfg.AI.Provider,
		"model":     s.cfg.AI.Model,
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) updatePromptHandler(w http.ResponseWriter, r *http.Request) {
	if !s.auth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.cfg.SystemPrompt = body.Prompt
	s.mu.Unlock()
	s.log("info", "system prompt updated")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	tools := s.registry.GetTools()
	rows := ""
	for _, t := range tools {
		danger := ""
		if t.Dangerous {
			danger = " [!]"
		}
		rows += fmt.Sprintf("<tr><td><code>%s</code></td><td>%s%s</td><td>%s</td></tr>",
			t.Name, t.Description, danger, t.Module)
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!doctype html><html><head><title>uwu.cpp</title>
<style>body{font-family:monospace;background:#111;color:#ddd;padding:2em}
code{background:#222;padding:2px 6px}table{border-collapse:collapse;width:100%%}
td,th{padding:6px 10px;border-bottom:1px solid #333;text-align:left}th{color:#88f}</style></head>
<body><h2>uwu.cpp mcp server v%s</h2>
<p>endpoint: <code>POST /mcp</code> | provider: <code>%s/%s</code> | tools: %d</p>
<table><tr><th>tool</th><th>description</th><th>module</th></tr>%s</table>
</body></html>`, s.cfg.Server.Version, s.cfg.AI.Provider, s.cfg.AI.Model, len(tools), rows)
}

// HELPERS
func (s *Server) send(resp *Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.Marshal(resp)
	s.log("debug", "send: "+string(data))
	fmt.Fprintf(s.writer, "%s\n", data)
}

func (s *Server) sendErr(id interface{}, code int, msg, data string) {
	s.send(&Response{JSONRPC: "2.0", ID: id,
		Error: &RPCError{Code: code, Message: msg, Data: data}})
}

func (s *Server) auth(r *http.Request) bool {
	if s.cfg.Security.HTTPAPIKey == "" {
		return true
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		if strings.TrimPrefix(auth, "Bearer ") == s.cfg.Security.HTTPAPIKey {
			return true
		}
	}
	if r.Header.Get("X-API-Key") == s.cfg.Security.HTTPAPIKey {
		return true
	}
	if r.URL.Query().Get("api_key") == s.cfg.Security.HTTPAPIKey {
		return true
	}
	return false
}

func (s *Server) log(level, msg string) {
	lvl := s.cfg.Log.Level
	if level == "debug" && lvl != "debug" {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", level, msg)
}
