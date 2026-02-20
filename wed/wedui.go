package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mcpAddr       = flag.String("mcp", "http://localhost:8765", "MCP server address")
	listenAddr    = flag.String("addr", ":9000", "Web UI listen address")
	mcpAPIKey     = flag.String("key", "", "MCP HTTP API key")
	apiKey        = flag.String("api-key", "", "AI provider API key")
	provider      = flag.String("provider", "gemini", "Provider: gemini|anthropic|openai|openrouter|ollama|custom")
	defaultModel  = flag.String("model", "", "Default model (empty = provider default)")
	baseURL       = flag.String("base-url", "", "Custom base URL (ollama/custom)")
	toolModules   = flag.String("modules", "shell,filesystem,system,process,clipboard,screen,input", "MCP modules. Never include 'ai'")
	maxTools      = flag.Int("max-tools", 40, "Max tools per request")
	maxTurns      = flag.Int("max-turns", 12, "Max agentic turns per request (lower = fewer API calls)")
	tokenBudget   = flag.Int("token-budget", 80000, "Max input tokens across all turns (0=unlimited)")
	minIntervalMs = flag.Int("min-interval", 1500, "Min ms between AI requests (rate limit)")
	resultTrunc   = flag.Int("result-trunc", 600, "Max chars for tool result in context")
	configFile    = flag.String("config", "config.yml", "Path to config YAML file")
)

const defaultSystemPrompt = "You are uwu-agent. Use MCP tools to execute tasks on this Linux machine. Be concise and efficient."

var (
	activeMu           sync.RWMutex
	activeProvider     string
	activeModel        string
	activeAPIKey       string
	activeBaseURL      string
	activeMaxTurns     int
	activeTokenBudget  int
	activeToolsEnabled bool
	activeSystemPrompt string
)

// ── config.yml load/save ──────────────────────────────────────────────────

type configYAML struct {
	Provider     string
	Model        string
	APIKey       string
	BaseURL      string
	MaxTurns     int
	TokenBudget  int
	ToolsEnabled bool
	SystemPrompt string
}

func loadConfigFile() {
	data, err := os.ReadFile(*configFile)
	if err != nil {
		return // file not found is fine
	}
	cfg := parseSimpleYAML(string(data))
	activeMu.Lock()
	defer activeMu.Unlock()
	if v, ok := cfg["provider"]; ok && v != "" {
		activeProvider = v
	}
	if v, ok := cfg["model"]; ok && v != "" {
		activeModel = v
	}
	if v, ok := cfg["api_key"]; ok {
		activeAPIKey = v
	}
	if v, ok := cfg["base_url"]; ok {
		activeBaseURL = v
	}
	if v, ok := cfg["max_turns"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			activeMaxTurns = n
		}
	}
	if v, ok := cfg["token_budget"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			activeTokenBudget = n
		}
	}
	if v, ok := cfg["tools_enabled"]; ok {
		activeToolsEnabled = v == "true"
	}
	if v, ok := cfg["system_prompt"]; ok && v != "" {
		activeSystemPrompt = v
	}
	log.Printf("[config] loaded from %s", *configFile)
}

func saveConfigFile() {
	activeMu.RLock()
	prov := activeProvider
	model := activeModel
	key := activeAPIKey
	base := activeBaseURL
	turns := activeMaxTurns
	budget := activeTokenBudget
	toolsOn := activeToolsEnabled
	sysPrompt := activeSystemPrompt
	activeMu.RUnlock()

	// encode system_prompt as a quoted YAML string to handle multiline safely
	sysPromptQ := yamlQuoteString(sysPrompt)

	content := fmt.Sprintf("# uwu-agent config — auto-generated\n"+
		"provider: %s\n"+
		"model: %s\n"+
		"api_key: %s\n"+
		"base_url: %s\n"+
		"max_turns: %d\n"+
		"token_budget: %d\n"+
		"tools_enabled: %v\n"+
		"system_prompt: %s\n",
		prov, model,
		yamlQuoteString(key),
		yamlQuoteString(base),
		turns, budget, toolsOn,
		sysPromptQ,
	)
	if err := os.WriteFile(*configFile, []byte(content), 0644); err != nil {
		log.Printf("[config] save error: %v", err)
	} else {
		log.Printf("[config] saved to %s", *configFile)
	}
}

// yamlQuoteString wraps a value in double-quotes with basic escaping.
func yamlQuoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return `"` + s + `"`
}

// parseSimpleYAML parses flat key: "value" or key: value lines.
func parseSimpleYAML(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		// handle quoted strings
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
			v = strings.ReplaceAll(v, `\"`, `"`)
			v = strings.ReplaceAll(v, `\\`, `\`)
			v = strings.ReplaceAll(v, `\n`, "\n")
			v = strings.ReplaceAll(v, `\r`, "\r")
		}
		out[k] = v
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────

func initActive() {
	activeMu.Lock()
	activeProvider = *provider
	activeAPIKey = *apiKey
	activeBaseURL = *baseURL
	activeModel = *defaultModel
	activeMaxTurns = *maxTurns
	activeTokenBudget = *tokenBudget
	activeToolsEnabled = true
	activeSystemPrompt = defaultSystemPrompt
	if activeModel == "" {
		activeModel = providerDefaultModel(activeProvider)
	}
	activeMu.Unlock()

	// overlay with saved config (may overwrite flag defaults)
	loadConfigFile()
}

func getSystemPrompt() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	if activeSystemPrompt == "" {
		return defaultSystemPrompt
	}
	return activeSystemPrompt
}

func providerDefaultModel(p string) string {
	switch p {
	case "anthropic":
		return "claude-sonnet-4-5"
	case "openai":
		return "gpt-4o"
	case "openrouter":
		return "anthropic/claude-sonnet-4-5"
	case "ollama":
		return "llama3.3"
	case "gemini":
		return "gemini-2.0-flash"
	default:
		return ""
	}
}

func providerBaseURL(p string) string {
	switch p {
	case "openai":
		return "https://api.openai.com/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "ollama":
		return "http://localhost:11434/v1"
	default:
		return ""
	}
}

var (
	rateMu      sync.Mutex
	lastReqTime time.Time
)

func waitRateLimit() {
	rateMu.Lock()
	defer rateMu.Unlock()
	since := time.Since(lastReqTime)
	minInterval := time.Duration(*minIntervalMs) * time.Millisecond
	if since < minInterval {
		time.Sleep(minInterval - since)
	}
	lastReqTime = time.Now()
}

var (
	cachedTools   []mcpTool
	cachedToolsMu sync.RWMutex
)

func refreshTools() error {
	tools, err := getMCPTools()
	if err != nil {
		return err
	}
	filtered := filterTools(tools)
	cachedToolsMu.Lock()
	cachedTools = filtered
	cachedToolsMu.Unlock()
	log.Printf("[tools] %d/%d loaded (modules: %s)", len(filtered), len(tools), *toolModules)
	return nil
}

func getTools() []mcpTool {
	cachedToolsMu.RLock()
	defer cachedToolsMu.RUnlock()
	return cachedTools
}

type mcpRPCReq struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type mcpTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type mcpToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func mcpCall(method string, params interface{}) ([]byte, error) {
	body, _ := json.Marshal(mcpRPCReq{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	req, _ := http.NewRequest("POST", *mcpAddr+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if *mcpAPIKey != "" {
		req.Header.Set("X-API-Key", *mcpAPIKey)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func getMCPTools() ([]mcpTool, error) {
	raw, err := mcpCall("tools/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Result struct{ Tools []mcpTool } `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s", out.Error.Message)
	}
	return out.Result.Tools, nil
}

func filterTools(tools []mcpTool) []mcpTool {
	allowed := map[string]bool{}
	for _, m := range strings.Split(*toolModules, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		if m == "ai" {
			log.Println("[warn] 'ai' module BLOCKED")
			continue
		}
		allowed[m] = true
	}
	var out []mcpTool
	for _, t := range tools {
		mod := strings.SplitN(t.Name, "_", 2)[0]
		if mod == "ai" {
			log.Printf("[tools] blocked ai tool: %s", t.Name)
			continue
		}
		if allowed[mod] {
			out = append(out, t)
		}
	}
	if len(out) > *maxTools {
		out = out[:*maxTools]
	}
	return out
}

func callMCPTool(name string, args map[string]interface{}) (string, bool) {
	raw, err := mcpCall("tools/call", map[string]interface{}{"name": name, "arguments": args})
	if err != nil {
		return "error: " + err.Error(), true
	}
	var out struct {
		Result mcpToolResult
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "parse error: " + err.Error(), true
	}
	if out.Error != nil {
		return "error: " + out.Error.Message, true
	}
	var parts []string
	for _, c := range out.Result.Content {
		if c.Type == "text" {
			parts = append(parts, c.Text)
		}
	}
	return strings.Join(parts, "\n"), out.Result.IsError
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

type uploadedFile struct {
	Name     string
	MimeType string
	Data     []byte
}

var (
	uploadedMu    sync.Mutex
	uploadedFiles []uploadedFile
)

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text             string              `json:"text,omitempty"`
	InlineData       *geminiInlineData   `json:"inlineData,omitempty"`
	FunctionCall     *geminiFuncCall     `json:"functionCall,omitempty"`
	FunctionResponse *geminiFuncResponse `json:"functionResponse,omitempty"`
}
type geminiInlineData struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}
type geminiFuncCall struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}
type geminiFuncResponse struct {
	Name     string                 `json:"name"`
	Response map[string]interface{} `json:"response"`
}

func sanitizeSchema(s map[string]interface{}) map[string]interface{} {
	if s == nil {
		return nil
	}
	out := map[string]interface{}{}
	for k, v := range s {
		if k == "$schema" || k == "additionalProperties" || k == "$defs" || k == "$ref" {
			continue
		}
		if sub, ok := v.(map[string]interface{}); ok {
			out[k] = sanitizeSchema(sub)
		} else {
			out[k] = v
		}
	}
	return out
}

func geminiToolDefs(tools []mcpTool) []interface{} {
	decls := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		d := map[string]interface{}{"name": t.Name, "description": t.Description}
		if t.InputSchema != nil {
			d["parameters"] = sanitizeSchema(t.InputSchema)
		}
		decls = append(decls, d)
	}
	return []interface{}{map[string]interface{}{"functionDeclarations": decls}}
}

func runGeminiAgent(model string, tools []mcpTool, toolsEnabled bool, parts []geminiPart, turns int, budget int, emit func(string, interface{})) {
	key := activeAPIKey
	sysPrompt := getSystemPrompt()
	contents := []geminiContent{{Role: "user", Parts: parts}}
	totalIn, totalOut := 0, 0

	var gdefs []interface{}
	if toolsEnabled && len(tools) > 0 {
		gdefs = geminiToolDefs(tools)
	}

	for turn := 0; turn < turns; turn++ {
		waitRateLimit()
		emit("activity", map[string]string{"text": "thinking...", "ts": now()})

		body := map[string]interface{}{
			"contents": contents,
			"systemInstruction": map[string]interface{}{
				"parts": []map[string]string{{"text": sysPrompt}},
			},
			"generationConfig": map[string]interface{}{"maxOutputTokens": 4096, "temperature": 0.7},
		}
		if len(gdefs) > 0 {
			body["tools"] = gdefs
		}

		data, _ := json.Marshal(body)
		url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, key)
		resp, err := doPost(url, "", data)
		if err != nil {
			emit("error", err.Error())
			return
		}

		var gr struct {
			Candidates []struct {
				Content      geminiContent `json:"content"`
				FinishReason string        `json:"finishReason"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount     int
				CandidatesTokenCount int
			} `json:"usageMetadata"`
			Error *struct{ Status, Message string } `json:"error"`
		}
		if err := json.Unmarshal(resp, &gr); err != nil {
			emit("error", "parse: "+truncate(string(resp), 150))
			return
		}
		if gr.Error != nil {
			emit("error", fmt.Sprintf("gemini [%s]: %s", gr.Error.Status, gr.Error.Message))
			return
		}
		if len(gr.Candidates) == 0 {
			emit("error", "no candidates")
			return
		}

		totalIn += gr.UsageMetadata.PromptTokenCount
		totalOut += gr.UsageMetadata.CandidatesTokenCount
		emit("tokens", map[string]int{"in": totalIn, "out": totalOut, "turn": turn + 1})

		if budget > 0 && totalIn > budget {
			emit("error", fmt.Sprintf("token budget exceeded (%d > %d input tokens)", totalIn, budget))
			return
		}

		cand := gr.Candidates[0]
		contents = append(contents, geminiContent{Role: "model", Parts: cand.Content.Parts})

		var funcCalls []geminiFuncCall
		var texts []string
		for _, p := range cand.Content.Parts {
			if p.FunctionCall != nil {
				funcCalls = append(funcCalls, *p.FunctionCall)
			}
			if p.Text != "" {
				texts = append(texts, p.Text)
			}
		}

		if len(funcCalls) == 0 {
			emit("activity", map[string]interface{}{"text": fmt.Sprintf("done  in:%d out:%d tok  (%d turns)", totalIn, totalOut, turn+1), "ts": now()})
			emit("reply", strings.Join(texts, "\n"))
			emit("done", nil)
			return
		}
		if len(texts) > 0 {
			emit("thinking", strings.Join(texts, "\n"))
		}

		var frs []geminiPart
		for _, fc := range funcCalls {
			argsJSON, _ := json.Marshal(fc.Args)
			emit("tool_call", map[string]interface{}{"name": fc.Name, "args": truncate(string(argsJSON), 200), "ts": now()})
			start := time.Now()
			result, isErr := callMCPTool(fc.Name, fc.Args)
			ms := time.Since(start).Milliseconds()
			emit("tool_result", map[string]interface{}{"name": fc.Name, "result": truncate(result, 300), "ms": ms, "ts": now(), "err": isErr})
			truncResult := truncate(result, *resultTrunc)
			frs = append(frs, geminiPart{FunctionResponse: &geminiFuncResponse{Name: fc.Name, Response: map[string]interface{}{"result": truncResult}}})
		}
		contents = append(contents, geminiContent{Role: "function", Parts: frs})
	}
	emit("error", fmt.Sprintf("max turns (%d) reached", turns))
}

func anthropicToolDefs(tools []mcpTool) []interface{} {
	out := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		d := map[string]interface{}{"name": t.Name, "description": t.Description}
		if t.InputSchema != nil {
			d["input_schema"] = t.InputSchema
		} else {
			d["input_schema"] = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}
		out = append(out, d)
	}
	return out
}

func runAnthropicAgent(model string, tools []mcpTool, toolsEnabled bool, promptParts []interface{}, turns int, budget int, emit func(string, interface{})) {
	key := activeAPIKey
	sysPrompt := getSystemPrompt()
	messages := []map[string]interface{}{{"role": "user", "content": promptParts}}
	totalIn, totalOut := 0, 0

	var defs []interface{}
	if toolsEnabled && len(tools) > 0 {
		defs = anthropicToolDefs(tools)
	}

	for turn := 0; turn < turns; turn++ {
		waitRateLimit()
		emit("activity", map[string]string{"text": "thinking...", "ts": now()})

		body := map[string]interface{}{
			"model":      model,
			"max_tokens": 4096,
			"system":     sysPrompt,
			"messages":   messages,
		}
		if len(defs) > 0 {
			body["tools"] = defs
		}

		data, _ := json.Marshal(body)
		resp, err := doPostHeaders("https://api.anthropic.com/v1/messages", map[string]string{
			"x-api-key": key, "anthropic-version": "2023-06-01",
		}, data)
		if err != nil {
			emit("error", err.Error())
			return
		}

		var ar struct {
			Content []struct {
				Type  string                 `json:"type"`
				Text  string                 `json:"text"`
				ID    string                 `json:"id"`
				Name  string                 `json:"name"`
				Input map[string]interface{} `json:"input"`
			} `json:"content"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				InputTokens  int
				OutputTokens int
			} `json:"usage"`
			Error *struct{ Type, Message string } `json:"error"`
		}
		if err := json.Unmarshal(resp, &ar); err != nil {
			emit("error", "parse: "+truncate(string(resp), 150))
			return
		}
		if ar.Error != nil {
			emit("error", fmt.Sprintf("anthropic [%s]: %s", ar.Error.Type, ar.Error.Message))
			return
		}

		totalIn += ar.Usage.InputTokens
		totalOut += ar.Usage.OutputTokens
		emit("tokens", map[string]int{"in": totalIn, "out": totalOut, "turn": turn + 1})

		if budget > 0 && totalIn > budget {
			emit("error", fmt.Sprintf("token budget exceeded (%d > %d input tokens)", totalIn, budget))
			return
		}

		messages = append(messages, map[string]interface{}{"role": "assistant", "content": ar.Content})

		var toolUses []struct {
			ID    string
			Name  string
			Input map[string]interface{}
		}
		var texts []string
		for _, c := range ar.Content {
			if c.Type == "text" && c.Text != "" {
				texts = append(texts, c.Text)
			}
			if c.Type == "tool_use" {
				toolUses = append(toolUses, struct {
					ID    string
					Name  string
					Input map[string]interface{}
				}{c.ID, c.Name, c.Input})
			}
		}

		if len(toolUses) == 0 {
			emit("activity", map[string]interface{}{"text": fmt.Sprintf("done  in:%d out:%d tok  (%d turns)", totalIn, totalOut, turn+1), "ts": now()})
			emit("reply", strings.Join(texts, "\n"))
			emit("done", nil)
			return
		}
		if len(texts) > 0 {
			emit("thinking", strings.Join(texts, "\n"))
		}

		var toolResults []interface{}
		for _, tu := range toolUses {
			argsJSON, _ := json.Marshal(tu.Input)
			emit("tool_call", map[string]interface{}{"name": tu.Name, "args": truncate(string(argsJSON), 200), "ts": now()})
			start := time.Now()
			result, isErr := callMCPTool(tu.Name, tu.Input)
			ms := time.Since(start).Milliseconds()
			emit("tool_result", map[string]interface{}{"name": tu.Name, "result": truncate(result, 300), "ms": ms, "ts": now(), "err": isErr})
			truncResult := truncate(result, *resultTrunc)
			toolResults = append(toolResults, map[string]interface{}{
				"type": "tool_result", "tool_use_id": tu.ID, "content": truncResult,
			})
		}
		messages = append(messages, map[string]interface{}{"role": "user", "content": toolResults})
	}
	emit("error", fmt.Sprintf("max turns (%d) reached", turns))
}

func openAIToolDefs(tools []mcpTool) []interface{} {
	out := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		params := map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		if t.InputSchema != nil {
			params = t.InputSchema
		}
		out = append(out, map[string]interface{}{
			"type": "function",
			"function": map[string]interface{}{
				"name": t.Name, "description": t.Description, "parameters": params,
			},
		})
	}
	return out
}

func runOpenAIAgent(prov, model string, tools []mcpTool, toolsEnabled bool, promptParts []interface{}, turns int, budget int, emit func(string, interface{})) {
	key := activeAPIKey
	sysPrompt := getSystemPrompt()
	base := activeBaseURL
	if base == "" {
		base = providerBaseURL(prov)
	}
	if prov == "ollama" && !strings.Contains(base, "/v1") {
		base = strings.TrimSuffix(base, "/") + "/v1"
	}
	endpoint := base + "/chat/completions"

	messages := []map[string]interface{}{
		{"role": "system", "content": sysPrompt},
		{"role": "user", "content": promptParts},
	}
	totalIn, totalOut := 0, 0

	var defs []interface{}
	if toolsEnabled && len(tools) > 0 {
		defs = openAIToolDefs(tools)
	}

	headers := map[string]string{"Authorization": "Bearer " + key}
	if prov == "openrouter" {
		headers["HTTP-Referer"] = "https://uwu.cpp"
		headers["X-Title"] = "uwu-agent"
	}

	for turn := 0; turn < turns; turn++ {
		waitRateLimit()
		emit("activity", map[string]string{"text": "thinking...", "ts": now()})

		body := map[string]interface{}{
			"model":    model,
			"messages": messages,
		}
		if len(defs) > 0 {
			body["tools"] = defs
			body["tool_choice"] = "auto"
		}

		data, _ := json.Marshal(body)
		resp, err := doPostHeaders(endpoint, headers, data)
		if err != nil {
			emit("error", err.Error())
			return
		}

		var or struct {
			Choices []struct {
				Message struct {
					Role      string `json:"role"`
					Content   string `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int
				CompletionTokens int
			} `json:"usage"`
			Error *struct{ Message, Type string } `json:"error"`
		}
		if err := json.Unmarshal(resp, &or); err != nil {
			emit("error", "parse: "+truncate(string(resp), 150))
			return
		}
		if or.Error != nil {
			emit("error", fmt.Sprintf("[%s]: %s", or.Error.Type, or.Error.Message))
			return
		}
		if len(or.Choices) == 0 {
			emit("error", "no choices")
			return
		}

		totalIn += or.Usage.PromptTokens
		totalOut += or.Usage.CompletionTokens
		emit("tokens", map[string]int{"in": totalIn, "out": totalOut, "turn": turn + 1})

		if budget > 0 && totalIn > budget {
			emit("error", fmt.Sprintf("token budget exceeded (%d > %d input tokens)", totalIn, budget))
			return
		}

		msg := or.Choices[0].Message
		messages = append(messages, map[string]interface{}{
			"role": "assistant", "content": msg.Content, "tool_calls": msg.ToolCalls,
		})

		if len(msg.ToolCalls) == 0 {
			emit("activity", map[string]interface{}{"text": fmt.Sprintf("done  in:%d out:%d tok  (%d turns)", totalIn, totalOut, turn+1), "ts": now()})
			emit("reply", msg.Content)
			emit("done", nil)
			return
		}
		if msg.Content != "" {
			emit("thinking", msg.Content)
		}

		for _, tc := range msg.ToolCalls {
			var args map[string]interface{}
			json.Unmarshal([]byte(tc.Function.Arguments), &args)
			emit("tool_call", map[string]interface{}{"name": tc.Function.Name, "args": truncate(tc.Function.Arguments, 200), "ts": now()})
			start := time.Now()
			result, isErr := callMCPTool(tc.Function.Name, args)
			ms := time.Since(start).Milliseconds()
			emit("tool_result", map[string]interface{}{"name": tc.Function.Name, "result": truncate(result, 300), "ms": ms, "ts": now(), "err": isErr})
			truncResult := truncate(result, *resultTrunc)
			messages = append(messages, map[string]interface{}{
				"role": "tool", "tool_call_id": tc.ID, "content": truncResult,
			})
		}
	}
	emit("error", fmt.Sprintf("max turns (%d) reached", turns))
}

func doPost(url, bearerKey string, data []byte) ([]byte, error) {
	h := map[string]string{}
	if bearerKey != "" {
		h["Authorization"] = "Bearer " + bearerKey
	}
	return doPostHeaders(url, h, data)
}

func doPostHeaders(url string, headers map[string]string, data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func now() string { return time.Now().Format("15:04:05") }

func pingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := http.Get(*mcpAddr + "/health")
	ms := time.Since(start).Milliseconds()
	activeMu.RLock()
	prov, model, turns, budget, toolsEnabled, sysPrompt := activeProvider, activeModel, activeMaxTurns, activeTokenBudget, activeToolsEnabled, activeSystemPrompt
	activeMu.RUnlock()
	info := map[string]interface{}{
		"provider":      prov,
		"model":         model,
		"tools":         len(getTools()),
		"max_turns":     turns,
		"token_budget":  budget,
		"tools_enabled": toolsEnabled,
		"system_prompt": sysPrompt,
	}
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "ms": -1, "info": info})
		return
	}
	defer resp.Body.Close()
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "ms": ms, "info": info})
}

func modelsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	activeMu.RLock()
	prov, key, base, model := activeProvider, activeAPIKey, activeBaseURL, activeModel
	activeMu.RUnlock()

	type modelInfo struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var models []modelInfo

	switch prov {
	case "gemini":
		url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models?key=%s&pageSize=50", key)
		resp, err := http.Get(url)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		var raw struct {
			Models []struct {
				Name    string   `json:"name"`
				Display string   `json:"displayName"`
				Methods []string `json:"supportedGenerationMethods"`
			} `json:"models"`
		}
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &raw)
		for _, m := range raw.Models {
			for _, method := range m.Methods {
				if method == "generateContent" {
					models = append(models, modelInfo{strings.TrimPrefix(m.Name, "models/"), m.Display})
					break
				}
			}
		}

	case "anthropic":
		models = []modelInfo{
			{"claude-opus-4-5", "Claude Opus 4.5"},
			{"claude-sonnet-4-5", "Claude Sonnet 4.5"},
			{"claude-haiku-4-5", "Claude Haiku 4.5"},
			{"claude-sonnet-4-5-20251022", "Claude Sonnet 4.5 (dated)"},
			{"claude-haiku-4-5-20251001", "Claude Haiku 4.5 (dated)"},
		}

	case "openai":
		models = []modelInfo{
			{"gpt-4o", "GPT-4o"}, {"gpt-4o-mini", "GPT-4o mini"},
			{"gpt-4-turbo", "GPT-4 Turbo"}, {"o1", "o1"}, {"o1-mini", "o1 mini"}, {"o3-mini", "o3 mini"},
		}

	case "openrouter":
		ep := "https://openrouter.ai/api/v1/models"
		if resp, err := http.Get(ep); err == nil {
			defer resp.Body.Close()
			var raw struct {
				Data []struct{ ID, Name string } `json:"data"`
			}
			body, _ := io.ReadAll(resp.Body)
			json.Unmarshal(body, &raw)
			for _, m := range raw.Data {
				models = append(models, modelInfo{m.ID, m.Name})
			}
		}
		if len(models) == 0 {
			models = []modelInfo{
				{"anthropic/claude-sonnet-4-5", "Claude Sonnet 4.5"},
				{"anthropic/claude-opus-4-5", "Claude Opus 4.5"},
				{"openai/gpt-4o", "GPT-4o"},
				{"google/gemini-2.0-flash-exp", "Gemini 2.0 Flash"},
				{"meta-llama/llama-3.3-70b-instruct", "Llama 3.3 70B"},
				{"deepseek/deepseek-r1", "DeepSeek R1"},
			}
		}

	case "ollama":
		ollamaRoot := base
		if ollamaRoot == "" {
			ollamaRoot = "http://localhost:11434"
		}
		ollamaRoot = strings.TrimSuffix(strings.TrimSuffix(ollamaRoot, "/"), "/v1")
		if resp, err := http.Get(ollamaRoot + "/api/tags"); err == nil {
			defer resp.Body.Close()
			var raw struct {
				Models []struct{ Name string } `json:"models"`
			}
			body, _ := io.ReadAll(resp.Body)
			json.Unmarshal(body, &raw)
			for _, m := range raw.Models {
				models = append(models, modelInfo{m.Name, m.Name})
			}
		}
		if len(models) == 0 {
			models = []modelInfo{
				{"llama3.3", "Llama 3.3"}, {"qwen2.5", "Qwen 2.5"},
				{"deepseek-r1", "DeepSeek R1"}, {"mistral", "Mistral"}, {"phi4", "Phi-4"},
			}
		}

	default:
		models = []modelInfo{{"default", "default"}}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"models": models, "current": model, "provider": prov})
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	var body struct {
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		APIKey       string `json:"api_key"`
		BaseURL      string `json:"base_url"`
		MaxTurns     int    `json:"max_turns"`
		TokenBudget  int    `json:"token_budget"`
		ToolsEnabled *bool  `json:"tools_enabled"`
		SystemPrompt *string `json:"system_prompt"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	activeMu.Lock()
	if body.Provider != "" {
		activeProvider = body.Provider
	}
	if body.Model != "" {
		activeModel = body.Model
	}
	if body.APIKey != "" {
		activeAPIKey = body.APIKey
	}
	if body.BaseURL != "" {
		activeBaseURL = body.BaseURL
	}
	if body.MaxTurns > 0 {
		activeMaxTurns = body.MaxTurns
	}
	if body.TokenBudget >= 0 {
		activeTokenBudget = body.TokenBudget
	}
	if body.ToolsEnabled != nil {
		activeToolsEnabled = *body.ToolsEnabled
	}
	if body.SystemPrompt != nil {
		if *body.SystemPrompt == "" {
			activeSystemPrompt = defaultSystemPrompt
		} else {
			activeSystemPrompt = *body.SystemPrompt
		}
	}
	activeMu.Unlock()

	// persist to config.yml
	saveConfigFile()

	w.Header().Set("Content-Type", "application/json")
	activeMu.RLock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"provider":      activeProvider,
		"model":         activeModel,
		"max_turns":     activeMaxTurns,
		"token_budget":  activeTokenBudget,
		"tools_enabled": activeToolsEnabled,
		"system_prompt": activeSystemPrompt,
	})
	activeMu.RUnlock()
}

func refreshToolsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := refreshTools(); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	tools := getTools()
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"tools": len(tools), "names": names})
}

func filesListHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uploadedMu.Lock()
	type fileInfo struct {
		Index    int    `json:"index"`
		Name     string `json:"name"`
		MimeType string `json:"mime"`
		Size     int    `json:"size"`
	}
	var list []fileInfo
	for i, f := range uploadedFiles {
		list = append(list, fileInfo{i, f.Name, f.MimeType, len(f.Data)})
	}
	uploadedMu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{"files": list})
}

func fileDownloadHandler(w http.ResponseWriter, r *http.Request) {
	var idx int
	fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/files/"), "%d", &idx)
	uploadedMu.Lock()
	if idx < 0 || idx >= len(uploadedFiles) {
		uploadedMu.Unlock()
		http.NotFound(w, r)
		return
	}
	f := uploadedFiles[idx]
	uploadedMu.Unlock()
	w.Header().Set("Content-Type", f.MimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", f.Name))
	w.Write(f.Data)
}

func agentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	r.ParseMultipartForm(64 << 20)

	prompt := r.FormValue("prompt")
	modelOverride := r.FormValue("model")
	turnsOverride := 0
	fmt.Sscanf(r.FormValue("max_turns"), "%d", &turnsOverride)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher := w.(http.Flusher)

	emit := func(typ string, v interface{}) {
		data, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, data)
		flusher.Flush()
	}

	activeMu.RLock()
	prov := activeProvider
	model := activeModel
	turns := activeMaxTurns
	budget := activeTokenBudget
	toolsEnabled := activeToolsEnabled
	activeMu.RUnlock()
	if modelOverride != "" {
		model = modelOverride
	}
	if turnsOverride > 0 {
		turns = turnsOverride
	}

	tools := getTools()
	toolsLabel := "on"
	if !toolsEnabled {
		toolsLabel = "off"
	}
	emit("activity", map[string]interface{}{
		"text": fmt.Sprintf("%d tools [%s] · %s/%s · max %d turns", len(tools), toolsLabel, prov, model, turns), "ts": now(),
	})
	if budget > 0 {
		emit("activity", map[string]interface{}{"text": fmt.Sprintf("token budget: %dk", budget/1000), "ts": now()})
	}

	var geminiParts []geminiPart
	var anthropicParts []interface{}
	var openaiParts []interface{}
	newFiles := []uploadedFile{}

	if r.MultipartForm != nil {
		for _, fhs := range r.MultipartForm.File {
			for _, fh := range fhs {
				f, err := fh.Open()
				if err != nil {
					continue
				}
				data, _ := io.ReadAll(f)
				f.Close()
				mime := fh.Header.Get("Content-Type")
				if mime == "" {
					mime = "application/octet-stream"
				}
				b64 := base64.StdEncoding.EncodeToString(data)

				newFiles = append(newFiles, uploadedFile{fh.Filename, mime, data})
				emit("activity", map[string]string{"text": fmt.Sprintf("attach: %s (%dKB)", fh.Filename, len(data)/1024), "ts": now()})

				geminiParts = append(geminiParts, geminiPart{InlineData: &geminiInlineData{MimeType: mime, Data: b64}})
				if strings.HasPrefix(mime, "image/") {
					anthropicParts = append(anthropicParts, map[string]interface{}{
						"type": "image", "source": map[string]interface{}{"type": "base64", "media_type": mime, "data": b64},
					})
					openaiParts = append(openaiParts, map[string]interface{}{
						"type":      "image_url",
						"image_url": map[string]string{"url": "data:" + mime + ";base64," + b64},
					})
				}
			}
		}
	}

	if len(newFiles) > 0 {
		uploadedMu.Lock()
		uploadedFiles = append(uploadedFiles, newFiles...)
		uploadedMu.Unlock()
	}

	switch prov {
	case "gemini":
		parts := append([]geminiPart{{Text: prompt}}, geminiParts...)
		runGeminiAgent(model, tools, toolsEnabled, parts, turns, budget, emit)

	case "anthropic":
		parts := []interface{}{map[string]string{"type": "text", "text": prompt}}
		parts = append(parts, anthropicParts...)
		runAnthropicAgent(model, tools, toolsEnabled, parts, turns, budget, emit)

	default:
		parts := []interface{}{map[string]string{"type": "text", "text": prompt}}
		parts = append(parts, openaiParts...)
		runOpenAIAgent(prov, model, tools, toolsEnabled, parts, turns, budget, emit)
	}
}

func main() {
	flag.Parse()
	initActive()

	log.Printf("fetching MCP tools from %s...", *mcpAddr)
	if err := refreshTools(); err != nil {
		log.Printf("[warn] tools load failed: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pageHTML)
	})
	http.HandleFunc("/api/ping", pingHandler)
	http.HandleFunc("/api/models", modelsHandler)
	http.HandleFunc("/api/config", configHandler)
	http.HandleFunc("/api/refresh-tools", refreshToolsHandler)
	http.HandleFunc("/api/files", filesListHandler)
	http.HandleFunc("/api/files/", fileDownloadHandler)
	http.HandleFunc("/api/send", agentHandler)

	log.Printf("uwu agent → http://localhost%s  provider:%s  model:%s  max-turns:%d  budget:%dtok",
		*listenAddr, activeProvider, activeModel, activeMaxTurns, activeTokenBudget)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>uwu.cpp</title>
<link href="https://fonts.googleapis.com/css2?family=Azeret+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#fff;--fg:#000;--muted:#888;--border:#e0e0e0;--hover:#f7f7f7;
  --accent:#000;--accent-fg:#fff;--danger:#d00;
  --mono:'Azeret Mono',monospace;
  --sidebar-w:220px;--act-w:260px;
}
html,body{height:100%;background:var(--bg);color:var(--fg);font-family:var(--mono);font-size:13px;overflow:hidden}
header{display:flex;align-items:center;justify-content:space-between;padding:0 14px 0 10px;height:46px;border-bottom:1px solid var(--border);position:fixed;top:0;left:0;right:0;background:var(--bg);z-index:200}
.logo{font-size:14px;font-weight:600;letter-spacing:-.02em;padding:0 4px}
.logo span{color:var(--muted);font-weight:300}
.hright{display:flex;align-items:center;gap:8px}
select{background:transparent;border:1px solid var(--border);color:var(--fg);font-family:var(--mono);font-size:11px;padding:3px 20px 3px 7px;cursor:pointer;outline:none;appearance:none;-webkit-appearance:none}
select:focus{border-color:#000}
.sel-wrap{position:relative;display:inline-flex;align-items:center}
.sel-wrap::after{content:'▾';position:absolute;right:6px;pointer-events:none;font-size:9px;color:var(--muted)}
.ibtn{background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:11px;padding:3px 8px;cursor:pointer;transition:all .15s;white-space:nowrap}
.ibtn:hover{border-color:#000;color:#000}
.ibtn.active{background:#000;color:#fff;border-color:#000}
.tools-toggle{background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:11px;padding:3px 8px;cursor:pointer;transition:all .15s;white-space:nowrap;display:flex;align-items:center;gap:5px}
.tools-toggle:hover{border-color:#000;color:#000}
.tools-toggle.enabled{border-color:#22c55e;color:#16a34a;background:#f0fdf4}
.tools-toggle.enabled:hover{border-color:#16a34a;background:#dcfce7}
.tools-toggle.disabled{border-color:#e0e0e0;color:var(--muted);background:var(--hover)}
.tools-toggle-dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}
.ping-badge{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--muted)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--muted)}
.dot.ok{background:#22c55e}.dot.err{background:#ef4444}
.dot.pinging{animation:pulse .8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.2}}
.ping-ms{font-variant-numeric:tabular-nums;min-width:40px}
.layout{display:flex;height:100vh;padding-top:46px}
.conv-sidebar{width:var(--sidebar-w);flex-shrink:0;border-right:1px solid var(--border);display:flex;flex-direction:column;background:var(--bg);z-index:100}
.conv-sidebar-hdr{padding:8px 10px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;flex-shrink:0}
.new-chat-btn{flex:1;background:#000;color:#fff;border:none;font-family:var(--mono);font-size:11px;font-weight:500;padding:6px 10px;cursor:pointer;transition:opacity .15s;text-align:left}
.new-chat-btn:hover{opacity:.75}
.conv-list{flex:1;overflow-y:auto;padding:4px 0}
.conv-list::-webkit-scrollbar{width:3px}
.conv-list::-webkit-scrollbar-thumb{background:var(--border)}
.conv-item{padding:7px 10px 7px 12px;cursor:pointer;display:flex;align-items:center;gap:6px;border-left:2px solid transparent;transition:background .1s;position:relative}
.conv-item:hover{background:var(--hover)}
.conv-item.active{border-left-color:#000;background:var(--hover)}
.conv-item-title{flex:1;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;line-height:1.4}
.conv-item-meta{font-size:9px;color:var(--muted);margin-top:1px}
.conv-del{opacity:0;background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:0 2px;line-height:1;flex-shrink:0}
.conv-item:hover .conv-del{opacity:1}
.conv-del:hover{color:var(--danger)}
.conv-empty{padding:16px 12px;font-size:11px;color:var(--muted);line-height:1.6}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
.msgs{flex:1;overflow-y:auto;padding:16px 0}
.msgs::-webkit-scrollbar{width:4px}
.msgs::-webkit-scrollbar-thumb{background:var(--border)}
.msg{padding:9px 20px;opacity:0;animation:fdIn .18s ease forwards}
@keyframes fdIn{to{opacity:1}}
.msg:hover{background:var(--hover)}
.msg-role{font-size:9px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:4px;display:flex;align-items:center;gap:6px}
.msg.user .msg-role{color:#000}
.msg-body{font-size:13px;line-height:1.75;white-space:pre-wrap;word-break:break-word}
.msg.user .msg-body{font-weight:500}
.msg.assistant .msg-body{color:#222}
.msg-body code{font-family:var(--mono);background:#f5f5f5;padding:1px 5px;font-size:12px}
.msg-body pre{background:#f5f5f5;padding:10px 12px;overflow-x:auto;margin:6px 0;font-size:12px;line-height:1.5}
.msg-body pre code{background:none;padding:0}
.msg-body strong{font-weight:600}
.file-chips{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
.fchip{font-size:10px;border:1px solid var(--border);padding:2px 8px;background:var(--hover);display:flex;align-items:center;gap:5px;cursor:pointer}
.fchip:hover{border-color:#000}
.fchip img{max-height:28px;max-width:50px}
.cursor{display:inline-block;width:7px;height:13px;background:#000;margin-left:1px;vertical-align:text-bottom;animation:blink .9s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.divider{padding:3px 20px;display:flex;align-items:center;gap:10px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
.divider span{font-size:10px;color:var(--muted)}
.empty-state{flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:6px;color:var(--muted);padding:40px}
.empty-state .big{font-size:15px;font-weight:600;color:#000}
.empty-state .sm{font-size:11px;text-align:center;line-height:1.7;max-width:320px}
.token-bar{display:flex;align-items:center;gap:10px;padding:4px 20px;font-size:10px;color:var(--muted);border-bottom:1px solid var(--border);background:var(--hover);flex-shrink:0;min-height:0;overflow:hidden;transition:all .2s}
.token-bar.hidden{padding:0 20px;min-height:0;height:0;border:none}
.tok-val{font-variant-numeric:tabular-nums;color:#000;font-weight:500}
.tok-budget-bar{flex:1;height:3px;background:var(--border);max-width:120px}
.tok-budget-fill{height:100%;background:#000;transition:width .3s}
.tok-budget-fill.warn{background:#f59e0b}
.tok-budget-fill.over{background:#ef4444}
.input-area{border-top:1px solid var(--border);padding:10px 20px;display:flex;flex-direction:column;gap:7px;flex-shrink:0}
.input-row{display:flex;gap:7px;align-items:flex-end}
.input-wrap{flex:1}
textarea{width:100%;background:transparent;border:1px solid var(--border);color:#000;font-family:var(--mono);font-size:13px;line-height:1.6;padding:8px 10px;resize:none;outline:none;min-height:38px;max-height:130px;overflow-y:auto;transition:border-color .15s}
textarea:focus{border-color:#000}
textarea::placeholder{color:var(--muted)}
textarea:disabled{opacity:.4;cursor:not-allowed}
.btn-row{display:flex;gap:5px;flex-shrink:0}
.send-btn{background:#000;color:#fff;border:none;font-family:var(--mono);font-size:12px;font-weight:500;padding:0 16px;cursor:pointer;height:38px;transition:opacity .15s}
.send-btn:hover{opacity:.75}
.send-btn:disabled{opacity:.3;cursor:not-allowed}
.attach-btn{background:transparent;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:16px;width:38px;height:38px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.attach-btn:hover{border-color:#000;color:#000}
#fileInput{display:none}
.hint-row{display:flex;align-items:center;gap:10px}
.hint{font-size:10px;color:var(--muted)}
.rate-indicator{font-size:10px;color:var(--muted);display:flex;align-items:center;gap:4px;margin-left:auto}
.rate-dot{width:5px;height:5px;border-radius:50%;background:#22c55e}
.rate-dot.wait{background:#f59e0b;animation:pulse .6s ease-in-out infinite}
.previews{display:flex;flex-wrap:wrap;gap:5px}
.prev-chip{font-size:11px;border:1px solid var(--border);padding:3px 9px;display:flex;align-items:center;gap:5px;background:var(--hover)}
.prev-chip img{max-height:28px;max-width:50px}
.prev-chip .rm{cursor:pointer;color:var(--muted);margin-left:2px}
.prev-chip .rm:hover{color:#000}
.aside{width:var(--act-w);flex-shrink:0;border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;transition:width .2s}
.aside.collapsed{width:0;border:none}
.panel-hdr{padding:8px 12px;font-size:9px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-shrink:0;white-space:nowrap}
.panel-hdr-btns{display:flex;gap:5px}
.phbtn{background:none;border:none;color:var(--muted);cursor:pointer;font-size:11px;padding:0 3px;line-height:1}
.phbtn:hover{color:#000}
.act-list{flex:1;overflow-y:auto;padding:3px 0}
.act-list::-webkit-scrollbar{width:0}
.act-item{padding:5px 10px;border-left:2px solid transparent;opacity:0;animation:slIn .15s ease forwards}
@keyframes slIn{from{opacity:0;transform:translateX(-3px)}to{opacity:1;transform:none}}
.act-item.tc{border-left-color:#000}.act-item.tr{border-left-color:#bbb}.act-item.aerr{border-left-color:#ef4444}
.act-tag{font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:1px}
.act-tag.bold{color:#000;font-weight:600}
.act-txt{font-size:10px;line-height:1.4;word-break:break-all;color:#444}
.act-txt.dim{color:var(--muted)}.act-txt.err{color:#ef4444}
.act-meta{font-size:9px;color:var(--muted);margin-top:1px;display:flex;gap:6px}
.act-ms{color:#000;font-weight:500}
.status-bar{padding:7px 10px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);display:flex;align-items:center;gap:6px;flex-shrink:0}
.spinner{display:none;width:7px;height:7px;border:1.5px solid #ddd;border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;flex-shrink:0}
.spinner.on{display:block}
@keyframes spin{to{transform:rotate(360deg)}}
.settings-panel{display:none;position:fixed;top:46px;right:0;bottom:0;width:300px;background:#fff;border-left:1px solid var(--border);z-index:150;flex-direction:column;overflow-y:auto}
.settings-panel.open{display:flex}
.settings-section{padding:14px 16px;border-bottom:1px solid var(--border)}
.settings-label{font-size:9px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:9px;display:flex;align-items:center;justify-content:space-between}
.settings-row{display:flex;flex-direction:column;gap:3px;margin-bottom:9px}
.settings-row label{font-size:10px;color:var(--muted)}
.settings-row input,.settings-row select,.settings-row textarea{width:100%;background:transparent;border:1px solid var(--border);color:#000;font-family:var(--mono);font-size:12px;padding:5px 8px;outline:none;transition:border-color .15s}
.settings-row textarea{resize:vertical;min-height:90px;line-height:1.5}
.settings-row input:focus,.settings-row select:focus,.settings-row textarea:focus{border-color:#000}
.settings-row select{appearance:none;-webkit-appearance:none;cursor:pointer}
.settings-row .hint{margin-top:2px}
.apply-btn{background:#000;color:#fff;border:none;font-family:var(--mono);font-size:11px;padding:7px 14px;cursor:pointer;width:100%;transition:opacity .15s}
.apply-btn:hover{opacity:.75}
.reset-link{font-size:10px;color:var(--muted);cursor:pointer;text-decoration:underline;margin-top:4px;display:inline-block}
.reset-link:hover{color:#000}
.range-row{display:flex;align-items:center;gap:8px}
.range-row input[type=range]{flex:1;accent-color:#000;cursor:pointer}
.range-val{font-size:11px;font-weight:500;min-width:28px;text-align:right}
.modules-grid{display:flex;flex-wrap:wrap;gap:5px;margin-top:4px}
.mod-chip{font-size:10px;border:1px solid var(--border);padding:3px 8px;cursor:pointer;background:var(--hover);transition:all .15s}
.mod-chip.on{background:#000;color:#fff;border-color:#000}
.mod-chip:hover{border-color:#000}
.tools-setting-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:9px}
.tools-setting-row label{font-size:10px;color:var(--muted)}
.toggle-switch{position:relative;width:36px;height:20px;cursor:pointer;flex-shrink:0}
.toggle-switch input{opacity:0;width:0;height:0;position:absolute}
.toggle-track{position:absolute;inset:0;background:var(--border);border-radius:10px;transition:background .2s}
.toggle-thumb{position:absolute;top:3px;left:3px;width:14px;height:14px;background:#fff;border-radius:50%;transition:transform .2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.toggle-switch input:checked + .toggle-track{background:#22c55e}
.toggle-switch input:checked ~ .toggle-thumb{transform:translateX(16px)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:#fff;width:680px;max-width:95vw;max-height:88vh;display:flex;flex-direction:column;border:1px solid var(--border)}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:12px 18px;border-bottom:1px solid var(--border);flex-shrink:0}
.modal-title{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.modal-close{background:none;border:none;cursor:pointer;font-size:18px;color:var(--muted);line-height:1}
.modal-close:hover{color:#000}
.modal-body{flex:1;overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:10px}
.file-entry{border:1px solid var(--border);padding:10px 14px;display:flex;align-items:flex-start;gap:12px}
.file-entry-info{flex:1;min-width:0}
.file-entry-name{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-entry-meta{font-size:10px;color:var(--muted);margin-top:2px}
.file-entry-preview{max-width:120px;max-height:80px;display:block;margin-top:6px;border:1px solid var(--border)}
.dl-btn{background:#000;color:#fff;border:none;font-family:var(--mono);font-size:10px;padding:4px 10px;cursor:pointer;white-space:nowrap}
.dl-btn:hover{opacity:.75}
.modal-empty{padding:32px;text-align:center;color:var(--muted);font-size:12px}
.tools-list{padding:4px 0;max-height:180px;overflow-y:auto}
.tool-item{padding:3px 10px;font-size:10px;color:var(--muted);display:flex;gap:6px}
.tool-item::before{content:'▸';flex-shrink:0}
.save-indicator{font-size:10px;color:#16a34a;margin-left:6px;opacity:0;transition:opacity .3s}
.save-indicator.show{opacity:1}
</style>
</head>
<body>

<header>
  <div style="display:flex;align-items:center;gap:8px">
    <div class="logo">uwu<span>.cpp</span></div>
    <div class="sel-wrap">
      <select id="provSel">
        <option value="gemini">gemini</option>
        <option value="anthropic">anthropic</option>
        <option value="openai">openai</option>
        <option value="openrouter">openrouter</option>
        <option value="ollama">ollama</option>
        <option value="custom">custom</option>
      </select>
    </div>
    <div class="sel-wrap">
      <select id="modelSel"><option value="">loading...</option></select>
    </div>
  </div>
  <div class="hright">
    <button class="tools-toggle enabled" id="toolsToggleBtn" title="Toggle MCP tools on/off">
      <span class="tools-toggle-dot"></span>
      <span id="toolsToggleTxt">tools on</span>
    </button>
    <button class="ibtn" id="settingsBtn">config</button>
    <button class="ibtn" id="filesBtn">files</button>
    <button class="ibtn" id="actToggleBtn">activity</button>
    <div class="ping-badge">
      <div class="dot pinging" id="pingDot"></div>
      <span class="ping-ms" id="pingMs">—</span>
    </div>
  </div>
</header>

<div class="layout">
  <div class="conv-sidebar">
    <div class="conv-sidebar-hdr">
      <button class="new-chat-btn" id="newChatBtn">+ new chat</button>
    </div>
    <div class="conv-list" id="convList">
      <div class="conv-empty">No conversations yet.<br>Start by sending a message.</div>
    </div>
  </div>

  <div class="main">
    <div class="token-bar hidden" id="tokenBar">
      <span>tokens:</span>
      <span>in <span class="tok-val" id="tokIn">0</span></span>
      <span>out <span class="tok-val" id="tokOut">0</span></span>
      <span>turn <span class="tok-val" id="tokTurn">0</span></span>
      <div class="tok-budget-bar" id="budgetBar" style="display:none">
        <div class="tok-budget-fill" id="budgetFill" style="width:0%"></div>
      </div>
      <span id="budgetTxt" style="display:none;color:var(--muted)"></span>
    </div>
    <div class="msgs" id="msgs">
      <div class="empty-state" id="emptyState">
        <div class="big">uwu agent</div>
        <div class="sm">Multi-provider AI agent with MCP tools.<br>Shell, filesystem, system, process, clipboard &amp; more.</div>
      </div>
    </div>
    <div class="input-area">
      <div class="previews" id="previews"></div>
      <div class="input-row">
        <div class="input-wrap">
          <textarea id="box" placeholder="ask agent to do something..." rows="1"></textarea>
        </div>
        <div class="btn-row">
          <button class="attach-btn" id="attachBtn" title="Attach file">+</button>
          <input type="file" id="fileInput" multiple accept="image/*,application/pdf,.txt,.csv,.json,.py,.go,.js,.ts,.md,.sh,.zip">
          <button class="send-btn" id="sendBtn">send</button>
        </div>
      </div>
      <div class="hint-row">
        <span class="hint">enter send · shift+enter newline · drag &amp; drop files</span>
        <div class="rate-indicator" id="rateIndicator">
          <div class="rate-dot" id="rateDot"></div>
          <span id="rateTxt">ready</span>
        </div>
      </div>
    </div>
  </div>

  <div class="aside" id="aside">
    <div class="panel-hdr">
      <span>activity</span>
      <div class="panel-hdr-btns">
        <button class="phbtn" id="clearActBtn" title="Clear">x</button>
      </div>
    </div>
    <div class="act-list" id="actList"></div>
    <div class="status-bar">
      <div class="spinner" id="spinner"></div>
      <span id="statusTxt">idle</span>
    </div>
  </div>
</div>

<div class="settings-panel" id="settingsPanel">
  <div class="settings-section">
    <div class="settings-label">provider config</div>
    <div class="settings-row">
      <label>provider</label>
      <select id="cfgProvider">
        <option value="gemini">gemini</option>
        <option value="anthropic">anthropic</option>
        <option value="openai">openai</option>
        <option value="openrouter">openrouter</option>
        <option value="ollama">ollama</option>
        <option value="custom">custom</option>
      </select>
    </div>
    <div class="settings-row">
      <label>api key</label>
      <input type="password" id="cfgKey" placeholder="sk-... or AIzaSy...">
    </div>
    <div class="settings-row">
      <label>base url (ollama/custom)</label>
      <input type="text" id="cfgBase" placeholder="http://localhost:11434">
    </div>
    <button class="apply-btn" id="applyConfig">apply provider</button>
  </div>

  <div class="settings-section">
    <div class="settings-label">system prompt</div>
    <div class="settings-row">
      <label>prompt sent before every conversation</label>
      <textarea id="cfgSystemPrompt" rows="5" placeholder="You are uwu-agent..."></textarea>
      <span class="reset-link" id="resetPromptBtn">reset to default</span>
    </div>
    <button class="apply-btn" id="applySystemPrompt">
      save system prompt
      <span class="save-indicator" id="promptSaveIndicator">✓ saved</span>
    </button>
  </div>

  <div class="settings-section">
    <div class="settings-label">request limits</div>
    <div class="settings-row">
      <label>max turns per request</label>
      <div class="range-row">
        <input type="range" id="cfgMaxTurns" min="1" max="30" value="12">
        <span class="range-val" id="cfgMaxTurnsVal">12</span>
      </div>
      <span class="hint">lower = fewer API calls</span>
    </div>
    <div class="settings-row">
      <label>token budget (0 = unlimited)</label>
      <input type="number" id="cfgBudget" placeholder="80000" min="0" step="10000">
      <span class="hint">stops agent if input tokens exceed this across all turns</span>
    </div>
    <button class="apply-btn" id="applyLimits">apply limits</button>
  </div>

  <div class="settings-section">
    <div class="settings-label">tools &amp; modules</div>
    <div class="tools-setting-row">
      <label>enable MCP tools</label>
      <label class="toggle-switch">
        <input type="checkbox" id="cfgToolsEnabled" checked>
        <div class="toggle-track"></div>
        <div class="toggle-thumb"></div>
      </label>
    </div>
    <div class="settings-row">
      <label>enabled modules (never includes 'ai')</label>
      <div class="modules-grid" id="modulesGrid">
        <div class="mod-chip on" data-mod="shell">shell</div>
        <div class="mod-chip on" data-mod="filesystem">filesystem</div>
        <div class="mod-chip on" data-mod="system">system</div>
        <div class="mod-chip on" data-mod="process">process</div>
        <div class="mod-chip on" data-mod="clipboard">clipboard</div>
        <div class="mod-chip on" data-mod="screen">screen</div>
        <div class="mod-chip on" data-mod="input">input</div>
      </div>
    </div>
    <button class="apply-btn" id="applyModules">refresh tools</button>
    <div class="tools-list" id="toolsList" style="margin-top:8px"></div>
  </div>

  <div class="settings-section">
    <div class="settings-label">info</div>
    <div id="cfgInfo" style="font-size:11px;color:var(--muted);line-height:1.8"></div>
  </div>
</div>

<div class="modal-overlay" id="fileModal">
  <div class="modal">
    <div class="modal-hdr">
      <span class="modal-title">uploaded files</span>
      <button class="modal-close" id="closeModal">x</button>
    </div>
    <div class="modal-body" id="modalBody">
      <div class="modal-empty">no files uploaded yet</div>
    </div>
  </div>
</div>

<script>
var busy = false;
var attachedFiles = [];
var sessionFiles = [];
var conversations = [];
var activeConvId = null;
var tokenStats = {in:0, out:0, turn:0};
var tokenBudget = 80000;
var toolsEnabled = true;
var currentSystemPrompt = 'You are uwu-agent. Use MCP tools to execute tasks on this Linux machine. Be concise and efficient.';
var DEFAULT_SYSTEM_PROMPT = currentSystemPrompt;

var CONV_KEY = 'uwu_conversations';
var CONV_MAX = 50;

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function nowStr(){ return new Date().toTimeString().slice(0,8) }
function genId(){ return Date.now().toString(36)+Math.random().toString(36).slice(2,6) }

function setStatus(t, loading){
  document.getElementById('statusTxt').textContent = t;
  document.getElementById('spinner').className = 'spinner'+(loading?' on':'');
}

function renderMd(text){
  var h = esc(text);
  h = h.replace(/\x60\x60\x60[\w]*\n?([\s\S]*?)\x60\x60\x60/g, function(_,c){return '<pre><code>'+c+'</code></pre>';});
  h = h.replace(/\x60([^\x60]+)\x60/g, '<code>$1</code>');
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  return h;
}

function updateToolsToggleUI(){
  var btn = document.getElementById('toolsToggleBtn');
  var txt = document.getElementById('toolsToggleTxt');
  var cfgChk = document.getElementById('cfgToolsEnabled');
  if(toolsEnabled){
    btn.className = 'tools-toggle enabled';
    txt.textContent = 'tools on';
  } else {
    btn.className = 'tools-toggle disabled';
    txt.textContent = 'tools off';
  }
  cfgChk.checked = toolsEnabled;
}

async function setToolsEnabled(val){
  toolsEnabled = val;
  updateToolsToggleUI();
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({tools_enabled: val})});
  addAct('activity',null,'tools '+(val?'enabled':'disabled'),{ts:nowStr()});
}

document.getElementById('toolsToggleBtn').addEventListener('click', function(){
  setToolsEnabled(!toolsEnabled);
});

document.getElementById('cfgToolsEnabled').addEventListener('change', function(){
  setToolsEnabled(this.checked);
});

// ── System prompt handlers ───────────────────────────────────────────────

document.getElementById('applySystemPrompt').addEventListener('click', async function(){
  var prompt = document.getElementById('cfgSystemPrompt').value.trim();
  var resp = await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({system_prompt: prompt})});
  var d = await resp.json();
  currentSystemPrompt = d.system_prompt || DEFAULT_SYSTEM_PROMPT;
  document.getElementById('cfgSystemPrompt').value = currentSystemPrompt;
  var ind = document.getElementById('promptSaveIndicator');
  ind.classList.add('show');
  setTimeout(function(){ ind.classList.remove('show'); }, 2000);
  addAct('activity',null,'system prompt updated · saved to config.yml',{ts:nowStr()});
});

document.getElementById('resetPromptBtn').addEventListener('click', function(){
  document.getElementById('cfgSystemPrompt').value = DEFAULT_SYSTEM_PROMPT;
});

// ─────────────────────────────────────────────────────────────────────────

function loadConversations(){
  try{
    var raw = localStorage.getItem(CONV_KEY);
    if(raw) conversations = JSON.parse(raw);
  }catch(e){ conversations = []; }
  renderConvList();
  if(conversations.length > 0){
    loadConversation(conversations[0].id);
  }
}

function saveConversations(){
  if(conversations.length > CONV_MAX) conversations = conversations.slice(0, CONV_MAX);
  try{ localStorage.setItem(CONV_KEY, JSON.stringify(conversations)); }catch(e){}
}

function createNewConversation(){
  var conv = {id:genId(), title:'New chat', messages:[], created:Date.now()};
  conversations.unshift(conv);
  saveConversations();
  loadConversation(conv.id);
  renderConvList();
  document.getElementById('box').focus();
}

function loadConversation(id){
  activeConvId = id;
  var conv = conversations.find(function(c){return c.id===id;});
  if(!conv) return;

  var msgsEl = document.getElementById('msgs');
  msgsEl.innerHTML = '';
  var emptyEl = document.createElement('div');
  emptyEl.className = 'empty-state';
  emptyEl.id = 'emptyState';
  emptyEl.innerHTML = '<div class="big">uwu agent</div><div class="sm">Multi-provider AI agent with MCP tools.<br>Shell, filesystem, system, process, clipboard &amp; more.</div>';

  if(conv.messages.length === 0){
    msgsEl.appendChild(emptyEl);
  } else {
    conv.messages.forEach(function(m, i){
      if(i>0 && m.role==='user'){
        var d=document.createElement('div');d.className='divider';d.innerHTML='<span>· · ·</span>';msgsEl.appendChild(d);
      }
      var el=document.createElement('div');
      el.className='msg '+(m.role==='user'?'user':'assistant');
      el.innerHTML='<div class="msg-role">'+m.role+'</div><div class="msg-body"></div>';
      if(m.role==='assistant'){
        el.querySelector('.msg-body').innerHTML = renderMd(m.text||'');
      } else {
        el.querySelector('.msg-body').textContent = m.text||'';
      }
      if(m.files && m.files.length){
        var wrapEl=document.createElement('div');wrapEl.className='file-chips';
        m.files.forEach(function(f){
          var chip=document.createElement('div');chip.className='fchip';
          chip.title='click to view files';
          if(f.dataURL&&f.mime&&f.mime.startsWith('image/')){
            chip.innerHTML='<img src="'+f.dataURL+'"><span>'+esc(f.name)+'</span>';
          }else{
            chip.innerHTML='[file] <span>'+esc(f.name)+'</span>';
          }
          chip.addEventListener('click',openFileModal);
          wrapEl.appendChild(chip);
        });
        el.appendChild(wrapEl);
      }
      msgsEl.appendChild(el);
    });
  }

  renderConvList();
  msgsEl.scrollTop = 9999;
  tokenStats = {in:0,out:0,turn:0};
  updateTokenBar(false);
}

function addMessageToConv(role, text, files){
  var conv = conversations.find(function(c){return c.id===activeConvId;});
  if(!conv) return;
  conv.messages.push({role:role, text:text, files:files||[]});
  if(role==='user' && conv.messages.filter(function(m){return m.role==='user';}).length===1){
    conv.title = text.slice(0,40)||(files&&files.length?'[file upload]':'New chat');
  }
  conv.updated = Date.now();
  var idx = conversations.findIndex(function(c){return c.id===activeConvId;});
  if(idx>0){ var removed=conversations.splice(idx,1); conversations.unshift(removed[0]); }
  saveConversations();
  renderConvList();
}

function deleteConversation(id){
  conversations = conversations.filter(function(c){return c.id!==id;});
  saveConversations();
  if(activeConvId===id){
    activeConvId=null;
    if(conversations.length>0){ loadConversation(conversations[0].id); }
    else { createNewConversation(); return; }
  }
  renderConvList();
}

function renderConvList(){
  var list = document.getElementById('convList');
  if(conversations.length===0){
    list.innerHTML='<div class="conv-empty">No conversations yet.<br>Start by sending a message.</div>';
    return;
  }
  list.innerHTML='';
  conversations.forEach(function(conv){
    var el=document.createElement('div');
    el.className='conv-item'+(conv.id===activeConvId?' active':'');
    var d=new Date(conv.updated||conv.created);
    var meta=d.toLocaleDateString(undefined,{month:'short',day:'numeric'});
    el.innerHTML=
      '<div style="flex:1;min-width:0"><div class="conv-item-title">'+esc(conv.title)+'</div>'+
      '<div class="conv-item-meta">'+esc(meta)+' · '+conv.messages.length+' msgs</div></div>'+
      '<button class="conv-del" data-id="'+conv.id+'" title="Delete">x</button>';
    el.addEventListener('click',function(e){
      if(e.target.classList.contains('conv-del')) return;
      if(!busy) loadConversation(conv.id);
    });
    el.querySelector('.conv-del').addEventListener('click',function(e){
      e.stopPropagation();
      if(confirm('Delete this conversation?')) deleteConversation(conv.id);
    });
    list.appendChild(el);
  });
}

function updateTokenBar(show){
  var bar=document.getElementById('tokenBar');
  if(!show){ bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  document.getElementById('tokIn').textContent = tokenStats.in.toLocaleString();
  document.getElementById('tokOut').textContent = tokenStats.out.toLocaleString();
  document.getElementById('tokTurn').textContent = tokenStats.turn;
  var budgetBar=document.getElementById('budgetBar');
  var budgetFill=document.getElementById('budgetFill');
  var budgetTxt=document.getElementById('budgetTxt');
  if(tokenBudget>0){
    budgetBar.style.display='block';budgetTxt.style.display='block';
    var pct=Math.min(100,Math.round(tokenStats.in/tokenBudget*100));
    budgetFill.style.width=pct+'%';
    budgetFill.className='tok-budget-fill'+(pct>90?' over':pct>70?' warn':'');
    budgetTxt.textContent=pct+'% of '+Math.round(tokenBudget/1000)+'k';
  } else {
    budgetBar.style.display='none';budgetTxt.style.display='none';
  }
}

async function ping(){
  document.getElementById('pingDot').className='dot pinging';
  try{
    var r=await fetch('/api/ping');
    var d=await r.json();
    document.getElementById('pingDot').className='dot '+(d.ok?'ok':'err');
    document.getElementById('pingMs').textContent=d.ok?d.ms+' ms':'offline';
    if(d.info){
      tokenBudget = d.info.token_budget||0;
      if(d.info.tools_enabled !== undefined && d.info.tools_enabled !== toolsEnabled){
        toolsEnabled = d.info.tools_enabled;
        updateToolsToggleUI();
      }
      // sync system prompt from server
      if(d.info.system_prompt && d.info.system_prompt !== currentSystemPrompt){
        currentSystemPrompt = d.info.system_prompt;
        document.getElementById('cfgSystemPrompt').value = currentSystemPrompt;
      }
      document.getElementById('cfgInfo').innerHTML=
        'provider: '+esc(d.info.provider)+'<br>model: '+esc(d.info.model)+
        '<br>tools: '+d.info.tools+
        '<br>tools enabled: '+(d.info.tools_enabled?'yes':'no')+
        '<br>max turns: '+d.info.max_turns+
        '<br>token budget: '+(d.info.token_budget?Math.round(d.info.token_budget/1000)+'k':'unlimited')+
        '<br>config: config.yml';
      document.getElementById('cfgMaxTurns').value=d.info.max_turns;
      document.getElementById('cfgMaxTurnsVal').textContent=d.info.max_turns;
      if(d.info.token_budget) document.getElementById('cfgBudget').value=d.info.token_budget;
      if(!busy) setStatus(d.info.tools+' tools · idle',false);
    }
  }catch(e){
    document.getElementById('pingDot').className='dot err';
    document.getElementById('pingMs').textContent='offline';
  }
}
ping(); setInterval(ping,10000);

async function loadModels(){
  try{
    var r=await fetch('/api/models');
    var d=await r.json();
    var sel=document.getElementById('modelSel');
    sel.innerHTML='';
    (d.models||[]).forEach(function(m){
      var o=document.createElement('option');
      o.value=m.id;o.textContent=m.id;
      if(m.id===d.current)o.selected=true;
      sel.appendChild(o);
    });
    if(d.provider){
      document.getElementById('provSel').value=d.provider;
      document.getElementById('cfgProvider').value=d.provider;
    }
  }catch(e){console.error(e);}
}

document.getElementById('provSel').addEventListener('change',async function(){
  var p=this.value;
  document.getElementById('cfgProvider').value=p;
  await applyProviderChange(p,'','');
  await loadModels();
});
document.getElementById('modelSel').addEventListener('change',async function(){
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:this.value})});
});

async function applyProviderChange(prov,key,baseUrl){
  var body={provider:prov,model:providerDefault(prov)};
  if(key)body.api_key=key;
  if(baseUrl)body.base_url=baseUrl;
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
}
function providerDefault(p){
  var m={gemini:'gemini-2.0-flash',anthropic:'claude-sonnet-4-5',openai:'gpt-4o',
         openrouter:'anthropic/claude-sonnet-4-5',ollama:'llama3.3'};
  return m[p]||'';
}

document.getElementById('settingsBtn').addEventListener('click',function(){
  var p=document.getElementById('settingsPanel');
  var open=!p.classList.contains('open');
  p.classList.toggle('open',open);
  document.getElementById('settingsBtn').classList.toggle('active',open);
  // populate system prompt field when opening
  if(open){
    document.getElementById('cfgSystemPrompt').value = currentSystemPrompt;
  }
});

document.getElementById('applyConfig').addEventListener('click',async function(){
  var prov=document.getElementById('cfgProvider').value;
  var key=document.getElementById('cfgKey').value.trim();
  var base=document.getElementById('cfgBase').value.trim();
  await applyProviderChange(prov,key,base);
  document.getElementById('provSel').value=prov;
  addAct('activity',null,'switched to '+prov+' · saved to config.yml',{ts:nowStr()});
  await loadModels();
});

document.getElementById('cfgMaxTurns').addEventListener('input',function(){
  document.getElementById('cfgMaxTurnsVal').textContent=this.value;
});

document.getElementById('applyLimits').addEventListener('click',async function(){
  var turns=parseInt(document.getElementById('cfgMaxTurns').value)||12;
  var budget=parseInt(document.getElementById('cfgBudget').value)||0;
  tokenBudget=budget;
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({max_turns:turns,token_budget:budget})});
  addAct('activity',null,'limits: '+turns+' turns, budget '+(budget?Math.round(budget/1000)+'k':'unlimited')+' · saved to config.yml',{ts:nowStr()});
});

document.querySelectorAll('.mod-chip').forEach(function(chip){
  chip.addEventListener('click',function(){
    if(chip.dataset.mod==='ai'){chip.classList.remove('on');return;}
    chip.classList.toggle('on');
  });
});

document.getElementById('applyModules').addEventListener('click',async function(){
  var r=await fetch('/api/refresh-tools',{method:'POST'});
  var d=await r.json();
  if(d.error){addAct('aerr',null,'error: '+d.error,{ts:nowStr()});}
  else{
    addAct('activity',null,d.tools+' tools loaded',{ts:nowStr()});
    setStatus(d.tools+' tools · idle',false);
    renderToolsList(d.names||[]);
  }
});

function renderToolsList(names){
  var el=document.getElementById('toolsList');
  el.innerHTML='';
  names.forEach(function(n){
    var d=document.createElement('div');d.className='tool-item';d.textContent=n;el.appendChild(d);
  });
}

document.getElementById('actToggleBtn').addEventListener('click',function(){
  var aside=document.getElementById('aside');
  var collapsed=aside.classList.toggle('collapsed');
  document.getElementById('actToggleBtn').classList.toggle('active',!collapsed);
});
document.getElementById('clearActBtn').addEventListener('click',function(){
  document.getElementById('actList').innerHTML='';
});

function addAct(type,label,text,meta){
  var list=document.getElementById('actList');
  var el=document.createElement('div');
  var cls=type==='tool_call'?'tc':type==='tool_result'?'tr':type==='aerr'?'aerr':'';
  el.className='act-item '+cls;
  var tagCls=type==='tool_call'?'act-tag bold':'act-tag';
  var txtCls=type==='aerr'?'act-txt err':'act-txt';
  el.innerHTML=(label?'<div class="'+tagCls+'">'+esc(label)+'</div>':'')+
    '<div class="'+txtCls+'">'+esc(text||'')+'</div>'+
    (meta?'<div class="act-meta">'+(meta.ts?'<span>'+meta.ts+'</span>':'')+
    (meta.ms!==undefined?'<span class="act-ms">'+meta.ms+'ms</span>':'')+'</div>':'');
  list.appendChild(el);
  list.scrollTop=list.scrollHeight;
}

document.getElementById('filesBtn').addEventListener('click',openFileModal);
document.getElementById('closeModal').addEventListener('click',function(){document.getElementById('fileModal').classList.remove('open');});
document.getElementById('fileModal').addEventListener('click',function(e){if(e.target===document.getElementById('fileModal'))document.getElementById('fileModal').classList.remove('open');});

function openFileModal(){
  var modal=document.getElementById('fileModal');
  var body=document.getElementById('modalBody');
  modal.classList.add('open');
  if(sessionFiles.length===0){body.innerHTML='<div class="modal-empty">no files uploaded yet</div>';return;}
  body.innerHTML='';
  sessionFiles.forEach(function(f,i){
    var entry=document.createElement('div');entry.className='file-entry';
    var sizeKB=f.size?Math.round(f.size/1024):'?';
    var prevHTML='';
    if(f.dataURL&&f.mime&&f.mime.startsWith('image/')){
      prevHTML='<img class="file-entry-preview" src="'+f.dataURL+'">';
    }
    entry.innerHTML='<div class="file-entry-info"><div class="file-entry-name">'+esc(f.name)+'</div>'+
      '<div class="file-entry-meta">'+esc(f.mime||'unknown')+' · '+sizeKB+' KB</div>'+prevHTML+'</div>'+
      '<div><button class="dl-btn" data-idx="'+f.serverIndex+'">download</button></div>';
    body.appendChild(entry);
  });
  body.querySelectorAll('.dl-btn').forEach(function(btn){
    btn.addEventListener('click',function(){window.open('/api/files/'+btn.dataset.idx,'_blank');});
  });
}

document.getElementById('attachBtn').addEventListener('click',function(){document.getElementById('fileInput').click();});
document.getElementById('fileInput').addEventListener('change',function(){
  for(var i=0;i<this.files.length;i++)addAttach(this.files[i]);this.value='';
});
function addAttach(file){attachedFiles.push(file);renderPreviews();}
function renderPreviews(){
  var wrap=document.getElementById('previews');wrap.innerHTML='';
  attachedFiles.forEach(function(f,i){
    var chip=document.createElement('div');chip.className='prev-chip';
    if(f.type.startsWith('image/')){
      var url=URL.createObjectURL(f);
      chip.innerHTML='<img src="'+url+'"><span>'+esc(f.name)+'</span><span class="rm" data-i="'+i+'">x</span>';
    }else{
      chip.innerHTML='<span>[file]</span><span>'+esc(f.name)+'</span><span class="rm" data-i="'+i+'">x</span>';
    }
    wrap.appendChild(chip);
  });
  wrap.querySelectorAll('.rm').forEach(function(btn){
    btn.addEventListener('click',function(){attachedFiles.splice(+btn.dataset.i,1);renderPreviews();});
  });
}

var box=document.getElementById('box');
box.addEventListener('dragover',function(e){e.preventDefault();box.style.borderColor='#000';});
box.addEventListener('dragleave',function(){box.style.borderColor='';});
box.addEventListener('drop',function(e){e.preventDefault();box.style.borderColor='';for(var i=0;i<e.dataTransfer.files.length;i++)addAttach(e.dataTransfer.files[i]);});

document.getElementById('newChatBtn').addEventListener('click',function(){
  if(busy)return;
  createNewConversation();
});

async function send(){
  if(busy)return;
  var prompt=box.value.trim();
  if(!prompt&&attachedFiles.length===0)return;

  if(!activeConvId||!conversations.find(function(c){return c.id===activeConvId;})){
    createNewConversation();
    await new Promise(function(r){setTimeout(r,10);});
  }

  busy=true;box.disabled=true;document.getElementById('sendBtn').disabled=true;
  var sentFiles=attachedFiles.slice();
  attachedFiles=[];renderPreviews();
  box.value='';box.style.height='auto';

  document.getElementById('rateDot').className='rate-dot wait';
  document.getElementById('rateTxt').textContent='waiting...';

  var fileInfos=await Promise.all(sentFiles.map(function(f){
    return new Promise(function(res){
      var fr=new FileReader();
      fr.onload=function(){res({name:f.name,mime:f.type,size:f.size,dataURL:fr.result,file:f});};
      fr.readAsDataURL(f);
    });
  }));

  var serverIndexStart=sessionFiles.length;
  fileInfos.forEach(function(fi,i){sessionFiles.push(Object.assign({},fi,{serverIndex:serverIndexStart+i}));});

  var empty=document.getElementById('emptyState');
  if(empty)empty.remove();
  var msgs=document.getElementById('msgs');
  var msgCount=msgs.querySelectorAll('.msg').length;
  if(msgCount>0){
    var sep=document.createElement('div');sep.className='divider';sep.innerHTML='<span>· · ·</span>';msgs.appendChild(sep);
  }
  var userEl=document.createElement('div');
  userEl.className='msg user';
  userEl.innerHTML='<div class="msg-role">user</div><div class="msg-body"></div>';
  userEl.querySelector('.msg-body').textContent=prompt||(sentFiles.length?'[files]':'');
  if(fileInfos.length){
    var wrapEl=document.createElement('div');wrapEl.className='file-chips';
    fileInfos.forEach(function(fi){
      var chip=document.createElement('div');chip.className='fchip';chip.title='click to view';
      if(fi.mime&&fi.mime.startsWith('image/'))chip.innerHTML='<img src="'+fi.dataURL+'"><span>'+esc(fi.name)+'</span>';
      else chip.innerHTML='[file] <span>'+esc(fi.name)+'</span>';
      chip.addEventListener('click',openFileModal);
      wrapEl.appendChild(chip);
    });
    userEl.appendChild(wrapEl);
  }
  msgs.appendChild(userEl);

  addMessageToConv('user',prompt||(sentFiles.length?'[files]':''),fileInfos.map(function(f){return {name:f.name,mime:f.mime,dataURL:f.dataURL};}));

  addAct('activity',null,'→ '+(prompt||'file').slice(0,60),{ts:nowStr()});
  setStatus('thinking...',true);

  var aiEl=document.createElement('div');
  aiEl.className='msg assistant thinking';
  aiEl.innerHTML='<div class="msg-role">assistant</div><div class="msg-body"><span class="cursor"></span></div>';
  msgs.appendChild(aiEl);
  msgs.scrollTop=9999;

  tokenStats={in:0,out:0,turn:0};
  updateTokenBar(true);

  var fd=new FormData();
  fd.append('prompt',prompt);
  fd.append('model',document.getElementById('modelSel').value||'');
  fd.append('max_turns',document.getElementById('cfgMaxTurns').value||'12');
  sentFiles.forEach(function(f){fd.append('file',f,f.name);});

  var replyText='';

  try{
    var resp=await fetch('/api/send',{method:'POST',body:fd});
    document.getElementById('rateDot').className='rate-dot';
    document.getElementById('rateTxt').textContent='active';
    var reader=resp.body.getReader();
    var dec=new TextDecoder();
    var buf='',evType=null;

    while(true){
      var chunk=await reader.read();
      if(chunk.done)break;
      buf+=dec.decode(chunk.value,{stream:true});
      var lines=buf.split('\n');buf=lines.pop();
      for(var i=0;i<lines.length;i++){
        var line=lines[i];
        if(line.startsWith('event: ')){evType=line.slice(7).trim();}
        else if(line.startsWith('data: ')&&evType){
          var d;try{d=JSON.parse(line.slice(6));}catch(e){evType=null;continue;}

          if(evType==='activity'){
            addAct('activity',null,d.text,{ts:d.ts});
            setStatus(d.text,true);
          }
          else if(evType==='tokens'){
            tokenStats={in:d.in,out:d.out,turn:d.turn};
            updateTokenBar(true);
          }
          else if(evType==='tool_call'){
            addAct('tool_call','tool: '+d.name,d.args,{ts:d.ts});
            setStatus('tool: '+d.name+'...',true);
          }
          else if(evType==='tool_result'){
            addAct('tool_result','result: '+d.name,d.result,{ts:d.ts,ms:d.ms});
          }
          else if(evType==='thinking'){
            addAct('activity',null,'thinking: '+String(d).slice(0,80),{ts:nowStr()});
          }
          else if(evType==='reply'){
            replyText=d;
            aiEl.className='msg assistant';
            aiEl.querySelector('.msg-body').innerHTML=renderMd(d);
            setStatus('done',false);
            msgs.scrollTop=9999;
          }
          else if(evType==='error'){
            aiEl.className='msg assistant';
            aiEl.querySelector('.msg-body').innerHTML='<span style="color:#ef4444">[ error: '+esc(String(d))+' ]</span>';
            addAct('aerr',null,'error: '+String(d),{ts:nowStr()});
            setStatus('error',false);
            replyText='[error: '+String(d)+']';
          }
          else if(evType==='done'){
            document.getElementById('rateDot').className='rate-dot';
            document.getElementById('rateTxt').textContent='ready';
          }
          evType=null;
        }
      }
    }
  }catch(e){
    aiEl.querySelector('.msg-body').innerHTML='<span style="color:#ef4444">[ connection error ]</span>';
    setStatus('error',false);
    replyText='[connection error]';
  }

  if(replyText) addMessageToConv('assistant',replyText,[]);

  busy=false;box.disabled=false;document.getElementById('sendBtn').disabled=false;
  document.getElementById('rateDot').className='rate-dot';
  document.getElementById('rateTxt').textContent='ready';
  box.focus();
}

box.addEventListener('input',function(){this.style.height='auto';this.style.height=Math.min(this.scrollHeight,130)+'px';});
box.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
document.getElementById('sendBtn').addEventListener('click',send);

loadConversations();
loadModels();
box.focus();
</script>
</body>
</html>`