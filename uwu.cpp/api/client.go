
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"uwu.cpp/config"
)

// Message is a standard chat message
type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// CompletionRequest is a provider-agnostic request
type CompletionRequest struct {
	Messages    []Message
	System      string
	MaxTokens   int
	Temperature float64
	Stream      bool
}

// CompletionResponse is the parsed result
type CompletionResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
	Model        string
	StopReason   string
}

// Client is the unified AI client
type Client struct {
	cfg    *config.Config
	http   *http.Client
}

// New creates a new AI client from config
func New(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: time.Duration(cfg.AI.TimeoutSecs) * time.Second,
		},
	}
}

// Complete sends a completion request to the configured provider
func (c *Client) Complete(req CompletionRequest) (*CompletionResponse, error) {
	switch c.cfg.AI.Provider {
	case "anthropic":
		return c.anthropicComplete(req)
	case "openai":
		return c.openAIComplete(req, "https://api.openai.com/v1/chat/completions")
	case "openrouter":
		return c.openAIComplete(req, "https://openrouter.ai/api/v1/chat/completions")
	case "gemini":
		return c.geminiComplete(req)
	case "ollama":
		base := c.cfg.ResolvedBaseURL()
		if base == "" {
			base = "http://localhost:11434"
		}
		return c.openAIComplete(req, base+"/v1/chat/completions")
	case "custom":
		base := c.cfg.ResolvedBaseURL()
		if base == "" {
			return nil, fmt.Errorf("custom provider requires base_url in config")
		}
		return c.openAIComplete(req, base+"/v1/chat/completions")
	default:
		return nil, fmt.Errorf("unknown provider: %s", c.cfg.AI.Provider)
	}
}

// ─── ANTHROPIC ───────────────────────────────────────────────────────────────

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) anthropicComplete(req CompletionRequest) (*CompletionResponse, error) {
	msgs := make([]anthropicMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			continue // system goes in top-level field
		}
		msgs = append(msgs, anthropicMessage{Role: m.Role, Content: m.Content})
	}

	// merge system from request.System + any system messages
	systemText := req.System
	for _, m := range req.Messages {
		if m.Role == "system" {
			systemText = m.Content
			break
		}
	}

	body := anthropicRequest{
		Model:       c.cfg.AI.Model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		System:      systemText,
		Messages:    msgs,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.cfg.GetAPIKey())
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	var ar anthropicResponse
	if err := json.Unmarshal(rawBody, &ar); err != nil {
		return nil, fmt.Errorf("parse anthropic response: %w\nbody: %s", err, string(rawBody))
	}
	if ar.Error != nil {
		return nil, fmt.Errorf("anthropic error [%s]: %s", ar.Error.Type, ar.Error.Message)
	}

	text := ""
	for _, block := range ar.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}

	return &CompletionResponse{
		Content:      text,
		InputTokens:  ar.Usage.InputTokens,
		OutputTokens: ar.Usage.OutputTokens,
		Model:        ar.Model,
		StopReason:   ar.StopReason,
	}, nil
}

// ─── OPENAI-COMPATIBLE (OpenAI, OpenRouter, Ollama, custom) ──────────────────

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature"`
	Stream      bool            `json:"stream"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	ID    string `json:"id"`
	Model string `json:"model"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func (c *Client) openAIComplete(req CompletionRequest, endpoint string) (*CompletionResponse, error) {
	msgs := make([]openAIMessage, 0, len(req.Messages)+1)

	// Inject system prompt
	if req.System != "" {
		msgs = append(msgs, openAIMessage{Role: "system", Content: req.System})
	}

	for _, m := range req.Messages {
		msgs = append(msgs, openAIMessage{Role: m.Role, Content: m.Content})
	}

	body := openAIRequest{
		Model:       c.cfg.AI.Model,
		Messages:    msgs,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Stream:      false,
	}

	data, _ := json.Marshal(body)
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.GetAPIKey())

	// OpenRouter extras
	if c.cfg.AI.Provider == "openrouter" {
		if c.cfg.AI.OpenRouterSiteURL != "" {
			httpReq.Header.Set("HTTP-Referer", c.cfg.AI.OpenRouterSiteURL)
		}
		if c.cfg.AI.OpenRouterSiteName != "" {
			httpReq.Header.Set("X-Title", c.cfg.AI.OpenRouterSiteName)
		}
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	var or openAIResponse
	if err := json.Unmarshal(rawBody, &or); err != nil {
		return nil, fmt.Errorf("parse response: %w\nbody: %s", err, string(rawBody))
	}
	if or.Error != nil {
		return nil, fmt.Errorf("api error [%s]: %s", or.Error.Type, or.Error.Message)
	}
	if len(or.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response\nbody: %s", string(rawBody))
	}

	return &CompletionResponse{
		Content:      or.Choices[0].Message.Content,
		InputTokens:  or.Usage.PromptTokens,
		OutputTokens: or.Usage.CompletionTokens,
		Model:        or.Model,
		StopReason:   or.Choices[0].FinishReason,
	}, nil
}

// ─── GEMINI ───────────────────────────────────────────────────────────────────

type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent        `json:"systemInstruction,omitempty"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig"`
}

type geminiContent struct {
	Role  string        `json:"role,omitempty"`
	Parts []geminiPart  `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
	Temperature     float64 `json:"temperature"`
}

type geminiResponse struct {
	Candidates []struct {
		Content       geminiContent `json:"content"`
		FinishReason  string        `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

func (c *Client) geminiComplete(req CompletionRequest) (*CompletionResponse, error) {
	var contents []geminiContent
	for _, m := range req.Messages {
		if m.Role == "system" {
			continue
		}
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, geminiContent{
			Role:  role,
			Parts: []geminiPart{{Text: m.Content}},
		})
	}

	body := geminiRequest{
		Contents: contents,
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: req.MaxTokens,
			Temperature:     req.Temperature,
		},
	}

	// System instruction
	sysText := req.System
	for _, m := range req.Messages {
		if m.Role == "system" {
			sysText = m.Content
			break
		}
	}
	if sysText != "" {
		body.SystemInstruction = &geminiContent{
			Parts: []geminiPart{{Text: sysText}},
		}
	}

	data, _ := json.Marshal(body)

	model := c.cfg.AI.Model
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		model, c.cfg.GetAPIKey())

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)

	var gr geminiResponse
	if err := json.Unmarshal(rawBody, &gr); err != nil {
		return nil, fmt.Errorf("parse gemini response: %w", err)
	}
	if gr.Error != nil {
		return nil, fmt.Errorf("gemini error [%s]: %s", gr.Error.Status, gr.Error.Message)
	}
	if len(gr.Candidates) == 0 {
		return nil, fmt.Errorf("no candidates in gemini response")
	}

	var parts []string
	for _, p := range gr.Candidates[0].Content.Parts {
		parts = append(parts, p.Text)
	}

	return &CompletionResponse{
		Content:      strings.Join(parts, ""),
		InputTokens:  gr.UsageMetadata.PromptTokenCount,
		OutputTokens: gr.UsageMetadata.CandidatesTokenCount,
		Model:        model,
		StopReason:   gr.Candidates[0].FinishReason,
	}, nil
}

// ─── UTILS ────────────────────────────────────────────────────────────────────

// ListModels returns known models for a provider (for reference)
func ListModels(provider string) []string {
	if models, ok := config.KnownModels[provider]; ok {
		return models
	}
	return nil
}

// ValidateConfig checks if the AI config looks correct
func ValidateConfig(cfg *config.Config) error {
	if cfg.AI.Provider == "" {
		return fmt.Errorf("ai.provider is required")
	}
	if cfg.AI.Provider != "ollama" && cfg.GetAPIKey() == "" {
		return fmt.Errorf("api_key is required for provider %s (or set UWU_API_KEY env)", cfg.AI.Provider)
	}
	if cfg.AI.Model == "" {
		return fmt.Errorf("ai.model is required")
	}
	if cfg.AI.MaxTokens == 0 {
		return fmt.Errorf("ai.max_tokens must be > 0")
	}
	return nil
}
