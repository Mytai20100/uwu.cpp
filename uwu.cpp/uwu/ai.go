package uwu

import (
	"fmt"
	"strings"

	"uwu.cpp/api"
	"uwu.cpp/config"
)

type aiModule struct {
	cfg    *config.Config
	client *api.Client
}

func newAIModule(cfg *config.Config) Module {
	return &aiModule{cfg: cfg}
}

func (m *aiModule) Name() string          { return "ai" }
func (m *aiModule) Description() string   { return "Call AI models: anthropic, openai, openrouter, gemini, ollama" }
func (m *aiModule) SupportedOS() []string { return nil }
func (m *aiModule) Shutdown() error       { return nil }

func (m *aiModule) Init(cfg *config.Config) error {
	m.cfg = cfg
	m.client = api.New(cfg)
	return nil
}

func (m *aiModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "ai_complete",
			Description: "Send a prompt to the configured AI model and get a response",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"prompt":      schemaStr("User message to send to the AI"),
				"system":      schemaStr("Override system prompt for this call"),
				"model":       schemaStr("Override model for this call (optional)"),
				"max_tokens":  schemaNum("Max output tokens (default from config)"),
				"temperature": schemaNum("Temperature 0-1 (default from config)"),
			}, "prompt"),
			Handler: m.handleComplete,
		},
		{
			Name:        "ai_chat",
			Description: "Multi-turn chat with an AI model",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"messages": schemaAny("Array of {role, content} messages (role: user|assistant|system)"),
				"system":   schemaStr("System prompt"),
				"model":    schemaStr("Override model"),
			}, "messages"),
			Handler: m.handleChat,
		},
		{
			Name:        "ai_providers",
			Description: "List supported AI providers and their known models",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"provider": schemaStr("Filter by provider name (optional)"),
			}),
			Handler: m.handleProviders,
		},
		{
			Name:        "ai_current",
			Description: "Show currently configured AI provider, model and status",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleCurrent,
		},
	}
}

func (m *aiModule) handleComplete(params map[string]interface{}) (*ToolResult, error) {
	prompt := getString(params, "prompt")
	system := getString(params, "system")
	if system == "" {
		system = m.cfg.SystemPrompt
	}
	maxTokens := getInt(params, "max_tokens")
	if maxTokens == 0 {
		maxTokens = m.cfg.AI.MaxTokens
	}
	temp := getFloat(params, "temperature")
	if temp == 0 {
		temp = m.cfg.AI.Temperature
	}

	// model override
	origModel := m.cfg.AI.Model
	if override := getString(params, "model"); override != "" {
		m.cfg.AI.Model = override
	}
	defer func() { m.cfg.AI.Model = origModel }()

	resp, err := m.client.Complete(api.CompletionRequest{
		Messages:    []api.Message{{Role: "user", Content: prompt}},
		System:      system,
		MaxTokens:   maxTokens,
		Temperature: temp,
	})
	if err != nil {
		return ErrorResult(fmt.Errorf("ai call failed: %w", err)), nil
	}

	result := fmt.Sprintf("model: %s | in: %d | out: %d | stop: %s\n\n%s",
		resp.Model, resp.InputTokens, resp.OutputTokens, resp.StopReason, resp.Content)

	return TextResult(result), nil
}

func (m *aiModule) handleChat(params map[string]interface{}) (*ToolResult, error) {
	system := getString(params, "system")
	if system == "" {
		system = m.cfg.SystemPrompt
	}

	rawMsgs, ok := params["messages"].([]interface{})
	if !ok {
		return ErrorResult(fmt.Errorf("messages must be an array")), nil
	}

	var messages []api.Message
	for _, raw := range rawMsgs {
		m2, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := m2["role"].(string)
		content, _ := m2["content"].(string)
		if role != "" && content != "" {
			messages = append(messages, api.Message{Role: role, Content: content})
		}
	}

	if len(messages) == 0 {
		return ErrorResult(fmt.Errorf("no valid messages")), nil
	}

	origModel := m.cfg.AI.Model
	if override := getString(params, "model"); override != "" {
		m.cfg.AI.Model = override
	}
	defer func() { m.cfg.AI.Model = origModel }()

	resp, err := m.client.Complete(api.CompletionRequest{
		Messages:    messages,
		System:      system,
		MaxTokens:   m.cfg.AI.MaxTokens,
		Temperature: m.cfg.AI.Temperature,
	})
	if err != nil {
		return ErrorResult(fmt.Errorf("ai chat failed: %w", err)), nil
	}

	result := fmt.Sprintf("model: %s | in: %d | out: %d | stop: %s\n\n%s",
		resp.Model, resp.InputTokens, resp.OutputTokens, resp.StopReason, resp.Content)

	return TextResult(result), nil
}

func (m *aiModule) handleProviders(params map[string]interface{}) (*ToolResult, error) {
	filter := getString(params, "provider")

	var lines []string
	for provider, models := range config.KnownModels {
		if filter != "" && !strings.EqualFold(provider, filter) {
			continue
		}
		lines = append(lines, fmt.Sprintf("\n[%s]", provider))
		if len(models) == 0 {
			lines = append(lines, "  (any model - set base_url in config)")
		}
		for _, model := range models {
			lines = append(lines, "  "+model)
		}
	}

	lines = append(lines, "\nconfig: set ai.provider + ai.model + ai.api_key")
	lines = append(lines, "env:    UWU_API_KEY overrides config api_key")

	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *aiModule) handleCurrent(params map[string]interface{}) (*ToolResult, error) {
	cfg := m.cfg.AI

	keyStatus := "not set"
	if m.cfg.GetAPIKey() != "" {
		key := m.cfg.GetAPIKey()
		if len(key) > 8 {
			keyStatus = key[:4] + "..." + key[len(key)-4:]
		} else {
			keyStatus = "set"
		}
	}

	baseURL := m.cfg.ResolvedBaseURL()

	result := fmt.Sprintf(
		"provider:    %s\nmodel:       %s\nbase_url:    %s\napi_key:     %s\nmax_tokens:  %d\ntemperature: %.2f\ntimeout:     %ds",
		cfg.Provider, cfg.Model, baseURL, keyStatus,
		cfg.MaxTokens, cfg.Temperature, cfg.TimeoutSecs,
	)

	return TextResult(result), nil
}
