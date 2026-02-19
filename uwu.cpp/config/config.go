package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// Supported providers and their known models
var KnownModels = map[string][]string{
	"anthropic": {
		"claude-opus-4-5",
		"claude-sonnet-4-5",
		"claude-haiku-4-5",
		"claude-opus-4-5-20251101",
		"claude-sonnet-4-5-20251022",
		"claude-haiku-4-5-20251001",
	},
	"openai": {
		"gpt-4o",
		"gpt-4o-mini",
		"gpt-4-turbo",
		"o1",
		"o1-mini",
		"o3-mini",
	},
	"openrouter": {
		"anthropic/claude-opus-4-5",
		"anthropic/claude-sonnet-4-5",
		"openai/gpt-4o",
		"openai/o1",
		"google/gemini-2.0-flash-exp",
		"meta-llama/llama-3.3-70b-instruct",
		"deepseek/deepseek-r1",
		"qwen/qwen-2.5-72b-instruct",
	},
	"gemini": {
		"gemini-2.0-flash",
		"gemini-2.0-flash-exp",
		"gemini-1.5-pro",
		"gemini-1.5-flash",
	},
	"ollama": {
		"llama3.3",
		"qwen2.5",
		"deepseek-r1",
		"mistral",
		"phi4",
	},
	"custom": {},
}

var ProviderBaseURLs = map[string]string{
	"anthropic":  "https://api.anthropic.com",
	"openai":     "https://api.openai.com",
	"openrouter": "https://openrouter.ai/api",
	"gemini":     "https://generativelanguage.googleapis.com",
	"ollama":     "http://localhost:11434",
}

type Config struct {
	Server   ServerConfig   `json:"server"`
	AI       AIConfig       `json:"ai"`
	Modules  ModulesConfig  `json:"modules"`
	Security SecurityConfig `json:"security"`
	Log      LogConfig      `json:"log"`

	// System prompt for the AI - editable at runtime via /config/prompt
	SystemPrompt string `json:"system_prompt"`
}

type ServerConfig struct {
	Transport string `json:"transport"` // stdio | http
	HTTPAddr  string `json:"http_addr"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type AIConfig struct {
	// Provider: anthropic | openai | openrouter | gemini | ollama | custom
	Provider string `json:"provider"`

	// API key - can also be set via env: UWU_API_KEY
	APIKey string `json:"api_key"`

	// Override base URL (required for ollama, custom; optional for openrouter)
	BaseURL string `json:"base_url"`

	// Model name (must match provider's model list)
	Model string `json:"model"`

	// Generation params
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`

	// Request timeout in seconds
	TimeoutSecs int `json:"timeout_secs"`

	// For OpenRouter: your site URL and name (shown in rankings)
	OpenRouterSiteURL  string `json:"openrouter_site_url"`
	OpenRouterSiteName string `json:"openrouter_site_name"`
}

type ModulesConfig struct {
	Filesystem bool `json:"filesystem"`
	Process    bool `json:"process"`
	Shell      bool `json:"shell"`
	Screen     bool `json:"screen"`
	Input      bool `json:"input"`
	System     bool `json:"system"`
	Network    bool `json:"network"`
	Clipboard  bool `json:"clipboard"`
}

type SecurityConfig struct {
	AllowedPaths               []string `json:"allowed_paths"`
	BlockedPaths               []string `json:"blocked_paths"`
	BlockedCommands            []string `json:"blocked_commands"`
	RequireConfirmForDangerous bool     `json:"require_confirm_for_dangerous"`
	SandboxMode                bool     `json:"sandbox_mode"`
	// API key to authenticate HTTP transport requests
	HTTPAPIKey string `json:"http_api_key"`
}

type LogConfig struct {
	Level  string `json:"level"`   // debug | info | warn | error
	ToFile string `json:"to_file"` // path, empty = stderr
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Transport: "stdio",
			HTTPAddr:  ":8765",
			Name:      "uwu-mcp-server",
			Version:   "1.0.0",
		},
		AI: AIConfig{
			Provider:    "anthropic",
			APIKey:      os.Getenv("UWU_API_KEY"),
			BaseURL:     "",
			Model:       "claude-opus-4-5",
			MaxTokens:   4096,
			Temperature: 0.7,
			TimeoutSecs: 120,
		},
		Modules: ModulesConfig{
			Filesystem: true,
			Process:    true,
			Shell:      true,
			Screen:     true,
			Input:      true,
			System:     true,
			Network:    true,
			Clipboard:  true,
		},
		SystemPrompt: buildSystemPrompt(),
		Security: SecurityConfig{
			AllowedPaths:    []string{},
			BlockedPaths:    defaultBlockedPaths(),
			BlockedCommands: defaultBlockedCommands(),
			RequireConfirmForDangerous: false,
			SandboxMode:                false,
			HTTPAPIKey:                 "",
		},
		Log: LogConfig{
			Level:  "info",
			ToFile: "",
		},
	}
}

func defaultBlockedPaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\SAM`,
			`C:\Windows\System32\SECURITY`,
		}
	}
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/.ssh",
	}
}

func defaultBlockedCommands() []string {
	if runtime.GOOS == "windows" {
		return []string{"format c:", "del /f /s /q c:\\windows"}
	}
	return []string{"rm -rf /", "mkfs", "> /dev/sda"}
}

func buildSystemPrompt() string {
	goos := runtime.GOOS
	return fmt.Sprintf(`You are uwu-agent, an AI with direct access to control a %s machine.

You have the following tool categories available:

filesystem  - read, write, delete, copy, move, search files and directories
process     - list, open, kill processes and applications  
shell       - execute bash/cmd/powershell commands and scripts
system      - query CPU, RAM, disk, network, uptime
screen      - capture screenshots, manage windows
input       - simulate keyboard and mouse (type, click, hotkeys, scroll)
clipboard   - read and write clipboard

Operating system: %s

Rules:
- Always prefer shell_exec for batching multiple operations into one call
- Report both stdout and stderr when running commands
- Confirm before deleting files or killing critical processes
- Use absolute paths when possible to avoid ambiguity
- For shell commands, use correct syntax for %s
- When automating a GUI task, use screen_capture to verify state before acting

Optimize for fewer, more effective tool calls. Batch related operations.`, goos, goos, goos)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Env overrides
	if v := os.Getenv("UWU_API_KEY"); v != "" {
		cfg.AI.APIKey = v
	}
	if v := os.Getenv("UWU_HTTP_API_KEY"); v != "" {
		cfg.Security.HTTPAPIKey = v
	}

	return cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func GenerateDefault(path string) error {
	cfg := Default()
	cfg.AI.APIKey = "YOUR_API_KEY_HERE"
	cfg.Security.HTTPAPIKey = "change-this-secret"
	return cfg.Save(path)
}

func (c *Config) GetAPIKey() string {
	if v := os.Getenv("UWU_API_KEY"); v != "" {
		return v
	}
	return c.AI.APIKey
}

// ResolvedBaseURL returns the effective base URL for the configured provider
func (c *Config) ResolvedBaseURL() string {
	if c.AI.BaseURL != "" {
		return c.AI.BaseURL
	}
	if u, ok := ProviderBaseURLs[c.AI.Provider]; ok {
		return u
	}
	return ""
}
