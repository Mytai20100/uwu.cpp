package uwu

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"uwu.cpp/config"
)

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	Handler     ToolHandler            `json:"-"`
	Module      string                 `json:"module"`
	Dangerous   bool                   `json:"dangerous"`
}

// ToolHandler is the function signature for tool execution
type ToolHandler func(params map[string]interface{}) (*ToolResult, error)

// ToolResult is what a tool returns
type ToolResult struct {
	Content  []ContentBlock         `json:"content"`
	IsError  bool                   `json:"isError,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ContentBlock is one block in a tool result
type ContentBlock struct {
	Type     string `json:"type"` // text | image | resource
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`     // base64
	MimeType string `json:"mimeType,omitempty"` // for image
}

func TextResult(text string) *ToolResult {
	return &ToolResult{Content: []ContentBlock{{Type: "text", Text: text}}}
}

func ErrorResult(err error) *ToolResult {
	return &ToolResult{
		Content: []ContentBlock{{Type: "text", Text: "error: " + err.Error()}},
		IsError: true,
	}
}

func ImageResult(base64Data, mimeType, caption string) *ToolResult {
	return &ToolResult{
		Content: []ContentBlock{
			{Type: "image", Data: base64Data, MimeType: mimeType},
			{Type: "text", Text: caption},
		},
	}
}

// Module is the interface every module must implement
type Module interface {
	Name() string
	Description() string
	Tools() []*Tool
	Init(cfg *config.Config) error
	Shutdown() error
	SupportedOS() []string // nil = all OS
}

// Registry holds all registered modules and tools
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
	tools   map[string]*Tool
	cfg     *config.Config
	stats   map[string]*ToolStats
}

type ToolStats struct {
	CallCount   int64
	ErrorCount  int64
	TotalTimeMs int64
	LastUsed    time.Time
}

func newRegistry(cfg *config.Config) *Registry {
	return &Registry{
		modules: make(map[string]Module),
		tools:   make(map[string]*Tool),
		cfg:     cfg,
		stats:   make(map[string]*ToolStats),
	}
}

func (r *Registry) register(m Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check OS support
	if supported := m.SupportedOS(); len(supported) > 0 {
		cur := runtime.GOOS
		ok := false
		for _, s := range supported {
			if s == cur {
				ok = true
				break
			}
		}
		if !ok {
			fmt.Fprintf(nil, "") // noop
			return nil
		}
	}

	if err := m.Init(r.cfg); err != nil {
		return fmt.Errorf("init module %s: %w", m.Name(), err)
	}

	r.modules[m.Name()] = m
	for _, t := range m.Tools() {
		r.tools[t.Name] = t
		r.stats[t.Name] = &ToolStats{}
	}

	return nil
}

func (r *Registry) CallTool(name string, params map[string]interface{}) (*ToolResult, error) {
	r.mu.RLock()
	tool, ok := r.tools[name]
	r.mu.RUnlock()

	if !ok {
		return ErrorResult(fmt.Errorf("tool not found: %s", name)), nil
	}

	start := time.Now()
	result, err := tool.Handler(params)
	elapsed := time.Since(start).Milliseconds()

	r.mu.Lock()
	s := r.stats[name]
	s.CallCount++
	s.TotalTimeMs += elapsed
	s.LastUsed = time.Now()
	if err != nil || (result != nil && result.IsError) {
		s.ErrorCount++
	}
	r.mu.Unlock()

	return result, err
}

func (r *Registry) GetTools() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Name < tools[j].Name
	})
	return tools
}

func (r *Registry) ToolCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

func (r *Registry) PrintInfo() {
	r.mu.RLock()
	defer r.mu.RUnlock()

	fmt.Println("\nmodules:")
	names := make([]string, 0, len(r.modules))
	for n := range r.modules {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("  %-20s %s\n", n, r.modules[n].Description())
	}

	fmt.Println("\ntools:")
	tools := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	for _, t := range tools {
		danger := ""
		if t.Dangerous {
			danger = " [DANGEROUS]"
		}
		fmt.Printf("  %-35s %s%s\n", t.Name, t.Description, danger)
	}

	fmt.Printf("\ntotal: %d modules, %d tools\n", len(r.modules), len(r.tools))
}

func (r *Registry) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.modules {
		m.Shutdown()
	}
}

// ─── UWU: THE LINKER ─────────────────────────────────────────────────────────

// uwu registers a set of modules into the registry.
// This is the single wiring point - add new modules here.
func uwu(cfg *config.Config, registry *Registry, modules ...Module) {
	for _, m := range modules {
		if err := registry.register(m); err != nil {
			fmt.Printf("[uwu] failed to register %s: %v\n", m.Name(), err)
		} else {
			fmt.Printf("[uwu] loaded %-20s (%d tools)\n", m.Name(), len(m.Tools()))
		}
	}
}

// Boot initializes all modules and returns the ready registry
func Boot(cfg *config.Config) *Registry {
	registry := newRegistry(cfg)

	// NOTE: newAIModule intentionally excluded — exposing AI tools via MCP
	// causes the agent to call AI recursively, doubling API costs per request.
	uwu(cfg, registry,
		newFilesystemModule(cfg),
		newProcessModule(cfg),
		newShellModule(cfg),
		newSystemModule(cfg),
		newScreenModule(cfg),
		newInputModule(cfg),
		newClipboardModule(cfg),
	)

	fmt.Printf("[uwu] ready: %d tools total\n", registry.ToolCount())
	return registry
}