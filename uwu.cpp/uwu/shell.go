package uwu

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"uwu.cpp/config"
)

type shellModule struct{ cfg *config.Config }

func newShellModule(cfg *config.Config) Module      { return &shellModule{cfg: cfg} }
func (m *shellModule) Name() string                { return "shell" }
func (m *shellModule) Description() string         { return "execute shell commands, scripts, manage env" }
func (m *shellModule) SupportedOS() []string       { return nil }
func (m *shellModule) Shutdown() error             { return nil }
func (m *shellModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *shellModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "shell_exec",
			Description: "Execute a shell command (bash/cmd/powershell)",
			Module:      m.Name(),
			Dangerous:   true,
			InputSchema: jsonSchema(map[string]interface{}{
				"command": schemaStr("command to execute"),
				"shell":   schemaStr("shell: bash | sh | cmd | powershell | zsh | python3 (auto if empty)"),
				"cwd":     schemaStr("working directory"),
				"timeout": schemaNum("timeout in seconds (default 30)"),
				"env":     schemaAny("extra env vars as object {KEY: value}"),
				"stdin":   schemaStr("data to pass as stdin"),
			}, "command"),
			Handler: m.handleExec,
		},
		{
			Name:        "shell_script",
			Description: "Run a script file (auto-detects .py .sh .ps1 .js)",
			Module:      m.Name(),
			Dangerous:   true,
			InputSchema: jsonSchema(map[string]interface{}{
				"path":    schemaStr("path to script file"),
				"args":    schemaAny("array of arguments"),
				"cwd":     schemaStr("working directory"),
				"timeout": schemaNum("timeout in seconds (default 60)"),
			}, "path"),
			Handler: m.handleScript,
		},
		{
			Name:        "shell_env",
			Description: "Get or set environment variables",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"get": schemaStr("variable name to get (empty = list all)"),
				"set": schemaAny("object of variables to set {KEY: value}"),
			}),
			Handler: m.handleEnv,
		},
		{
			Name:        "shell_which",
			Description: "Find the path of a program",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"program": schemaStr("program name"),
			}, "program"),
			Handler: m.handleWhich,
		},
	}
}

func (m *shellModule) handleExec(params map[string]interface{}) (*ToolResult, error) {
	command := getString(params, "command")
	shell := getString(params, "shell")
	cwd := getString(params, "cwd")
	timeout := getInt(params, "timeout")
	if timeout == 0 {
		timeout = 30
	}

	if err := m.checkCommand(command); err != nil {
		return ErrorResult(err), nil
	}

	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd"
		} else {
			shell = "bash"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch shell {
	case "cmd":
		cmd = exec.CommandContext(ctx, "cmd", "/c", command)
	case "powershell", "pwsh":
		cmd = exec.CommandContext(ctx, "powershell", "-NonInteractive", "-Command", command)
	case "bash":
		cmd = exec.CommandContext(ctx, "bash", "-c", command)
	case "sh":
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	case "zsh":
		cmd = exec.CommandContext(ctx, "zsh", "-c", command)
	case "python3", "python":
		cmd = exec.CommandContext(ctx, "python3", "-c", command)
	default:
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}

	if cwd != "" {
		cmd.Dir = cwd
	}

	if envMap, ok := params["env"].(map[string]interface{}); ok {
		cmd.Env = os.Environ()
		for k, v := range envMap {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%v", k, v))
		}
	}

	if stdin := getString(params, "stdin"); stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("command: %s\nshell: %s  time: %.3fs\n", command, shell, elapsed.Seconds()))
	if cwd != "" {
		sb.WriteString(fmt.Sprintf("cwd: %s\n", cwd))
	}

	if stdout.Len() > 0 {
		sb.WriteString("\nstdout:\n")
		sb.WriteString(stdout.String())
	}
	if stderr.Len() > 0 {
		sb.WriteString("\nstderr:\n")
		sb.WriteString(stderr.String())
	}

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			sb.WriteString(fmt.Sprintf("\ntimeout after %ds", timeout))
		} else {
			sb.WriteString(fmt.Sprintf("\nexit: %v", runErr))
		}
	} else {
		sb.WriteString("\nexit: 0")
	}

	return TextResult(sb.String()), nil
}

func (m *shellModule) handleScript(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	cwd := getString(params, "cwd")
	timeout := getInt(params, "timeout")
	if timeout == 0 {
		timeout = 60
	}

	var args []string
	if raw, ok := params["args"].([]interface{}); ok {
		for _, a := range raw {
			args = append(args, fmt.Sprintf("%v", a))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch {
	case strings.HasSuffix(path, ".py"):
		cmd = exec.CommandContext(ctx, "python3", append([]string{path}, args...)...)
	case strings.HasSuffix(path, ".sh"):
		cmd = exec.CommandContext(ctx, "bash", append([]string{path}, args...)...)
	case strings.HasSuffix(path, ".ps1"):
		cmd = exec.CommandContext(ctx, "powershell", append([]string{"-File", path}, args...)...)
	case strings.HasSuffix(path, ".js"):
		cmd = exec.CommandContext(ctx, "node", append([]string{path}, args...)...)
	default:
		cmd = exec.CommandContext(ctx, path, args...)
	}

	if cwd != "" {
		cmd.Dir = cwd
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return ErrorResult(fmt.Errorf("script %s: %w\n%s", path, err, string(out))), nil
	}
	return TextResult(fmt.Sprintf("script: %s\n\n%s", path, string(out))), nil
}

func (m *shellModule) handleEnv(params map[string]interface{}) (*ToolResult, error) {
	if setMap, ok := params["set"].(map[string]interface{}); ok {
		var set []string
		for k, v := range setMap {
			val := fmt.Sprintf("%v", v)
			os.Setenv(k, val)
			set = append(set, k+"="+val)
		}
		return TextResult("set:\n" + strings.Join(set, "\n")), nil
	}

	if name := getString(params, "get"); name != "" {
		val := os.Getenv(name)
		if val == "" {
			return TextResult(fmt.Sprintf("%s is not set", name)), nil
		}
		return TextResult(name + "=" + val), nil
	}

	vars := os.Environ()
	return TextResult(fmt.Sprintf("%d env vars:\n%s", len(vars), strings.Join(vars, "\n"))), nil
}

func (m *shellModule) handleWhich(params map[string]interface{}) (*ToolResult, error) {
	program := getString(params, "program")
	path, err := exec.LookPath(program)
	if err != nil {
		return TextResult(fmt.Sprintf("not found: %s", program)), nil
	}
	return TextResult(fmt.Sprintf("%s -> %s", program, path)), nil
}

func (m *shellModule) checkCommand(cmd string) error {
	if m.cfg == nil {
		return nil
	}
	lower := strings.ToLower(cmd)
	for _, blocked := range m.cfg.Security.BlockedCommands {
		if strings.Contains(lower, strings.ToLower(blocked)) {
			return fmt.Errorf("command blocked: contains '%s'", blocked)
		}
	}
	return nil
}
