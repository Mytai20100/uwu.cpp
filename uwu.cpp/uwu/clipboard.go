package uwu

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"uwu.cpp/config"
)

type clipboardModule struct{ cfg *config.Config }

func newClipboardModule(cfg *config.Config) Module      { return &clipboardModule{cfg: cfg} }
func (m *clipboardModule) Name() string                { return "clipboard" }
func (m *clipboardModule) Description() string         { return "read and write system clipboard" }
func (m *clipboardModule) SupportedOS() []string       { return nil }
func (m *clipboardModule) Shutdown() error             { return nil }
func (m *clipboardModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *clipboardModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "clipboard_read",
			Description: "Read current clipboard contents",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleRead,
		},
		{
			Name:        "clipboard_write",
			Description: "Write text to clipboard",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"text": schemaStr("text to copy to clipboard"),
			}, "text"),
			Handler: m.handleWrite,
		},
		{
			Name:        "clipboard_clear",
			Description: "Clear the clipboard",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleClear,
		},
	}
}

func (m *clipboardModule) handleRead(_ map[string]interface{}) (*ToolResult, error) {
	text, err := readClipboard()
	if err != nil {
		return ErrorResult(err), nil
	}
	if text == "" {
		return TextResult("clipboard is empty"), nil
	}
	return TextResult(fmt.Sprintf("clipboard (%d chars):\n%s", len(text), text)), nil
}

func (m *clipboardModule) handleWrite(params map[string]interface{}) (*ToolResult, error) {
	text := getString(params, "text")
	if err := writeClipboard(text); err != nil {
		return ErrorResult(err), nil
	}
	return TextResult(fmt.Sprintf("wrote %d chars to clipboard", len(text))), nil
}

func (m *clipboardModule) handleClear(_ map[string]interface{}) (*ToolResult, error) {
	if err := writeClipboard(""); err != nil {
		return ErrorResult(err), nil
	}
	return TextResult("clipboard cleared"), nil
}

func readClipboard() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-Command", "Get-Clipboard").Output()
		return strings.TrimRight(string(out), "\r\n"), err
	case "darwin":
		out, err := exec.Command("pbpaste").Output()
		return string(out), err
	default:
		for _, tool := range [][]string{
			{"xclip", "-o", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--output"},
			{"wl-paste"},
		} {
			out, err := exec.Command(tool[0], tool[1:]...).Output()
			if err == nil {
				return string(out), nil
			}
		}
		return "", fmt.Errorf("no clipboard tool found (install xclip, xsel, or wl-paste)")
	}
}

func writeClipboard(text string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("powershell", "-Command",
			fmt.Sprintf("Set-Clipboard '%s'", strings.ReplaceAll(text, "'", "''"))).Run()
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	default:
		for _, tool := range [][]string{
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
			{"wl-copy"},
		} {
			cmd := exec.Command(tool[0], tool[1:]...)
			cmd.Stdin = strings.NewReader(text)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
		return fmt.Errorf("no clipboard tool found (install xclip, xsel, or wl-paste)")
	}
}
