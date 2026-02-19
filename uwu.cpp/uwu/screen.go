package uwu

import (
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"uwu.cpp/config"

	"github.com/kbinani/screenshot"
)

type screenModule struct{ cfg *config.Config }

func newScreenModule(cfg *config.Config) Module      { return &screenModule{cfg: cfg} }
func (m *screenModule) Name() string                { return "screen" }
func (m *screenModule) Description() string         { return "screenshot, window focus, display info" }
func (m *screenModule) SupportedOS() []string       { return nil }
func (m *screenModule) Shutdown() error             { return nil }
func (m *screenModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *screenModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "screen_capture",
			Description: "Capture a screenshot, returns base64 image",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"display": schemaNum("display index (0 = primary)"),
				"format":  schemaStr("png | jpeg (default png)"),
				"quality": schemaNum("jpeg quality 1-100 (default 85)"),
				"save":    schemaStr("optional path to save the image"),
			}),
			Handler: m.handleCapture,
		},
		{
			Name:        "screen_displays",
			Description: "List connected displays and their resolutions",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleDisplays,
		},
		{
			Name:        "screen_focus",
			Description: "Bring a window to the foreground",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"title":   schemaStr("window title to match"),
				"process": schemaStr("process name to match"),
			}),
			Handler: m.handleFocus,
		},
	}
}

func (m *screenModule) handleCapture(params map[string]interface{}) (*ToolResult, error) {
	display := getInt(params, "display")
	format := getString(params, "format")
	if format == "" {
		format = "png"
	}
	quality := getInt(params, "quality")
	if quality == 0 {
		quality = 85
	}
	savePath := getString(params, "save")

	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return ErrorResult(fmt.Errorf("no displays found")), nil
	}
	if display >= n {
		return ErrorResult(fmt.Errorf("display %d not found (have %d)", display, n)), nil
	}

	bounds := screenshot.GetDisplayBounds(display)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return ErrorResult(fmt.Errorf("capture: %w", err)), nil
	}

	tmp, err := os.CreateTemp("", "uwu_screen_*."+format)
	if err != nil {
		return ErrorResult(err), nil
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	mimeType := "image/png"
	if format == "jpeg" || format == "jpg" {
		mimeType = "image/jpeg"
		jpeg.Encode(tmp, img, &jpeg.Options{Quality: quality})
	} else {
		png.Encode(tmp, img)
	}

	tmp.Seek(0, 0)
	raw, _ := os.ReadFile(tmp.Name())
	encoded := base64.StdEncoding.EncodeToString(raw)

	if savePath != "" {
		os.WriteFile(savePath, raw, 0644)
	}

	caption := fmt.Sprintf("display %d: %dx%d format=%s size=%d bytes",
		display, bounds.Dx(), bounds.Dy(), format, len(raw))
	if savePath != "" {
		caption += " saved=" + savePath
	}

	return ImageResult(encoded, mimeType, caption), nil
}

func (m *screenModule) handleDisplays(_ map[string]interface{}) (*ToolResult, error) {
	n := screenshot.NumActiveDisplays()
	var lines []string
	lines = append(lines, fmt.Sprintf("displays: %d", n))
	for i := 0; i < n; i++ {
		b := screenshot.GetDisplayBounds(i)
		lines = append(lines, fmt.Sprintf("  [%d] %dx%d at (%d,%d)", i, b.Dx(), b.Dy(), b.Min.X, b.Min.Y))
	}
	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *screenModule) handleFocus(params map[string]interface{}) (*ToolResult, error) {
	title := getString(params, "title")
	proc := getString(params, "process")

	switch runtime.GOOS {
	case "windows":
		script := fmt.Sprintf(`
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr FindWindow(string c, string t); }
"@
$h = [W]::FindWindow($null, "%s"); [W]::SetForegroundWindow($h)`, title)
		exec.Command("powershell", "-Command", script).Run()
	case "linux":
		if title != "" {
			exec.Command("wmctrl", "-a", title).Run()
		} else if proc != "" {
			exec.Command("wmctrl", "-x", "-a", proc).Run()
		}
	case "darwin":
		if title != "" {
			exec.Command("osascript", "-e", fmt.Sprintf(`tell application "%s" to activate`, title)).Run()
		}
	}

	target := title
	if target == "" {
		target = proc
	}
	return TextResult(fmt.Sprintf("focused: %s", target)), nil
}
