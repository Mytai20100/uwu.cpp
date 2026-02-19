package uwu

import (
	"fmt"
	"strings"
	"time"

	"uwu.cpp/config"

	"github.com/go-vgo/robotgo"
)

type inputModule struct{ cfg *config.Config }

func newInputModule(cfg *config.Config) Module      { return &inputModule{cfg: cfg} }
func (m *inputModule) Name() string                { return "input" }
func (m *inputModule) Description() string         { return "keyboard and mouse simulation" }
func (m *inputModule) SupportedOS() []string       { return nil }
func (m *inputModule) Shutdown() error             { return nil }
func (m *inputModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *inputModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "input_type",
			Description: "Type text into the active window",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"text":  schemaStr("text to type"),
				"delay": schemaNum("delay between chars in ms (default 0)"),
			}, "text"),
			Handler: m.handleType,
		},
		{
			Name:        "input_key",
			Description: "Press a key or key combination",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"key":  schemaStr("key name (enter, tab, space, f1, etc)"),
				"hold": schemaAny("modifier keys to hold (array: ctrl, shift, alt, cmd)"),
			}, "key"),
			Handler: m.handleKey,
		},
		{
			Name:        "input_hotkey",
			Description: "Execute a hotkey like ctrl+shift+t",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"keys": schemaStr("keys joined by + (e.g. ctrl+shift+t, alt+f4)"),
			}, "keys"),
			Handler: m.handleHotkey,
		},
		{
			Name:        "input_mouse_move",
			Description: "Move the mouse cursor to a position",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"x":      schemaNum("X coordinate"),
				"y":      schemaNum("Y coordinate"),
				"smooth": schemaBool("smooth movement"),
			}, "x", "y"),
			Handler: m.handleMouseMove,
		},
		{
			Name:        "input_mouse_click",
			Description: "Click the mouse at a position",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"x":      schemaNum("X (0 = current position)"),
				"y":      schemaNum("Y (0 = current position)"),
				"button": schemaStr("left | right | center (default left)"),
				"double": schemaBool("double click"),
				"count":  schemaNum("number of clicks (default 1)"),
			}),
			Handler: m.handleMouseClick,
		},
		{
			Name:        "input_mouse_pos",
			Description: "Get current mouse cursor position",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleMousePos,
		},
		{
			Name:        "input_scroll",
			Description: "Scroll the mouse wheel",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"direction": schemaStr("up | down | left | right"),
				"amount":    schemaNum("scroll steps (default 3)"),
				"x":         schemaNum("move to X before scrolling (0 = stay)"),
				"y":         schemaNum("move to Y before scrolling (0 = stay)"),
			}, "direction"),
			Handler: m.handleScroll,
		},
	}
}

func (m *inputModule) handleType(params map[string]interface{}) (*ToolResult, error) {
	text := getString(params, "text")
	delay := getInt(params, "delay")
	if delay > 0 {
		robotgo.TypeStr(text, delay)
	} else {
		robotgo.TypeStr(text)
	}
	preview := text
	if len(preview) > 60 {
		preview = preview[:60] + "..."
	}
	return TextResult(fmt.Sprintf("typed %d chars: %q", len(text), preview)), nil
}

func (m *inputModule) handleKey(params map[string]interface{}) (*ToolResult, error) {
	key := getString(params, "key")
	var mods []string
	if raw, ok := params["hold"].([]interface{}); ok {
		for _, v := range raw {
			mods = append(mods, fmt.Sprintf("%v", v))
		}
	}
	if len(mods) > 0 {
		robotgo.KeyTap(key, mods)
	} else {
		robotgo.KeyTap(key)
	}
	combo := key
	if len(mods) > 0 {
		combo = strings.Join(mods, "+") + "+" + key
	}
	return TextResult(fmt.Sprintf("key: %s", combo)), nil
}

func (m *inputModule) handleHotkey(params map[string]interface{}) (*ToolResult, error) {
	keys := getString(params, "keys")
	parts := strings.Split(keys, "+")
	if len(parts) == 0 {
		return ErrorResult(fmt.Errorf("no keys specified")), nil
	}
	if len(parts) == 1 {
		robotgo.KeyTap(parts[0])
	} else {
		main := parts[len(parts)-1]
		mods := parts[:len(parts)-1]
		robotgo.KeyTap(main, mods)
	}
	return TextResult(fmt.Sprintf("hotkey: %s", keys)), nil
}

func (m *inputModule) handleMouseMove(params map[string]interface{}) (*ToolResult, error) {
	x, y := getInt(params, "x"), getInt(params, "y")
	smooth := getBool(params, "smooth")
	if smooth {
		robotgo.MoveSmooth(x, y)
	} else {
		robotgo.Move(x, y)
	}
	return TextResult(fmt.Sprintf("mouse moved to (%d, %d)", x, y)), nil
}

func (m *inputModule) handleMouseClick(params map[string]interface{}) (*ToolResult, error) {
	x, y := getInt(params, "x"), getInt(params, "y")
	button := getString(params, "button")
	if button == "" {
		button = "left"
	}
	double := getBool(params, "double")
	count := getInt(params, "count")
	if count == 0 {
		count = 1
	}

	if x != 0 || y != 0 {
		robotgo.Move(x, y)
		time.Sleep(50 * time.Millisecond)
	}

	for i := 0; i < count; i++ {
		robotgo.Click(button, double)
		if i < count-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	desc := "click"
	if double {
		desc = "double-click"
	}
	return TextResult(fmt.Sprintf("%s %s at (%d,%d) x%d", button, desc, x, y, count)), nil
}

func (m *inputModule) handleMousePos(_ map[string]interface{}) (*ToolResult, error) {
	x, y := robotgo.Location()
	return TextResult(fmt.Sprintf("mouse at (%d, %d)", x, y)), nil
}

func (m *inputModule) handleScroll(params map[string]interface{}) (*ToolResult, error) {
	direction := getString(params, "direction")
	amount := getInt(params, "amount")
	if amount == 0 {
		amount = 3
	}
	x, y := getInt(params, "x"), getInt(params, "y")

	if x != 0 || y != 0 {
		robotgo.Move(x, y)
		time.Sleep(50 * time.Millisecond)
	}

	switch direction {
	case "down":
		robotgo.Scroll(0, -amount)
	case "up":
		robotgo.Scroll(0, amount)
	case "right":
		robotgo.Scroll(amount, 0)
	case "left":
		robotgo.Scroll(-amount, 0)
	default:
		return ErrorResult(fmt.Errorf("invalid direction: %s (use up/down/left/right)", direction)), nil
	}

	return TextResult(fmt.Sprintf("scrolled %s by %d", direction, amount)), nil
}
