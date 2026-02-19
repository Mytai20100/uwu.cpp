package uwu

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"uwu.cpp/config"
)

type filesystemModule struct {
	cfg *config.Config
}

func newFilesystemModule(cfg *config.Config) Module {
	return &filesystemModule{cfg: cfg}
}

func (m *filesystemModule) Name() string          { return "filesystem" }
func (m *filesystemModule) Description() string   { return "read, write, delete, search files and directories" }
func (m *filesystemModule) SupportedOS() []string { return nil }
func (m *filesystemModule) Shutdown() error       { return nil }
func (m *filesystemModule) Init(cfg *config.Config) error {
	m.cfg = cfg
	return nil
}

func (m *filesystemModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "fs_read",
			Description: "Read file contents (text or binary)",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path":   schemaStr("file path to read"),
				"binary": schemaBool("return base64-encoded binary instead of text"),
			}, "path"),
			Handler: m.handleRead,
		},
		{
			Name:        "fs_write",
			Description: "Write content to a file (create or overwrite)",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path":    schemaStr("file path"),
				"content": schemaStr("content to write"),
				"append":  schemaBool("append instead of overwrite"),
			}, "path", "content"),
			Handler: m.handleWrite,
		},
		{
			Name:        "fs_delete",
			Description: "Delete a file or directory",
			Module:      m.Name(),
			Dangerous:   true,
			InputSchema: jsonSchema(map[string]interface{}{
				"path":      schemaStr("path to delete"),
				"recursive": schemaBool("recursive delete for directories"),
			}, "path"),
			Handler: m.handleDelete,
		},
		{
			Name:        "fs_list",
			Description: "List directory contents",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path":       schemaStr("directory path"),
				"recursive":  schemaBool("list recursively"),
				"pattern":    schemaStr("glob filter pattern (e.g. *.go)"),
				"showHidden": schemaBool("include hidden files"),
			}, "path"),
			Handler: m.handleList,
		},
		{
			Name:        "fs_copy",
			Description: "Copy a file",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"src": schemaStr("source path"),
				"dst": schemaStr("destination path"),
			}, "src", "dst"),
			Handler: m.handleCopy,
		},
		{
			Name:        "fs_move",
			Description: "Move or rename a file or directory",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"src": schemaStr("source"),
				"dst": schemaStr("destination"),
			}, "src", "dst"),
			Handler: m.handleMove,
		},
		{
			Name:        "fs_mkdir",
			Description: "Create a directory",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path": schemaStr("directory path to create"),
				"all":  schemaBool("create all intermediate directories (like mkdir -p)"),
			}, "path"),
			Handler: m.handleMkdir,
		},
		{
			Name:        "fs_stat",
			Description: "Get file or directory metadata",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path": schemaStr("path to stat"),
			}, "path"),
			Handler: m.handleStat,
		},
		{
			Name:        "fs_search",
			Description: "Search for files by name pattern or content",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"root":    schemaStr("root directory to search from"),
				"pattern": schemaStr("glob pattern to match filenames"),
				"content": schemaStr("search for this string inside files"),
				"depth":   schemaNum("max depth (default 10)"),
			}, "root"),
			Handler: m.handleSearch,
		},
	}
}

func (m *filesystemModule) handleRead(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	binary := getBool(params, "binary")

	if err := m.checkPath(path); err != nil {
		return ErrorResult(err), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ErrorResult(err), nil
	}

	info, _ := os.Stat(path)
	size := int64(0)
	if info != nil {
		size = info.Size()
	}

	if binary {
		return TextResult(fmt.Sprintf("path: %s\nsize: %d bytes\nencoding: base64\n\n%s",
			path, size, base64.StdEncoding.EncodeToString(data))), nil
	}

	return TextResult(fmt.Sprintf("path: %s\nsize: %d bytes\n\n%s", path, size, string(data))), nil
}

func (m *filesystemModule) handleWrite(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	content := getString(params, "content")
	appendMode := getBool(params, "append")

	if err := m.checkPath(path); err != nil {
		return ErrorResult(err), nil
	}

	os.MkdirAll(filepath.Dir(path), 0755)

	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}

	f, err := os.OpenFile(path, flag, 0644)
	if err != nil {
		return ErrorResult(err), nil
	}
	defer f.Close()

	n, err := f.WriteString(content)
	if err != nil {
		return ErrorResult(err), nil
	}

	mode := "wrote"
	if appendMode {
		mode = "appended"
	}
	return TextResult(fmt.Sprintf("%s %d bytes to %s", mode, n, path)), nil
}

func (m *filesystemModule) handleDelete(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	recursive := getBool(params, "recursive")

	if err := m.checkPath(path); err != nil {
		return ErrorResult(err), nil
	}

	var err error
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	if err != nil {
		return ErrorResult(err), nil
	}

	return TextResult(fmt.Sprintf("deleted: %s", path)), nil
}

func (m *filesystemModule) handleList(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	if path == "" {
		path = "."
	}
	recursive := getBool(params, "recursive")
	pattern := getString(params, "pattern")
	showHidden := getBool(params, "showHidden")

	var entries []string
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		base := filepath.Base(p)
		if !showHidden && strings.HasPrefix(base, ".") && p != path {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if p == path {
			return nil
		}
		if !recursive {
			rel, _ := filepath.Rel(path, p)
			if strings.Contains(rel, string(os.PathSeparator)) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if pattern != "" {
			if matched, _ := filepath.Match(pattern, base); !matched {
				return nil
			}
		}

		kind := "file"
		if info.IsDir() {
			kind = "dir "
		}
		entries = append(entries, fmt.Sprintf("%s  %-50s  %8d  %s",
			kind, p, info.Size(), info.ModTime().Format("2006-01-02 15:04")))
		return nil
	})

	if err != nil {
		return ErrorResult(err), nil
	}
	if len(entries) == 0 {
		return TextResult(fmt.Sprintf("%s (empty)", path)), nil
	}
	return TextResult(fmt.Sprintf("%s  (%d entries)\n\n%s", path, len(entries), strings.Join(entries, "\n"))), nil
}

func (m *filesystemModule) handleCopy(params map[string]interface{}) (*ToolResult, error) {
	src, dst := getString(params, "src"), getString(params, "dst")

	srcFile, err := os.Open(src)
	if err != nil {
		return ErrorResult(err), nil
	}
	defer srcFile.Close()

	os.MkdirAll(filepath.Dir(dst), 0755)

	dstFile, err := os.Create(dst)
	if err != nil {
		return ErrorResult(err), nil
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return ErrorResult(err), nil
	}

	return TextResult(fmt.Sprintf("copied %s -> %s (%d bytes)", src, dst, n)), nil
}

func (m *filesystemModule) handleMove(params map[string]interface{}) (*ToolResult, error) {
	src, dst := getString(params, "src"), getString(params, "dst")
	os.MkdirAll(filepath.Dir(dst), 0755)
	if err := os.Rename(src, dst); err != nil {
		return ErrorResult(err), nil
	}
	return TextResult(fmt.Sprintf("moved %s -> %s", src, dst)), nil
}

func (m *filesystemModule) handleMkdir(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	var err error
	if getBool(params, "all") {
		err = os.MkdirAll(path, 0755)
	} else {
		err = os.Mkdir(path, 0755)
	}
	if err != nil {
		return ErrorResult(err), nil
	}
	return TextResult(fmt.Sprintf("created directory: %s", path)), nil
}

func (m *filesystemModule) handleStat(params map[string]interface{}) (*ToolResult, error) {
	path := getString(params, "path")
	info, err := os.Stat(path)
	if err != nil {
		return ErrorResult(err), nil
	}

	kind := "file"
	if info.IsDir() {
		kind = "directory"
	}

	return TextResult(fmt.Sprintf(
		"path:     %s\ntype:     %s\nsize:     %d bytes\nperm:     %s\nmodified: %s",
		path, kind, info.Size(), info.Mode(), info.ModTime().Format("2006-01-02 15:04:05"),
	)), nil
}

func (m *filesystemModule) handleSearch(params map[string]interface{}) (*ToolResult, error) {
	root := getString(params, "root")
	pattern := getString(params, "pattern")
	content := getString(params, "content")
	maxDepth := getInt(params, "depth")
	if maxDepth == 0 {
		maxDepth = 10
	}

	var results []string
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if depth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if pattern != "" {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); !matched {
				return nil
			}
		}
		if content != "" {
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), content) {
				return nil
			}
		}
		results = append(results, path)
		return nil
	})

	if len(results) == 0 {
		return TextResult("no results"), nil
	}
	return TextResult(fmt.Sprintf("%d results:\n%s", len(results), strings.Join(results, "\n"))), nil
}

func (m *filesystemModule) checkPath(path string) error {
	if m.cfg == nil {
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, blocked := range m.cfg.Security.BlockedPaths {
		ba, _ := filepath.Abs(blocked)
		if strings.HasPrefix(absPath, ba) {
			return fmt.Errorf("path blocked: %s", path)
		}
	}
	if len(m.cfg.Security.AllowedPaths) > 0 {
		allowed := false
		for _, ap := range m.cfg.Security.AllowedPaths {
			aa, _ := filepath.Abs(ap)
			if strings.HasPrefix(absPath, aa) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("path not in allowed list: %s", path)
		}
	}
	return nil
}
