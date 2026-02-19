package uwu

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"uwu.cpp/config"

	"github.com/shirou/gopsutil/v3/process"
)

type processModule struct{ cfg *config.Config }

func newProcessModule(cfg *config.Config) Module   { return &processModule{cfg: cfg} }
func (m *processModule) Name() string              { return "process" }
func (m *processModule) Description() string       { return "open, kill, list processes and applications" }
func (m *processModule) SupportedOS() []string     { return nil }
func (m *processModule) Shutdown() error           { return nil }
func (m *processModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *processModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "proc_list",
			Description: "List running processes",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"filter": schemaStr("filter by name (case-insensitive)"),
				"limit":  schemaNum("max results (default 50)"),
			}),
			Handler: m.handleList,
		},
		{
			Name:        "proc_open",
			Description: "Launch an application or file",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"app":    schemaStr("application name or path"),
				"args":   schemaAny("array of arguments"),
				"detach": schemaBool("run in background (default true)"),
			}, "app"),
			Handler: m.handleOpen,
		},
		{
			Name:        "proc_kill",
			Description: "Kill a process by PID or name",
			Module:      m.Name(),
			Dangerous:   true,
			InputSchema: jsonSchema(map[string]interface{}{
				"pid":   schemaNum("process PID"),
				"name":  schemaStr("process name (kills all matches)"),
				"force": schemaBool("force kill (SIGKILL instead of SIGTERM)"),
			}),
			Handler: m.handleKill,
		},
		{
			Name:        "proc_info",
			Description: "Get detailed info about a process",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"pid": schemaNum("process PID"),
			}, "pid"),
			Handler: m.handleInfo,
		},
		{
			Name:        "proc_windows",
			Description: "List open application windows",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleWindows,
		},
	}
}

func (m *processModule) handleList(params map[string]interface{}) (*ToolResult, error) {
	filter := strings.ToLower(getString(params, "filter"))
	limit := getInt(params, "limit")
	if limit == 0 {
		limit = 50
	}

	procs, err := process.Processes()
	if err != nil {
		return ErrorResult(err), nil
	}

	type row struct {
		pid  int32
		name string
		cpu  float64
		mem  float32
	}
	var rows []row
	for _, p := range procs {
		name, _ := p.Name()
		if filter != "" && !strings.Contains(strings.ToLower(name), filter) {
			continue
		}
		cpu, _ := p.CPUPercent()
		mem, _ := p.MemoryPercent()
		rows = append(rows, row{p.Pid, name, cpu, mem})
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}

	lines := []string{fmt.Sprintf("%-8s  %-30s  %8s  %8s", "PID", "NAME", "CPU%", "MEM%")}
	lines = append(lines, strings.Repeat("-", 60))
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("%-8d  %-30s  %7.1f%%  %7.1f%%", r.pid, r.name, r.cpu, r.mem))
	}

	return TextResult(fmt.Sprintf("processes: %d/%d shown\n\n%s", len(rows), len(procs), strings.Join(lines, "\n"))), nil
}

func (m *processModule) handleOpen(params map[string]interface{}) (*ToolResult, error) {
	app := getString(params, "app")
	detach := true
	if v, ok := params["detach"].(bool); ok {
		detach = v
	}

	var args []string
	if raw, ok := params["args"].([]interface{}); ok {
		for _, a := range raw {
			args = append(args, fmt.Sprintf("%v", a))
		}
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", append([]string{"/c", "start", "", app}, args...)...)
	case "darwin":
		if len(args) > 0 {
			cmd = exec.Command("open", append([]string{app, "--args"}, args...)...)
		} else {
			cmd = exec.Command("open", app)
		}
	default:
		cmd = exec.Command(app, args...)
	}

	if detach {
		if err := cmd.Start(); err != nil {
			return ErrorResult(fmt.Errorf("launch %s: %w", app, err)), nil
		}
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		return TextResult(fmt.Sprintf("launched %s (pid %d)", app, pid)), nil
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return ErrorResult(fmt.Errorf("%w\noutput: %s", err, string(out))), nil
	}
	return TextResult(fmt.Sprintf("exited: %s\n\n%s", app, string(out))), nil
}

func (m *processModule) handleKill(params map[string]interface{}) (*ToolResult, error) {
	pid := getInt(params, "pid")
	name := getString(params, "name")
	force := getBool(params, "force")

	if pid == 0 && name == "" {
		return ErrorResult(fmt.Errorf("provide pid or name")), nil
	}

	var killed []string

	if pid != 0 {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return ErrorResult(fmt.Errorf("pid %d not found: %w", pid, err)), nil
		}
		if force {
			p.Kill()
		} else {
			p.Terminate()
		}
		killed = append(killed, strconv.Itoa(pid))
	}

	if name != "" {
		procs, _ := process.Processes()
		for _, p := range procs {
			pname, _ := p.Name()
			if strings.Contains(strings.ToLower(pname), strings.ToLower(name)) {
				if force {
					p.Kill()
				} else {
					p.Terminate()
				}
				killed = append(killed, fmt.Sprintf("%d(%s)", p.Pid, pname))
			}
		}
	}

	if len(killed) == 0 {
		return TextResult("no matching processes found"), nil
	}
	action := "terminated"
	if force {
		action = "killed"
	}
	return TextResult(fmt.Sprintf("%s: %s", action, strings.Join(killed, ", "))), nil
}

func (m *processModule) handleInfo(params map[string]interface{}) (*ToolResult, error) {
	pid := getInt(params, "pid")
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return ErrorResult(fmt.Errorf("pid %d not found: %w", pid, err)), nil
	}

	name, _ := p.Name()
	cmdline, _ := p.Cmdline()
	cpu, _ := p.CPUPercent()
	mem, _ := p.MemoryPercent()
	memInfo, _ := p.MemoryInfo()
	status, _ := p.Status()
	ppid, _ := p.Ppid()
	username, _ := p.Username()
	numThreads, _ := p.NumThreads()

	rss, vms := uint64(0), uint64(0)
	if memInfo != nil {
		rss = memInfo.RSS / 1024 / 1024
		vms = memInfo.VMS / 1024 / 1024
	}

	return TextResult(fmt.Sprintf(
		"pid:      %d\nname:     %s\nuser:     %s\nppid:     %d\nstatus:   %s\ncpu:      %.2f%%\nrss:      %d MB\nvms:      %d MB\nmem:      %.2f%%\nthreads:  %d\ncmd:      %s",
		pid, name, username, ppid, strings.Join(status, ","),
		cpu, rss, vms, mem, numThreads, cmdline,
	)), nil
}

func (m *processModule) handleWindows(params map[string]interface{}) (*ToolResult, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("powershell", "-Command",
			"Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object Id,ProcessName,MainWindowTitle | Format-Table -Auto")
	case "linux":
		cmd = exec.Command("wmctrl", "-l")
	default:
		return TextResult("window listing not supported on this OS"), nil
	}
	out, err := cmd.Output()
	if err != nil {
		return ErrorResult(fmt.Errorf("list windows: %w", err)), nil
	}
	return TextResult(string(out)), nil
}
