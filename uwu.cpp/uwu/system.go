package uwu

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"uwu.cpp/config"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type systemModule struct{ cfg *config.Config }

func newSystemModule(cfg *config.Config) Module      { return &systemModule{cfg: cfg} }
func (m *systemModule) Name() string                { return "system" }
func (m *systemModule) Description() string         { return "CPU, RAM, disk, network, OS info" }
func (m *systemModule) SupportedOS() []string       { return nil }
func (m *systemModule) Shutdown() error             { return nil }
func (m *systemModule) Init(cfg *config.Config) error { m.cfg = cfg; return nil }

func (m *systemModule) Tools() []*Tool {
	return []*Tool{
		{
			Name:        "sys_info",
			Description: "System overview: OS, CPU, RAM, disk",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleInfo,
		},
		{
			Name:        "sys_cpu",
			Description: "CPU usage and frequency",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"per_core": schemaBool("show per-core usage"),
				"interval": schemaNum("sampling interval in seconds (default 1)"),
			}),
			Handler: m.handleCPU,
		},
		{
			Name:        "sys_memory",
			Description: "RAM and swap usage",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleMemory,
		},
		{
			Name:        "sys_disk",
			Description: "Disk usage for all partitions or a specific path",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"path": schemaStr("specific mount point to check"),
			}),
			Handler: m.handleDisk,
		},
		{
			Name:        "sys_network",
			Description: "Network interfaces and optional connection list",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{
				"connections": schemaBool("include active connections"),
			}),
			Handler: m.handleNetwork,
		},
		{
			Name:        "sys_uptime",
			Description: "System uptime and boot time",
			Module:      m.Name(),
			InputSchema: jsonSchema(map[string]interface{}{}),
			Handler:     m.handleUptime,
		},
	}
}

func (m *systemModule) handleInfo(_ map[string]interface{}) (*ToolResult, error) {
	hi, _ := host.Info()
	vm, _ := mem.VirtualMemory()
	cpus, _ := cpu.Info()
	d, _ := disk.Usage("/")

	cpuModel := "unknown"
	if len(cpus) > 0 {
		cpuModel = cpus[0].ModelName
	}
	ramGB := uint64(0)
	if vm != nil {
		ramGB = vm.Total / 1024 / 1024 / 1024
	}
	diskGB := uint64(0)
	if d != nil {
		diskGB = d.Total / 1024 / 1024 / 1024
	}
	osInfo, kernel, arch := "unknown", "unknown", runtime.GOARCH
	if hi != nil {
		osInfo = fmt.Sprintf("%s %s (%s)", hi.OS, hi.PlatformVersion, hi.Platform)
		kernel = hi.KernelVersion
		arch = hi.KernelArch
	}

	return TextResult(fmt.Sprintf(
		"os:        %s\nkernel:    %s\narch:      %s\ncpu:       %s\ncores:     %d\nram:       %d GB\ndisk (/):  %d GB\ngo:        %s",
		osInfo, kernel, arch, cpuModel, runtime.NumCPU(), ramGB, diskGB, runtime.Version(),
	)), nil
}

func (m *systemModule) handleCPU(params map[string]interface{}) (*ToolResult, error) {
	perCore := getBool(params, "per_core")
	interval := getInt(params, "interval")
	if interval == 0 {
		interval = 1
	}

	pcts, err := cpu.Percent(time.Duration(interval)*time.Second, perCore)
	if err != nil {
		return ErrorResult(err), nil
	}
	infos, _ := cpu.Info()
	freq := 0.0
	if len(infos) > 0 {
		freq = infos[0].Mhz
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("cores: %d  freq: %.0f MHz  sample: %ds", runtime.NumCPU(), freq, interval))

	if perCore {
		for i, p := range pcts {
			lines = append(lines, fmt.Sprintf("core %2d  [%-20s] %.1f%%", i, bar(p, 20), p))
		}
	} else {
		lines = append(lines, fmt.Sprintf("total    [%-30s] %.1f%%", bar(pcts[0], 30), pcts[0]))
	}

	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *systemModule) handleMemory(_ map[string]interface{}) (*ToolResult, error) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return ErrorResult(err), nil
	}
	sw, _ := mem.SwapMemory()

	lines := []string{
		fmt.Sprintf("ram   total: %-10s used: %-10s avail: %-10s  %.1f%%  [%s]",
			fmtBytes(vm.Total), fmtBytes(vm.Used), fmtBytes(vm.Available),
			vm.UsedPercent, bar(vm.UsedPercent, 20)),
	}
	if sw != nil && sw.Total > 0 {
		lines = append(lines, fmt.Sprintf("swap  total: %-10s used: %-10s              %.1f%%  [%s]",
			fmtBytes(sw.Total), fmtBytes(sw.Used),
			sw.UsedPercent, bar(sw.UsedPercent, 20)))
	}

	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *systemModule) handleDisk(params map[string]interface{}) (*ToolResult, error) {
	specificPath := getString(params, "path")

	lines := []string{fmt.Sprintf("%-20s  %10s  %10s  %10s  %6s", "mount", "total", "used", "free", "use%")}

	if specificPath != "" {
		u, err := disk.Usage(specificPath)
		if err != nil {
			return ErrorResult(err), nil
		}
		lines = append(lines, fmt.Sprintf("%-20s  %10s  %10s  %10s  %5.1f%%",
			specificPath, fmtBytes(u.Total), fmtBytes(u.Used), fmtBytes(u.Free), u.UsedPercent))
	} else {
		parts, err := disk.Partitions(false)
		if err != nil {
			return ErrorResult(err), nil
		}
		for _, p := range parts {
			u, err := disk.Usage(p.Mountpoint)
			if err != nil {
				continue
			}
			lines = append(lines, fmt.Sprintf("%-20s  %10s  %10s  %10s  %5.1f%%",
				p.Mountpoint, fmtBytes(u.Total), fmtBytes(u.Used), fmtBytes(u.Free), u.UsedPercent))
		}
	}

	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *systemModule) handleNetwork(params map[string]interface{}) (*ToolResult, error) {
	showConns := getBool(params, "connections")

	ifaces, err := net.Interfaces()
	if err != nil {
		return ErrorResult(err), nil
	}

	var lines []string
	lines = append(lines, "interfaces:")
	for _, iface := range ifaces {
		isUp := false
		for _, f := range iface.Flags {
			if f == "up" {
				isUp = true
				break
			}
		}
		if !isUp {
			continue
		}
		var addrs []string
		for _, a := range iface.Addrs {
			addrs = append(addrs, a.Addr)
		}
		lines = append(lines, fmt.Sprintf("  %-12s %s", iface.Name, strings.Join(addrs, ", ")))
	}

	stats, _ := net.IOCounters(true)
	if len(stats) > 0 {
		lines = append(lines, "\nio counters:")
		for _, s := range stats {
			if s.BytesSent == 0 && s.BytesRecv == 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf("  %-12s  tx: %s  rx: %s",
				s.Name, fmtBytes(s.BytesSent), fmtBytes(s.BytesRecv)))
		}
	}

	if showConns {
		conns, err := net.Connections("all")
		if err == nil {
			lines = append(lines, fmt.Sprintf("\nconnections: %d", len(conns)))
			for i, c := range conns {
				if i >= 20 {
					lines = append(lines, "  ...")
					break
				}
				lines = append(lines, fmt.Sprintf("  [%-12s] %s:%d -> %s:%d",
					c.Status, c.Laddr.IP, c.Laddr.Port, c.Raddr.IP, c.Raddr.Port))
			}
		}
	}

	return TextResult(strings.Join(lines, "\n")), nil
}

func (m *systemModule) handleUptime(_ map[string]interface{}) (*ToolResult, error) {
	uptime, err := host.Uptime()
	if err != nil {
		return ErrorResult(err), nil
	}
	boot, _ := host.BootTime()

	d := time.Duration(uptime) * time.Second
	return TextResult(fmt.Sprintf("uptime: %dd %dh %dm\nboot:   %s\nnow:    %s",
		int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60,
		time.Unix(int64(boot), 0).Format("2006-01-02 15:04:05"),
		time.Now().Format("2006-01-02 15:04:05"),
	)), nil
}

func fmtBytes(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func bar(pct float64, w int) string {
	n := int(pct / 100.0 * float64(w))
	if n > w {
		n = w
	}
	return strings.Repeat("#", n) + strings.Repeat(".", w-n)
}
