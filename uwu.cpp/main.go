package main

import (
	"flag"
	"fmt"
	"os"

	"uwu.cpp/config"
	"uwu.cpp/mcp"
	"uwu.cpp/uwu"
)

func main() {
	var (
		configPath = flag.String("config", "uwu_config.json", "path to config file")
		transport  = flag.String("transport", "stdio", "mcp transport: stdio | http")
		httpAddr   = flag.String("addr", ":8765", "http listen address")
		genConfig  = flag.Bool("init", false, "generate default config file")
		showInfo   = flag.Bool("info", false, "print loaded modules and exit")
	)
	flag.Parse()

	if *genConfig {
		if err := config.GenerateDefault(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("config written to %s\n", *configPath)
		fmt.Println("set your api_key, then run without --init")
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		cfg = config.Default()
	}

	registry := uwu.Boot(cfg)

	if *showInfo {
		registry.PrintInfo()
		return
	}

	srv := mcp.NewServer(cfg, registry)

	switch *transport {
	case "stdio":
		fmt.Fprintf(os.Stderr, "uwu.cpp mcp server | stdio | %d tools\n", registry.ToolCount())
		if err := srv.ServeStdio(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "http":
		fmt.Fprintf(os.Stderr, "uwu.cpp mcp server | http %s | %d tools\n", *httpAddr, registry.ToolCount())
		if err := srv.ServeHTTP(*httpAddr); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown transport: %s\n", *transport)
		os.Exit(1)
	}
}
