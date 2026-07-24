package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// GenerateServiceConfig generates and optionally installs a service config
// for the current OS.
func GenerateServiceConfig(secretID string, install bool) error {
	switch runtime.GOOS {
	case "linux":
		return generateSystemd(secretID, install)
	case "darwin":
		return generateLaunchd(secretID, install)
	case "windows":
		return generateWindows(secretID, install)
	default:
		return fmt.Errorf("unsupported OS: %s. Run 'sikkerkey agent start --secret %s' manually.", runtime.GOOS, secretID)
	}
}

func sikkerKeyBinary() string {
	path, err := exec.LookPath("sikkerkey")
	if err != nil {
		path, _ = os.Executable()
	}
	return path
}

func currentUser() string {
	// Prefer SUDO_USER (original user when running under sudo)
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "root"
}

func currentHome() string {
	// When running under sudo, resolve the original user's home
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		if h := os.Getenv("SUDO_HOME"); h != "" {
			return h
		}
		// Fall back to /home/<user>
		return "/home/" + sudoUser
	}
	h, _ := os.UserHomeDir()
	return h
}

// ── systemd (Linux) ──

func generateSystemd(secretID string, install bool) error {
	user := currentUser()
	binary := sikkerKeyBinary()
	home := currentHome()
	serviceName := fmt.Sprintf("sikkerkey-agent-%s", secretID)

	unit := fmt.Sprintf(`[Unit]
Description=SikkerKey Agent for %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
ExecStart=%s agent start --secret %s
Restart=on-failure
RestartSec=10
Environment=HOME=%s
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`, secretID, user, binary, secretID, home, home)

	if !install {
		fmt.Println(unit)
		fmt.Printf("# Save to: /etc/systemd/system/%s.service\n", serviceName)
		fmt.Printf("# Then run:\n")
		fmt.Printf("#   sudo systemctl daemon-reload\n")
		fmt.Printf("#   sudo systemctl enable --now %s\n", serviceName)
		return nil
	}

	path := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.WriteFile(path, []byte(unit), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w (try with sudo)", path, err)
	}

	fmt.Printf("Service file written to %s\n", path)

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", serviceName).Run(); err != nil {
		return fmt.Errorf("systemctl enable failed: %w", err)
	}

	fmt.Printf("Service %s installed and started.\n", serviceName)
	fmt.Printf("  Status: sudo systemctl status %s\n", serviceName)
	fmt.Printf("  Logs:   sudo journalctl -u %s -f\n", serviceName)
	fmt.Printf("  Stop:   sudo systemctl stop %s\n", serviceName)
	return nil
}

// ── launchd (macOS) ──

func generateLaunchd(secretID string, install bool) error {
	binary := sikkerKeyBinary()
	home, _ := os.UserHomeDir()
	label := fmt.Sprintf("com.sikkerkey.agent.%s", secretID)
	logPath := filepath.Join(home, ".sikkerkey", "agents", secretID+".log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>agent</string>
        <string>start</string>
        <string>--secret</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>%s</string>
    </dict>
</dict>
</plist>
`, label, binary, secretID, logPath, logPath, home)

	if !install {
		fmt.Println(plist)
		fmt.Printf("# Save to: ~/Library/LaunchAgents/%s.plist\n", label)
		fmt.Printf("# Then run: launchctl load ~/Library/LaunchAgents/%s.plist\n", label)
		return nil
	}

	dir := filepath.Join(home, "Library", "LaunchAgents")
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, label+".plist")

	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	fmt.Printf("Plist written to %s\n", path)

	if err := exec.Command("launchctl", "load", path).Run(); err != nil {
		return fmt.Errorf("launchctl load failed: %w", err)
	}

	fmt.Printf("Agent loaded via launchd.\n")
	fmt.Printf("  Stop:   launchctl unload %s\n", path)
	fmt.Printf("  Logs:   tail -f %s\n", logPath)
	return nil
}

// ── Windows (NSSM / sc) ──

func generateWindows(secretID string, install bool) error {
	binary := sikkerKeyBinary()
	serviceName := fmt.Sprintf("SikkerKeyAgent_%s", strings.ReplaceAll(secretID, "-", "_"))

	// Check for NSSM first (preferred)
	_, nssmErr := exec.LookPath("nssm")

	if nssmErr == nil {
		cmd := fmt.Sprintf(`nssm install %s "%s" agent start --secret %s
nssm set %s AppDirectory "%s"
nssm set %s DisplayName "SikkerKey Agent (%s)"
nssm set %s Description "SikkerKey sync agent for secret %s"
nssm set %s Start SERVICE_AUTO_START
nssm start %s`, serviceName, binary, secretID,
			serviceName, filepath.Dir(binary),
			serviceName, secretID,
			serviceName, secretID,
			serviceName,
			serviceName)

		if !install {
			fmt.Println("# Using NSSM (recommended):")
			fmt.Println(cmd)
			return nil
		}

		for _, line := range strings.Split(cmd, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if err := exec.Command(parts[0], parts[1:]...).Run(); err != nil {
				return fmt.Errorf("failed: %s: %w", line, err)
			}
		}
		fmt.Printf("Service %s installed and started via NSSM.\n", serviceName)
		fmt.Printf("  Stop:   nssm stop %s\n", serviceName)
		fmt.Printf("  Remove: nssm remove %s confirm\n", serviceName)
		return nil
	}

	// Fallback: sc.exe
	scCmd := fmt.Sprintf(`sc create %s binPath= "\"%s\" agent start --secret %s" start= auto DisplayName= "SikkerKey Agent (%s)"
sc start %s`, serviceName, binary, secretID, secretID, serviceName)

	if !install {
		fmt.Println("# Using sc.exe:")
		fmt.Println(scCmd)
		fmt.Println()
		fmt.Println("# For better service management, install NSSM: https://nssm.cc")
		return nil
	}

	fmt.Println("Automatic install via sc.exe is not recommended.")
	fmt.Println("Install NSSM (https://nssm.cc) and re-run, or use the commands below:")
	fmt.Println()
	fmt.Println(scCmd)
	return nil
}
