package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/SikkerKeyOfficial/sikkerkey-cli/internal/client"
)

// AgentConfig is stored at ~/.sikkerkey/agents/{secretId}.json
type AgentConfig struct {
	SecretID     string `json:"secretId"`
	ProviderType string `json:"providerType"`
	Connection   Config `json:"connection"`
	PollInterval int    `json:"pollIntervalSeconds,omitempty"` // default 10
}

func agentsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sikkerkey", "agents")
}

func agentConfigPath(secretID string) string {
	return filepath.Join(agentsDir(), secretID+".json")
}

func agentPidPath(secretID string) string {
	return filepath.Join(agentsDir(), secretID+".pid")
}

func agentLogPath(secretID string) string {
	return filepath.Join(agentsDir(), secretID+".log")
}

// SaveConfig writes the agent config to disk.
func SaveConfig(cfg AgentConfig) error {
	if err := os.MkdirAll(agentsDir(), 0700); err != nil {
		return fmt.Errorf("create agents dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(agentConfigPath(cfg.SecretID), data, 0600)
}

// LoadConfig reads the agent config from disk.
func LoadConfig(secretID string) (*AgentConfig, error) {
	data, err := os.ReadFile(agentConfigPath(secretID))
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}
	return &cfg, nil
}

// RunFromServer starts the agent using the two-phase rotate-after-confirm model.
// The agent polls sync config for pending rotations, applies them, verifies, and confirms.
func RunFromServer(c *client.Client, secretID string) error {
	fmt.Printf("Fetching sync config for %s from SikkerKey...\n", secretID)
	syncCfg, err := c.GetSyncConfig(secretID)
	if err != nil {
		return fmt.Errorf("failed to fetch sync config: %w", err)
	}

	provider, err := GetProvider(syncCfg.ProviderType)
	if err != nil {
		return err
	}

	cfg := Config{
		Host:             syncCfg.Connection.Host,
		Port:             syncCfg.Connection.Port,
		Database:         syncCfg.Connection.Database,
		AdminUser:        syncCfg.Connection.AdminUser,
		AdminPass:        syncCfg.Connection.AdminPass,
		ProjectReference: syncCfg.Connection.ProjectReference,
	}

	fmt.Printf("Testing %s connection to %s:%d...\n", provider.DisplayName(), cfg.Host, cfg.Port)
	if err := provider.TestConnection(cfg); err != nil {
		c.SendHeartbeat(secretID, "error", err.Error())
		return fmt.Errorf("connection test failed: %w", err)
	}
	fmt.Println("Connection OK.")
	c.SendHeartbeat(secretID, "healthy", "")

	// Write PID file
	if err := os.MkdirAll(agentsDir(), 0700); err == nil {
		os.WriteFile(agentPidPath(secretID), []byte(strconv.Itoa(os.Getpid())), 0600)
	}
	defer os.Remove(agentPidPath(secretID))

	pollInterval := 10 * time.Second
	if syncCfg.PollIntervalSecs > 0 {
		pollInterval = time.Duration(syncCfg.PollIntervalSecs) * time.Second
	}
	if pollInterval < 5*time.Second {
		pollInterval = 5 * time.Second
	}
	heartbeatInterval := 30 * time.Second

	fmt.Printf("Agent running for secret %s via %s (polling every %s)\n", secretID, provider.DisplayName(), pollInterval)
	fmt.Println("Press Ctrl+C to stop.")

	var lastProcessedRotationId string

	// Handle any pending rotation from a previous agent instance
	if syncCfg.PendingRotationId != "" && syncCfg.PendingValue != "" {
		fmt.Printf("[%s] Found pending rotation on startup. Applying...\n", timestamp())
		handlePendingRotation(c, provider, cfg, secretID, syncCfg.PendingRotationId, syncCfg.PendingValue, syncCfg.ManagedUsername)
		lastProcessedRotationId = syncCfg.PendingRotationId
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Printf("\nAgent stopping for secret %s.\n", secretID)
			return nil

		case <-heartbeatTicker.C:
			c.SendHeartbeat(secretID, "healthy", "")

		case <-pollTicker.C:
			pollCfg, err := c.GetSyncConfig(secretID)
			if err != nil {
				if client.IsTerminalError(err) {
					fmt.Printf("[%s] Secret deleted or access revoked. Agent exiting.\n", timestamp())
					return nil
				}
				c.SendHeartbeat(secretID, "error", "poll failed: "+err.Error())
				fmt.Printf("[%s] ERROR: failed to poll sync config: %s\n", timestamp(), err)
				continue
			}

			if pollCfg.PendingRotationId != "" && pollCfg.PendingValue != "" && pollCfg.PendingRotationId != lastProcessedRotationId {
				handlePendingRotation(c, provider, cfg, secretID, pollCfg.PendingRotationId, pollCfg.PendingValue, pollCfg.ManagedUsername)
				lastProcessedRotationId = pollCfg.PendingRotationId
			}
		}
	}
}

// handlePendingRotation applies a pending rotation, verifies it, and confirms or rejects.
func handlePendingRotation(c *client.Client, provider Provider, cfg Config, secretID, rotationId, pendingValue, managedUsername string) {
	newFields := parseFields(pendingValue)
	username := newFields[cfg.GetUsernameField()]
	password := newFields[cfg.GetPasswordField()]

	if username == "" {
		username = managedUsername
	}

	shortId := rotationId
	if len(shortId) > 8 {
		shortId = shortId[:8]
	}
	fmt.Printf("[%s] Pending rotation detected (id=%s). Applying to %s...\n", timestamp(), shortId, provider.DisplayName())

	// Fetch current live secret for rollback if needed
	currentValue, _ := c.GetSecret(secretID)
	currentFields := parseFields(currentValue)

	// Step 1: Apply the new credentials
	if err := provider.ApplyCredentials(cfg, newFields); err != nil {
		errMsg := fmt.Sprintf("apply failed: %s", err)
		fmt.Printf("[%s] ERROR: %s\n", timestamp(), errMsg)
		c.RejectRotation(secretID, rotationId, errMsg)
		c.SendHeartbeat(secretID, "error", errMsg)
		return
	}

	// Step 2: Verify the new credentials work
	if err := provider.VerifyCredentials(cfg, username, password); err != nil {
		errMsg := fmt.Sprintf("verification failed after apply: %s", err)
		fmt.Printf("[%s] ERROR: %s\n", timestamp(), errMsg)

		// Attempt rollback to the old credentials
		if currentValue != "" {
			fmt.Printf("[%s] Attempting rollback to previous credentials...\n", timestamp())
			if rbErr := provider.ApplyCredentials(cfg, currentFields); rbErr != nil {
				errMsg = fmt.Sprintf("verification failed AND rollback failed: verify=%s, rollback=%s", err, rbErr)
				fmt.Printf("[%s] CRITICAL: rollback also failed: %s\n", timestamp(), rbErr)
			} else {
				fmt.Printf("[%s] Rollback successful — database reverted to previous credentials.\n", timestamp())
			}
		}

		c.RejectRotation(secretID, rotationId, errMsg)
		c.SendHeartbeat(secretID, "error", errMsg)
		return
	}

	// Step 3: Confirm — SikkerKey promotes pending to live
	if err := c.ConfirmRotation(secretID, rotationId); err != nil {
		fmt.Printf("[%s] ERROR: confirm failed: %s (credentials were applied but not promoted)\n", timestamp(), err)
		c.SendHeartbeat(secretID, "error", "confirm failed: "+err.Error())
		return
	}

	c.SendHeartbeat(secretID, "healthy", "")
	fmt.Printf("[%s] Rotation confirmed and promoted.\n", timestamp())
}

// Run starts the agent in the foreground. It polls for version changes
// on the secret and applies new values via the configured provider.
// Blocks until interrupted (SIGINT/SIGTERM).
func Run(c *client.Client, cfg AgentConfig) error {
	provider, err := GetProvider(cfg.ProviderType)
	if err != nil {
		return err
	}

	// Test the connection first
	fmt.Printf("Testing %s connection to %s:%d...\n", provider.DisplayName(), cfg.Connection.Host, cfg.Connection.Port)
	if err := provider.TestConnection(cfg.Connection); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	fmt.Println("Connection OK.")

	// Write PID file
	if err := os.MkdirAll(agentsDir(), 0700); err == nil {
		os.WriteFile(agentPidPath(cfg.SecretID), []byte(strconv.Itoa(os.Getpid())), 0600)
	}
	defer os.Remove(agentPidPath(cfg.SecretID))

	pollInterval := time.Duration(cfg.PollInterval) * time.Second
	if pollInterval < 5*time.Second {
		pollInterval = 10 * time.Second
	}

	fmt.Printf("Agent running for secret %s via %s (polling every %s)\n", cfg.SecretID, provider.DisplayName(), pollInterval)
	fmt.Println("Press Ctrl+C to stop.")

	// Get initial version
	lastVersion := -1
	lastValue := ""

	// Initial fetch
	value, err := c.GetSecret(cfg.SecretID)
	if err != nil {
		return fmt.Errorf("initial secret fetch failed: %w", err)
	}
	lastValue = value
	fmt.Printf("Initial value loaded. Watching for rotations...\n")

	// Apply initial value
	fields := parseFields(value)
	if err := provider.ApplyCredentials(cfg.Connection, fields); err != nil {
		fmt.Printf("WARNING: initial apply failed: %s\n", err)
	} else {
		fmt.Printf("Initial credentials applied to %s.\n", provider.DisplayName())
	}

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Printf("\nAgent stopping for secret %s.\n", cfg.SecretID)
			return nil

		case <-ticker.C:
			value, err := c.GetSecret(cfg.SecretID)
			if err != nil {
				fmt.Printf("[%s] ERROR: failed to fetch secret: %s\n", timestamp(), err)
				continue
			}

			if value == lastValue {
				continue // No change
			}

			// Secret value changed — apply it
			_ = lastVersion
			lastVersion++
			lastValue = value
			fields := parseFields(value)

			fmt.Printf("[%s] Rotation detected. Applying to %s...\n", timestamp(), provider.DisplayName())
			if err := provider.ApplyCredentials(cfg.Connection, fields); err != nil {
				fmt.Printf("[%s] ERROR: failed to apply: %s\n", timestamp(), err)
			} else {
				fmt.Printf("[%s] Credentials applied successfully.\n", timestamp())
			}
		}
	}
}

// ListRunning returns info about running agents by checking PID files.
func ListRunning() []RunningAgent {
	dir := agentsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var result []RunningAgent
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".pid" {
			continue
		}
		secretID := e.Name()[:len(e.Name())-4]

		pidData, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(string(pidData))
		if err != nil {
			continue
		}

		// Check if process is still running
		running := isProcessRunning(pid)

		cfg, _ := LoadConfig(secretID)
		providerType := ""
		host := ""
		if cfg != nil {
			providerType = cfg.ProviderType
			host = fmt.Sprintf("%s:%d", cfg.Connection.Host, cfg.Connection.Port)
		}

		result = append(result, RunningAgent{
			SecretID:     secretID,
			PID:          pid,
			Running:      running,
			ProviderType: providerType,
			Host:         host,
		})
	}
	return result
}

// StopAgent sends SIGTERM to a running agent.
func StopAgent(secretID string) error {
	pidData, err := os.ReadFile(agentPidPath(secretID))
	if err != nil {
		return fmt.Errorf("no agent running for %s", secretID)
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		return fmt.Errorf("invalid PID file for %s", secretID)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(agentPidPath(secretID))
		return fmt.Errorf("process %d not found", pid)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		os.Remove(agentPidPath(secretID))
		return fmt.Errorf("failed to signal process %d: %w", pid, err)
	}

	fmt.Printf("Sent stop signal to agent for %s (PID %d)\n", secretID, pid)
	return nil
}

// RemoveConfig deletes the agent config for a secret.
func RemoveConfig(secretID string) {
	os.Remove(agentConfigPath(secretID))
	os.Remove(agentPidPath(secretID))
}

type RunningAgent struct {
	SecretID     string
	PID          int
	Running      bool
	ProviderType string
	Host         string
}

func parseFields(value string) map[string]string {
	var fields map[string]string
	if json.Unmarshal([]byte(value), &fields) == nil && len(fields) > 0 {
		return fields
	}
	return map[string]string{"value": value}
}

func timestamp() string {
	return time.Now().Format("15:04:05")
}

func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
