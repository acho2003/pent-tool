package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type envSettingDefinition struct {
	Key             string   `json:"key"`
	Label           string   `json:"label"`
	Category        string   `json:"category"`
	Description     string   `json:"description"`
	DefaultValue    string   `json:"defaultValue,omitempty"`
	Placeholder     string   `json:"placeholder,omitempty"`
	InputType       string   `json:"inputType"`
	Options         []string `json:"options,omitempty"`
	Sensitive       bool     `json:"sensitive"`
	RequiresRestart bool     `json:"requiresRestart"`
}

type envSettingValue struct {
	envSettingDefinition
	Value    string `json:"value"`
	HasValue bool   `json:"hasValue"`
}

type environmentSettingsResponse struct {
	EnvFile         string            `json:"envFile"`
	Variables       []envSettingValue `json:"variables"`
	RestartRequired bool              `json:"restartRequired,omitempty"`
}

var envSettingKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func allEnvSettingDefinitions() []envSettingDefinition {
	return []envSettingDefinition{
		{Key: "XALGORIX_NUCLEI_PATH", Label: "Nuclei path", Category: "Scanners", Description: "Nuclei executable path.", DefaultValue: "nuclei", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_TRIVY_PATH", Label: "Trivy path", Category: "Scanners", Description: "Trivy executable path.", DefaultValue: "trivy", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_VULS_PATH", Label: "Vuls path", Category: "Scanners", Description: "Vuls executable path.", DefaultValue: "vuls", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_VULS_SSH_CONFIG", Label: "Vuls SSH config", Category: "Scanners", Description: "Operator-managed SSH config used to resolve Vuls aliases. Private key material is not stored in scan records.", Placeholder: "~/.ssh/config", InputType: "path", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_ZAP_URL", Label: "ZAP API URL", Category: "Scanners", Description: "Internal authenticated OWASP ZAP API endpoint.", Placeholder: "http://zap:8080", InputType: "url", RequiresRestart: true},
		{Key: "XALGORIX_ZAP_API_KEY", Label: "ZAP API key", Category: "Scanners", Description: "API key for the internal ZAP service.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_GVM_HOST", Label: "GMP host", Category: "Scanners", Description: "Greenbone GMP host.", Placeholder: "gvmd", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_GVM_PORT", Label: "GMP port", Category: "Scanners", Description: "Greenbone GMP TCP port.", DefaultValue: "9390", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_GVM_USERNAME", Label: "GMP username", Category: "Scanners", Description: "Greenbone GMP username.", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_GVM_PASSWORD", Label: "GMP password", Category: "Scanners", Description: "Greenbone GMP password.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_SCANNER_MAX_OUTPUT_BYTES", Label: "Scanner output bytes", Category: "Scanners", Description: "Per-scanner raw output cap. Truncation is recorded on the scanner run.", DefaultValue: "104857600", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_NUCLEI_TIMEOUT_SECONDS", Label: "Nuclei timeout", Category: "Scanners", Description: "Nuclei attempt timeout in seconds.", DefaultValue: "3600", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_ZAP_TIMEOUT_SECONDS", Label: "ZAP timeout", Category: "Scanners", Description: "ZAP attempt timeout in seconds.", DefaultValue: "7200", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_OPENVAS_TIMEOUT_SECONDS", Label: "OpenVAS timeout", Category: "Scanners", Description: "OpenVAS attempt timeout in seconds.", DefaultValue: "14400", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_TRIVY_TIMEOUT_SECONDS", Label: "Trivy timeout", Category: "Scanners", Description: "Trivy attempt timeout in seconds.", DefaultValue: "3600", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_VULS_TIMEOUT_SECONDS", Label: "Vuls timeout", Category: "Scanners", Description: "Vuls attempt timeout in seconds.", DefaultValue: "3600", InputType: "number", RequiresRestart: true},

		{Key: "XALGORIX_TARGET_AUTH", Label: "Target auth", Category: "Runtime", Description: "Authenticated target headers applied deterministically to web scanners. One 'Header-Name: value' per line or separated by ';'.", Placeholder: "Cookie: session=...; Authorization: Bearer ...", InputType: "text", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_SCAN_HEADERS", Label: "Scan headers", Category: "Runtime", Description: "Attribution headers added to target-facing scanner traffic. Never attached to Report AI APIs, notifications, or the dashboard.", Placeholder: "X-Bug-Bounty: handle; X-Scan-ID: engagement-42", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_HEADERS_FILE", Label: "Scan headers file", Category: "Runtime", Description: "Path to a file of scan/attribution headers, one 'Name: value' per line ('#' comments and blank lines ignored). Merged with XALGORIX_SCAN_HEADERS; the inline value wins on a name clash.", Placeholder: "/path/to/scan-headers.txt", InputType: "path", RequiresRestart: true},

		{Key: "XALGORIX_DISCORD_WEBHOOK", Label: "Discord webhook", Category: "Notifications", Description: "Global Discord webhook used when a scan does not provide its own.", Placeholder: "https://discord.com/api/webhooks/...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_DISCORD_MIN_SEVERITY", Label: "Discord minimum severity", Category: "Notifications", Description: "Minimum severity sent to Discord.", InputType: "select", Options: []string{"", "info", "low", "medium", "high", "critical"}},

		{Key: "XALGORIX_TELEGRAM_BOT_TOKEN", Label: "Telegram bot token", Category: "Notifications", Description: "Bot token from @BotFather. Required to enable Telegram notifications.", Placeholder: "123456789:ABC-DEF...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_TELEGRAM_CHAT_ID", Label: "Telegram chat ID", Category: "Notifications", Description: "Target chat/channel ID. Numeric ID (e.g. -1001234567890) or @channelusername.", Placeholder: "-1001234567890", InputType: "text"},
		{Key: "XALGORIX_TELEGRAM_MIN_SEVERITY", Label: "Telegram minimum severity", Category: "Notifications", Description: "Minimum severity sent to Telegram.", InputType: "select", Options: []string{"", "info", "low", "medium", "high", "critical"}},

		{Key: "XALGORIX_RATE_LIMIT_REQUESTS", Label: "Rate-limit requests", Category: "Rate limits", Description: "Requests allowed per dashboard rate-limit window.", DefaultValue: "60", InputType: "number"},
		{Key: "XALGORIX_RATE_LIMIT_WINDOW", Label: "Rate-limit window", Category: "Rate limits", Description: "Rate-limit window in seconds.", DefaultValue: "60", InputType: "number"},
		{Key: "XALGORIX_RATE_RPS", Label: "Outbound RPS", Category: "Rate limits", Description: "Sustained per-domain outbound request rate.", DefaultValue: "10", InputType: "number"},
		{Key: "XALGORIX_RATE_BURST", Label: "Outbound burst", Category: "Rate limits", Description: "Per-domain outbound burst size.", DefaultValue: "20", InputType: "number"},

		{Key: "XALGORIX_USE_PROXY", Label: "Use proxy", Category: "Proxy", Description: "Enable proxy routing for outbound traffic.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_PROXY_URL", Label: "Proxy URL", Category: "Proxy", Description: "Single proxy URL. Overrides proxy file when set.", Placeholder: "socks5://user:pass@127.0.0.1:1080", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_PROXY_FILE", Label: "Proxy file", Category: "Proxy", Description: "Path to a file with one proxy per line.", Placeholder: "/path/to/proxies.txt", InputType: "path"},
		{Key: "XALGORIX_PROXY_ROTATION", Label: "Proxy rotation", Category: "Proxy", Description: "Proxy rotation strategy.", DefaultValue: "roundrobin", InputType: "select", Options: []string{"roundrobin", "random"}},
		{Key: "XALGORIX_TLS_SKIP_VERIFY", Label: "Skip TLS verification", Category: "Proxy", Description: "Allow insecure TLS verification for proxied/testing traffic.", DefaultValue: "false", InputType: "boolean"},

		{Key: "XALGORIX_WORKSPACE", Label: "Workspace", Category: "Runtime", Description: "Workspace root for scan execution.", InputType: "path", RequiresRestart: true},
		{Key: "XALGORIX_ALLOW_ABSOLUTE_FILEEDIT", Label: "Allow absolute file edits", Category: "Runtime", Description: "Allow file-edit tooling to write absolute paths.", DefaultValue: "false", InputType: "boolean"},

		{Key: "XALGORIX_USERNAME", Label: "Dashboard username", Category: "Security", Description: "Dashboard login username.", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD", Label: "Dashboard password", Category: "Security", Description: "Plaintext dashboard password. Prefer XALGORIX_PASSWORD_HASH.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD_HASH", Label: "Dashboard password hash", Category: "Security", Description: "Bcrypt dashboard password hash.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_BIND", Label: "Bind address", Category: "Security", Description: "Web server listen address.", DefaultValue: "127.0.0.1", Placeholder: "127.0.0.1", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_ALLOW_LOCAL_TARGETS", Label: "Allow local targets", Category: "Security", Description: "Permit scanning locally-hosted apps (localhost / 127.0.0.1 / private IPs) — for self-hosted demo/staging on the same box. The dashboard's own listener is always protected. Leave OFF on shared/hosted deployments.", DefaultValue: "false", InputType: "boolean"},

		{Key: "CAIDO_PORT", Label: "Caido port", Category: "Integrations", Description: "Caido proxy port. 0 means auto-detect.", DefaultValue: "0", InputType: "number"},
		{Key: "CAIDO_API_TOKEN", Label: "Caido API token", Category: "Integrations", Description: "Caido API token for proxy integration.", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_TELEMETRY", Label: "Telemetry", Category: "Integrations", Description: "Enable OpenTelemetry export.", DefaultValue: "true", InputType: "boolean"},
		{Key: "XALGORIX_OTEL_ENDPOINT", Label: "OTel endpoint", Category: "Integrations", Description: "OpenTelemetry collector endpoint.", InputType: "url"},

		{Key: "XALGORIX_CPU_CAUTION_PCT", Label: "CPU caution percent", Category: "Resources", Description: "CPU load caution threshold.", DefaultValue: "70", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_CPU_CRITICAL_PCT", Label: "CPU critical percent", Category: "Resources", Description: "CPU load critical threshold.", DefaultValue: "90", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_RAM_CAUTION_MB", Label: "RAM caution MB", Category: "Resources", Description: "Available RAM caution threshold.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_RAM_CRITICAL_MB", Label: "RAM critical MB", Category: "Resources", Description: "Available RAM critical threshold.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_DISK_CAUTION_MB", Label: "Disk caution MB", Category: "Resources", Description: "Free disk caution threshold.", DefaultValue: "2048", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_DISK_CRITICAL_MB", Label: "Disk critical MB", Category: "Resources", Description: "Free disk critical threshold.", DefaultValue: "1024", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_MAX_INSTANCES", Label: "Max instances", Category: "Resources", Description: "Manual maximum concurrent scan instances.", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_CPU_LOAD", Label: "Heavy tool CPU load", Category: "Resources", Description: "Expected CPU load per heavy terminal tool. Empty means auto-scale from CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_MEMORY_BUDGET_MB", Label: "Scan memory budget MB", Category: "Resources", Description: "Memory budget per active scan. Empty means auto-scale from RAM and CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_OVERHEAD_MB", Label: "Scan overhead MB", Category: "Resources", Description: "Reserved memory overhead per scan. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", Label: "Heavy tool memory limit MB", Category: "Resources", Description: "Optional hard address-space limit for heavy terminal tools. Empty or 0 leaves hard limiting disabled; dynamic admission still uses live RAM headroom.", Placeholder: "disabled", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_GO_MEM_LIMIT_MB", Label: "Go memory limit MB", Category: "Resources", Description: "Soft memory limit for the Xalgorix parent process. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
	}
}

func envDefinitionByKey() map[string]envSettingDefinition {
	defs := allEnvSettingDefinitions()
	out := make(map[string]envSettingDefinition, len(defs))
	for _, def := range defs {
		out[def.Key] = def
	}
	for _, def := range hiddenLegacyEnvSettingDefinitions() {
		out[def.Key] = def
	}
	return out
}

func hiddenLegacyEnvSettingDefinitions() []envSettingDefinition {
	return []envSettingDefinition{}
}

func (s *Server) handleEnvironmentSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.environmentSettings(false))
	case http.MethodPost:
		var req struct {
			Values map[string]string `json:"values"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		restartRequired, err := s.applyEnvironmentUpdates(req.Values)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(s.environmentSettings(restartRequired))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) environmentSettings(restartRequired bool) environmentSettingsResponse {
	defs := allEnvSettingDefinitions()
	values := make([]envSettingValue, 0, len(defs))
	for _, def := range defs {
		value := s.envSettingValue(def.Key)
		hasValue := os.Getenv(def.Key) != ""
		if def.Sensitive {
			value = maskSecretValue(value)
		}
		values = append(values, envSettingValue{
			envSettingDefinition: def,
			Value:                value,
			HasValue:             hasValue,
		})
	}
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Category != values[j].Category {
			return values[i].Category < values[j].Category
		}
		return values[i].Key < values[j].Key
	})
	return environmentSettingsResponse{
		EnvFile:         xalgorixEnvFilePath(),
		Variables:       values,
		RestartRequired: restartRequired,
	}
}

func (s *Server) applyEnvironmentUpdates(values map[string]string) (bool, error) {
	if len(values) == 0 {
		return false, nil
	}
	defs := envDefinitionByKey()
	effective := make(map[string]string, len(values))
	restartRequired := false

	for key, value := range values {
		key = strings.TrimSpace(key)
		if !envSettingKeyRe.MatchString(key) {
			return false, fmt.Errorf("invalid environment variable name %q", key)
		}
		def, ok := defs[key]
		if !ok {
			return false, fmt.Errorf("unsupported environment variable %q", key)
		}
		if def.Sensitive && isMaskedSettingValue(value) {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.ContainsAny(value, "\r\n") {
			return false, fmt.Errorf("%s cannot contain newlines", key)
		}
		normalized, err := normalizeEnvSettingValue(def, value)
		if err != nil {
			return false, err
		}
		value = normalized
		effective[key] = value
		if def.RequiresRestart {
			restartRequired = true
		}
	}
	if len(effective) == 0 {
		return restartRequired, nil
	}

	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()

	if err := updateXalgorixEnvFile(xalgorixEnvFilePath(), effective); err != nil {
		return false, err
	}
	for key, value := range effective {
		if value == "" {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, value)
		}
	}
	s.applyEnvironmentToRuntimeConfig(effective)
	return restartRequired, nil
}

func (s *Server) applyEnvironmentToRuntimeConfig(values map[string]string) {
	rateChanged := false
	for key, value := range values {
		switch key {
		case "XALGORIX_WORKSPACE":
			if value != "" {
				s.cfg.Workspace = value
			}
		case "XALGORIX_RATE_LIMIT_REQUESTS":
			s.cfg.RateLimitRequests = parseIntSetting(value, 60)
			rateChanged = true
		case "XALGORIX_RATE_LIMIT_WINDOW":
			s.cfg.RateLimitWindow = parseIntSetting(value, 60)
			rateChanged = true
		case "XALGORIX_RATE_RPS":
			s.cfg.RateLimitRPS = parseFloatSetting(value, 10)
		case "XALGORIX_RATE_BURST":
			s.cfg.RateLimitBurst = parseIntSetting(value, 20)
		case "XALGORIX_TLS_SKIP_VERIFY":
			s.cfg.TLSSkipVerify = parseBoolSetting(value, false)
		case "XALGORIX_ALLOW_LOCAL_TARGETS":
			s.cfg.AllowLocalTargets = parseBoolSetting(value, false)
		case "CAIDO_PORT":
			s.cfg.CaidoPort = parseIntSetting(value, 0)
		case "CAIDO_API_TOKEN":
			s.cfg.CaidoAPIToken = value
		case "XALGORIX_TELEMETRY":
			s.cfg.Telemetry = parseBoolSetting(value, true)
		case "XALGORIX_OTEL_ENDPOINT":
			s.cfg.OTelEndpoint = value
		case "XALGORIX_DISCORD_WEBHOOK":
			s.cfg.DiscordWebhook = value
			s.discordWebhook = value
		case "XALGORIX_DISCORD_MIN_SEVERITY":
			s.cfg.DiscordMinSeverity = value
			s.discordMinSeverity = strings.ToLower(strings.TrimSpace(value))
		case "XALGORIX_TELEGRAM_BOT_TOKEN":
			s.cfg.TelegramBotToken = value
			s.telegramBotToken = value
		case "XALGORIX_TELEGRAM_CHAT_ID":
			s.cfg.TelegramChatID = value
			s.telegramChatID = value
		case "XALGORIX_TELEGRAM_MIN_SEVERITY":
			s.cfg.TelegramMinSeverity = value
			s.telegramMinSeverity = strings.ToLower(strings.TrimSpace(value))
		case "XALGORIX_USERNAME":
			s.cfg.Username = value
		case "XALGORIX_PASSWORD":
			s.cfg.Password = value
		case "XALGORIX_PASSWORD_HASH":
			s.cfg.PasswordHash = value
		case "XALGORIX_BIND":
			s.cfg.BindAddr = valueOrDefault(value, "127.0.0.1")
		case "XALGORIX_USE_PROXY":
			s.cfg.UseProxy = parseBoolSetting(value, false)
		case "XALGORIX_PROXY_FILE":
			s.cfg.ProxyFile = value
		case "XALGORIX_PROXY_ROTATION":
			s.cfg.ProxyRotation = valueOrDefault(value, "roundrobin")
		case "XALGORIX_PROXY_URL":
			s.cfg.ProxyURL = value
		}
	}
	if rateChanged {
		requests := clampInt(s.cfg.RateLimitRequests, 1, 1000)
		window := clampInt(s.cfg.RateLimitWindow, 10, 3600)
		s.cfg.RateLimitRequests = requests
		s.cfg.RateLimitWindow = window
		if s.rateLimiter != nil {
			s.rateLimiter.Stop()
		}
		s.rateLimiter = NewRateLimiter(requests, time.Duration(window)*time.Second)
		log.Printf("Rate limiting updated: %d requests/%ds per IP", requests, window)
	}
}

func (s *Server) envSettingValue(key string) string {
	switch key {
	case "XALGORIX_WORKSPACE":
		return s.cfg.Workspace
	case "XALGORIX_RATE_LIMIT_REQUESTS":
		return strconv.Itoa(s.cfg.RateLimitRequests)
	case "XALGORIX_RATE_LIMIT_WINDOW":
		return strconv.Itoa(s.cfg.RateLimitWindow)
	case "XALGORIX_RATE_RPS":
		return strconv.FormatFloat(s.cfg.RateLimitRPS, 'f', -1, 64)
	case "XALGORIX_RATE_BURST":
		return strconv.Itoa(s.cfg.RateLimitBurst)
	case "XALGORIX_TLS_SKIP_VERIFY":
		return strconv.FormatBool(s.cfg.TLSSkipVerify)
	case "XALGORIX_ALLOW_LOCAL_TARGETS":
		return strconv.FormatBool(s.cfg.AllowLocalTargets)
	case "CAIDO_PORT":
		return strconv.Itoa(s.cfg.CaidoPort)
	case "CAIDO_API_TOKEN":
		return s.cfg.CaidoAPIToken
	case "XALGORIX_TELEMETRY":
		return strconv.FormatBool(s.cfg.Telemetry)
	case "XALGORIX_OTEL_ENDPOINT":
		return s.cfg.OTelEndpoint
	case "XALGORIX_DISCORD_WEBHOOK":
		return s.cfg.DiscordWebhook
	case "XALGORIX_DISCORD_MIN_SEVERITY":
		return s.cfg.DiscordMinSeverity
	case "XALGORIX_TELEGRAM_BOT_TOKEN":
		return s.cfg.TelegramBotToken
	case "XALGORIX_TELEGRAM_CHAT_ID":
		return s.cfg.TelegramChatID
	case "XALGORIX_TELEGRAM_MIN_SEVERITY":
		return s.cfg.TelegramMinSeverity
	case "XALGORIX_USERNAME":
		return s.cfg.Username
	case "XALGORIX_PASSWORD":
		return s.cfg.Password
	case "XALGORIX_PASSWORD_HASH":
		return s.cfg.PasswordHash
	case "XALGORIX_BIND":
		return valueOrDefault(s.cfg.BindAddr, "127.0.0.1")
	case "XALGORIX_USE_PROXY":
		return strconv.FormatBool(s.cfg.UseProxy)
	case "XALGORIX_PROXY_FILE":
		return s.cfg.ProxyFile
	case "XALGORIX_PROXY_ROTATION":
		return valueOrDefault(s.cfg.ProxyRotation, "roundrobin")
	case "XALGORIX_PROXY_URL":
		return s.cfg.ProxyURL
	default:
		return os.Getenv(key)
	}
}

func updateXalgorixEnvFile(path string, updates map[string]string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read env file: %w", err)
	}
	lines := []string{}
	if len(existing) > 0 {
		lines = strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	}

	seen := make(map[string]bool, len(updates))
	newLines := make([]string, 0, len(lines)+len(updates)+1)
	for _, line := range lines {
		key, ok := envLineKey(line)
		if !ok {
			newLines = append(newLines, line)
			continue
		}
		value, shouldUpdate := updates[key]
		if !shouldUpdate {
			newLines = append(newLines, line)
			continue
		}
		seen[key] = true
		if value == "" {
			continue
		}
		newLines = append(newLines, formatEnvLine(key, value))
	}

	missing := make([]string, 0, len(updates))
	for key, value := range updates {
		if seen[key] || value == "" {
			continue
		}
		missing = append(missing, key)
	}
	sort.Strings(missing)
	if len(missing) > 0 && len(newLines) > 0 {
		last := strings.TrimSpace(newLines[len(newLines)-1])
		if last != "" {
			newLines = append(newLines, "")
		}
	}
	for _, key := range missing {
		newLines = append(newLines, formatEnvLine(key, updates[key]))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create env dir: %w", err)
	}
	out := strings.TrimRight(strings.Join(newLines, "\n"), "\n")
	if out != "" {
		out += "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		return fmt.Errorf("write env file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod env file: %w", err)
	}
	return nil
}

func envLineKey(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", false
	}
	trimmed = strings.TrimPrefix(trimmed, "export ")
	parts := strings.SplitN(trimmed, "=", 2)
	if len(parts) != 2 {
		return "", false
	}
	key := strings.TrimSpace(parts[0])
	if !envSettingKeyRe.MatchString(key) {
		return "", false
	}
	return key, true
}

func formatEnvLine(key, value string) string {
	return key + "=" + value
}

func xalgorixEnvFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".xalgorix.env")
}

func maskSecretValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 8 {
		return "****" + value[len(value)-8:]
	}
	return "****"
}

func isMaskedSettingValue(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "****") || strings.Contains(value, "••••")
}

func parseIntSetting(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseFloatSetting(value string, fallback float64) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return n
}

func parseBoolSetting(value string, fallback bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func normalizeEnvSettingValue(def envSettingDefinition, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	switch def.InputType {
	case "boolean":
		return strconv.FormatBool(parseBoolSetting(value, false)), nil
	case "select":
		if len(def.Options) > 0 && !oneOf(value, def.Options) {
			return "", fmt.Errorf("invalid value %q for %s", value, def.Key)
		}
	case "number":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return "", fmt.Errorf("%s must be a number", def.Key)
		}
	}
	switch def.Key {
	case "XALGORIX_RATE_LIMIT_REQUESTS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 60), 1, 1000)), nil
	case "XALGORIX_RATE_LIMIT_WINDOW":
		return strconv.Itoa(clampInt(parseIntSetting(value, 60), 10, 3600)), nil
	case "XALGORIX_LLM_MAX_RETRIES":
		return strconv.Itoa(clampInt(parseIntSetting(value, 5), 0, 20)), nil
	case "XALGORIX_MAX_OUTPUT_TOKENS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 8192), 1024, 200000)), nil
	case "XALGORIX_CONTEXT_COMPACT_TOKENS":
		// Negative = auto (window-relative, normalized to -1); 0 disables;
		// positive = explicit absolute budget clamped to a sane range (avoid a
		// tiny value that would compact every turn, or an absurd one).
		ct := parseIntSetting(value, -1)
		if ct < 0 {
			ct = -1
		} else if ct != 0 {
			ct = clampInt(ct, 20000, 2000000)
		}
		return strconv.Itoa(ct), nil
	case "XALGORIX_LLM_CONTEXT_WINDOW":
		return strconv.Itoa(clampInt(parseIntSetting(value, 128000), 8000, 2000000)), nil
	case "XALGORIX_CONTEXT_COMPACT_RATIO":
		r := parseFloatSetting(value, 0.75)
		if r < 0.5 {
			r = 0.5
		} else if r > 0.9 {
			r = 0.9
		}
		return strconv.FormatFloat(r, 'g', -1, 64), nil
	case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
		return strconv.Itoa(clampInt(parseIntSetting(value, 30), 5, 600)), nil
	case "XALGORIX_MAX_ITERATIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 0), 0, 1000)), nil
	case "XALGORIX_MIN_ITERATIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 50), 1, 500)), nil
	case "XALGORIX_MAX_FINISH_REJECTIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 15), 1, 100)), nil
	}
	return value, nil
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func oneOf(value string, values []string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
