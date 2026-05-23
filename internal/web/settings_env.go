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

type llmSettingsResponse struct {
	Model                     string `json:"model"`
	APIBase                   string `json:"apiBase"`
	APIKey                    string `json:"apiKey"`
	HasAPIKey                 bool   `json:"hasApiKey"`
	ReasoningEffort           string `json:"reasoningEffort"`
	LLMMaxRetries             int    `json:"llmMaxRetries"`
	MemoryCompressorTimeout   int    `json:"memoryCompressorTimeout"`
	MaxIterations             int    `json:"maxIterations"`
	GeminiAPIKey              string `json:"geminiApiKey"`
	HasGeminiAPIKey           bool   `json:"hasGeminiApiKey"`
	EnvFile                   string `json:"envFile"`
	EnvironmentRestartWarning bool   `json:"environmentRestartWarning"`
}

var envSettingKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func allEnvSettingDefinitions() []envSettingDefinition {
	autoInstallDefault := "false"
	if os.Getuid() == 0 {
		autoInstallDefault = "true"
	}
	return []envSettingDefinition{
		{Key: "XALGORIX_LLM", Label: "LLM model", Category: "LLM", Description: "Default model used by scans and post-scan chat.", Placeholder: "minimax/MiniMax-M2.7", InputType: "text"},
		{Key: "XALGORIX_API_KEY", Label: "LLM API key", Category: "LLM", Description: "Provider API key for the configured model.", Placeholder: "sk-...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_API_BASE", Label: "API base URL", Category: "LLM", Description: "Optional custom provider endpoint. Leave blank to use provider defaults.", Placeholder: "https://api.openai.com/v1", InputType: "url"},
		{Key: "XALGORIX_REASONING_EFFORT", Label: "Reasoning effort", Category: "LLM", Description: "Reasoning depth for providers that support it.", DefaultValue: "high", InputType: "select", Options: []string{"low", "medium", "high", "xhigh"}},
		{Key: "XALGORIX_LLM_MAX_RETRIES", Label: "LLM max retries", Category: "LLM", Description: "Retry count for transient LLM provider failures.", DefaultValue: "5", InputType: "number"},
		{Key: "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT", Label: "Memory compressor timeout", Category: "LLM", Description: "Timeout in seconds for context compression.", DefaultValue: "30", InputType: "number"},
		{Key: "XALGORIX_MAX_ITERATIONS", Label: "Max iterations", Category: "Runtime", Description: "Maximum agent iterations per scan. 0 means unlimited.", DefaultValue: "0", InputType: "number"},
		{Key: "GEMINI_API_KEY", Label: "Gemini web-search key", Category: "LLM", Description: "Optional Gemini key for web search enrichment.", Placeholder: "AIza...", InputType: "secret", Sensitive: true},

		{Key: "XALGORIX_DISCORD_WEBHOOK", Label: "Discord webhook", Category: "Notifications", Description: "Global Discord webhook used when a scan does not provide its own.", Placeholder: "https://discord.com/api/webhooks/...", InputType: "secret", Sensitive: true},
		{Key: "XALGORIX_DISCORD_MIN_SEVERITY", Label: "Discord minimum severity", Category: "Notifications", Description: "Minimum severity sent to Discord.", InputType: "select", Options: []string{"", "info", "low", "medium", "high", "critical"}},

		{Key: "AGENTMAIL_POD", Label: "AgentMail pod", Category: "AgentMail", Description: "AgentMail pod identifier.", Placeholder: "am_us_pod_47", InputType: "text"},
		{Key: "AGENTMAIL_API_KEY", Label: "AgentMail API key", Category: "AgentMail", Description: "AgentMail API key for inbound email triage.", Placeholder: "ak_...", InputType: "secret", Sensitive: true},

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
		{Key: "XALGORIX_DISABLE_BROWSER", Label: "Disable browser", Category: "Runtime", Description: "Disable browser automation tools.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_BROWSER_PATH", Label: "Browser path", Category: "Runtime", Description: "Custom Chrome/Chromium executable path.", InputType: "path"},
		{Key: "XALGORIX_ALLOW_AUTO_INSTALL", Label: "Allow auto-install", Category: "Runtime", Description: "Permit the agent to auto-install missing packages.", DefaultValue: autoInstallDefault, InputType: "boolean"},
		{Key: "XALGORIX_AUTO_INSTALL_SUDO", Label: "Allow sudo auto-install", Category: "Runtime", Description: "Permit sudo-prefixed auto-installs.", DefaultValue: "false", InputType: "boolean"},
		{Key: "XALGORIX_ALLOW_ABSOLUTE_FILEEDIT", Label: "Allow absolute file edits", Category: "Runtime", Description: "Allow file-edit tooling to write absolute paths.", DefaultValue: "false", InputType: "boolean"},

		{Key: "XALGORIX_USERNAME", Label: "Dashboard username", Category: "Security", Description: "Dashboard login username.", InputType: "text", RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD", Label: "Dashboard password", Category: "Security", Description: "Plaintext dashboard password. Prefer XALGORIX_PASSWORD_HASH.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_PASSWORD_HASH", Label: "Dashboard password hash", Category: "Security", Description: "Bcrypt dashboard password hash.", InputType: "secret", Sensitive: true, RequiresRestart: true},
		{Key: "XALGORIX_BIND", Label: "Bind address", Category: "Security", Description: "Web server listen address.", DefaultValue: "127.0.0.1", Placeholder: "127.0.0.1", InputType: "text", RequiresRestart: true},

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
		{Key: "XALGORIX_SCAN_CPU_LOAD", Label: "Scan CPU load", Category: "Resources", Description: "Expected CPU load per active scan. Empty means auto-scale from CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_CPU_LOAD", Label: "Heavy tool CPU load", Category: "Resources", Description: "Expected CPU load per heavy terminal tool. Empty means auto-scale from CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_MEMORY_BUDGET_MB", Label: "Scan memory budget MB", Category: "Resources", Description: "Memory budget per active scan. Empty means auto-scale from RAM and CPU cores.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_SCAN_OVERHEAD_MB", Label: "Scan overhead MB", Category: "Resources", Description: "Reserved memory overhead per scan. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", Label: "Heavy tool memory limit MB", Category: "Resources", Description: "Maximum memory limit for heavy terminal tools. Empty means auto-scale; 0 disables the process memory limit.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
		{Key: "XALGORIX_GO_MEM_LIMIT_MB", Label: "Go memory limit MB", Category: "Resources", Description: "Soft memory limit for the Xalgorix parent process. Empty means auto-scale from RAM.", Placeholder: "auto", InputType: "number", RequiresRestart: true},
	}
}

func envDefinitionByKey() map[string]envSettingDefinition {
	defs := allEnvSettingDefinitions()
	out := make(map[string]envSettingDefinition, len(defs))
	for _, def := range defs {
		out[def.Key] = def
	}
	return out
}

func (s *Server) handleLLMSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.llmSettings())
	case http.MethodPost:
		var req llmSettingsResponse
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		req.LLMMaxRetries = clampInt(req.LLMMaxRetries, 0, 20)
		req.MemoryCompressorTimeout = clampInt(req.MemoryCompressorTimeout, 5, 600)
		req.MaxIterations = clampInt(req.MaxIterations, 0, 1000)
		reasoning := strings.ToLower(strings.TrimSpace(req.ReasoningEffort))
		if reasoning == "" {
			reasoning = "high"
		}
		if !oneOf(reasoning, []string{"low", "medium", "high", "xhigh"}) {
			http.Error(w, "invalid reasoning effort", http.StatusBadRequest)
			return
		}

		updates := map[string]string{
			"XALGORIX_LLM":                       strings.TrimSpace(req.Model),
			"XALGORIX_API_BASE":                  strings.TrimSpace(req.APIBase),
			"XALGORIX_REASONING_EFFORT":          reasoning,
			"XALGORIX_LLM_MAX_RETRIES":           strconv.Itoa(req.LLMMaxRetries),
			"XALGORIX_MEMORY_COMPRESSOR_TIMEOUT": strconv.Itoa(req.MemoryCompressorTimeout),
			"XALGORIX_MAX_ITERATIONS":            strconv.Itoa(req.MaxIterations),
		}
		if !isMaskedSettingValue(req.APIKey) {
			updates["XALGORIX_API_KEY"] = strings.TrimSpace(req.APIKey)
		}
		if !isMaskedSettingValue(req.GeminiAPIKey) {
			updates["GEMINI_API_KEY"] = strings.TrimSpace(req.GeminiAPIKey)
		}
		if _, err := s.applyEnvironmentUpdates(updates); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(s.llmSettings())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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

func (s *Server) llmSettings() llmSettingsResponse {
	return llmSettingsResponse{
		Model:                   s.cfg.LLM,
		APIBase:                 s.cfg.APIBase,
		APIKey:                  maskSecretValue(s.cfg.APIKey),
		HasAPIKey:               s.cfg.APIKey != "",
		ReasoningEffort:         s.cfg.ReasoningEffort,
		LLMMaxRetries:           s.cfg.LLMMaxRetries,
		MemoryCompressorTimeout: s.cfg.MemCompTimeout,
		MaxIterations:           s.cfg.MaxIterations,
		GeminiAPIKey:            maskSecretValue(s.cfg.GeminiAPIKey),
		HasGeminiAPIKey:         s.cfg.GeminiAPIKey != "",
		EnvFile:                 xalgorixEnvFilePath(),
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
		case "XALGORIX_LLM":
			s.cfg.LLM = value
		case "XALGORIX_API_BASE":
			s.cfg.APIBase = value
		case "XALGORIX_API_KEY":
			s.cfg.APIKey = value
		case "XALGORIX_REASONING_EFFORT":
			s.cfg.ReasoningEffort = valueOrDefault(value, "high")
		case "XALGORIX_LLM_MAX_RETRIES":
			s.cfg.LLMMaxRetries = parseIntSetting(value, 5)
		case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
			s.cfg.MemCompTimeout = parseIntSetting(value, 30)
		case "XALGORIX_MAX_ITERATIONS":
			s.cfg.MaxIterations = parseIntSetting(value, 0)
		case "XALGORIX_WORKSPACE":
			if value != "" {
				s.cfg.Workspace = value
			}
		case "XALGORIX_DISABLE_BROWSER":
			s.cfg.DisableBrowser = parseBoolSetting(value, false)
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
		case "CAIDO_PORT":
			s.cfg.CaidoPort = parseIntSetting(value, 0)
		case "CAIDO_API_TOKEN":
			s.cfg.CaidoAPIToken = value
		case "XALGORIX_TELEMETRY":
			s.cfg.Telemetry = parseBoolSetting(value, true)
		case "XALGORIX_OTEL_ENDPOINT":
			s.cfg.OTelEndpoint = value
		case "GEMINI_API_KEY":
			s.cfg.GeminiAPIKey = value
		case "AGENTMAIL_API_KEY":
			s.cfg.AgentMailAPIKey = value
		case "AGENTMAIL_POD":
			s.cfg.AgentMailPod = value
		case "XALGORIX_DISCORD_WEBHOOK":
			s.cfg.DiscordWebhook = value
			s.discordWebhook = value
		case "XALGORIX_DISCORD_MIN_SEVERITY":
			s.cfg.DiscordMinSeverity = value
			s.discordMinSeverity = strings.ToLower(strings.TrimSpace(value))
		case "XALGORIX_USERNAME":
			s.cfg.Username = value
		case "XALGORIX_PASSWORD":
			s.cfg.Password = value
		case "XALGORIX_PASSWORD_HASH":
			s.cfg.PasswordHash = value
		case "XALGORIX_BIND":
			s.cfg.BindAddr = valueOrDefault(value, "127.0.0.1")
		case "XALGORIX_ALLOW_AUTO_INSTALL":
			s.cfg.AllowAutoInstall = parseBoolSetting(value, os.Getuid() == 0)
		case "XALGORIX_AUTO_INSTALL_SUDO":
			s.cfg.AllowAutoInstallSudo = parseBoolSetting(value, false)
		case "XALGORIX_USE_PROXY":
			s.cfg.UseProxy = parseBoolSetting(value, false)
		case "XALGORIX_PROXY_FILE":
			s.cfg.ProxyFile = value
		case "XALGORIX_PROXY_ROTATION":
			s.cfg.ProxyRotation = valueOrDefault(value, "roundrobin")
		case "XALGORIX_PROXY_URL":
			s.cfg.ProxyURL = value
		case "XALGORIX_BROWSER_PATH":
			s.cfg.BrowserPath = value
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
	case "XALGORIX_LLM":
		return s.cfg.LLM
	case "XALGORIX_API_BASE":
		return s.cfg.APIBase
	case "XALGORIX_API_KEY":
		return s.cfg.APIKey
	case "XALGORIX_REASONING_EFFORT":
		return valueOrDefault(s.cfg.ReasoningEffort, "high")
	case "XALGORIX_LLM_MAX_RETRIES":
		return strconv.Itoa(s.cfg.LLMMaxRetries)
	case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
		return strconv.Itoa(s.cfg.MemCompTimeout)
	case "XALGORIX_MAX_ITERATIONS":
		return strconv.Itoa(s.cfg.MaxIterations)
	case "XALGORIX_WORKSPACE":
		return s.cfg.Workspace
	case "XALGORIX_DISABLE_BROWSER":
		return strconv.FormatBool(s.cfg.DisableBrowser)
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
	case "CAIDO_PORT":
		return strconv.Itoa(s.cfg.CaidoPort)
	case "CAIDO_API_TOKEN":
		return s.cfg.CaidoAPIToken
	case "XALGORIX_TELEMETRY":
		return strconv.FormatBool(s.cfg.Telemetry)
	case "XALGORIX_OTEL_ENDPOINT":
		return s.cfg.OTelEndpoint
	case "GEMINI_API_KEY":
		return s.cfg.GeminiAPIKey
	case "AGENTMAIL_API_KEY":
		return s.cfg.AgentMailAPIKey
	case "AGENTMAIL_POD":
		return s.cfg.AgentMailPod
	case "XALGORIX_DISCORD_WEBHOOK":
		return s.cfg.DiscordWebhook
	case "XALGORIX_DISCORD_MIN_SEVERITY":
		return s.cfg.DiscordMinSeverity
	case "XALGORIX_USERNAME":
		return s.cfg.Username
	case "XALGORIX_PASSWORD":
		return s.cfg.Password
	case "XALGORIX_PASSWORD_HASH":
		return s.cfg.PasswordHash
	case "XALGORIX_BIND":
		return valueOrDefault(s.cfg.BindAddr, "127.0.0.1")
	case "XALGORIX_ALLOW_AUTO_INSTALL":
		return strconv.FormatBool(s.cfg.AllowAutoInstall)
	case "XALGORIX_AUTO_INSTALL_SUDO":
		return strconv.FormatBool(s.cfg.AllowAutoInstallSudo)
	case "XALGORIX_USE_PROXY":
		return strconv.FormatBool(s.cfg.UseProxy)
	case "XALGORIX_PROXY_FILE":
		return s.cfg.ProxyFile
	case "XALGORIX_PROXY_ROTATION":
		return valueOrDefault(s.cfg.ProxyRotation, "roundrobin")
	case "XALGORIX_PROXY_URL":
		return s.cfg.ProxyURL
	case "XALGORIX_BROWSER_PATH":
		return s.cfg.BrowserPath
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
	case "XALGORIX_MEMORY_COMPRESSOR_TIMEOUT":
		return strconv.Itoa(clampInt(parseIntSetting(value, 30), 5, 600)), nil
	case "XALGORIX_MAX_ITERATIONS":
		return strconv.Itoa(clampInt(parseIntSetting(value, 0), 0, 1000)), nil
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
