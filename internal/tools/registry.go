// Package tools provides the tool registry and execution framework.
package tools

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CircuitBreaker tracks tool failures and can temporarily block failing tools
type CircuitBreaker struct {
	mu           sync.RWMutex
	failures     map[string]int
	lastFailure  map[string]time.Time
	failLimit    int
	recoveryTime time.Duration
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failLimit int, recoverySeconds int) *CircuitBreaker {
	return &CircuitBreaker{
		failures:     make(map[string]int),
		lastFailure:  make(map[string]time.Time),
		failLimit:    failLimit,
		recoveryTime: time.Duration(recoverySeconds) * time.Second,
	}
}

// RecordFailure records a failure for a tool
func (cb *CircuitBreaker) RecordFailure(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName]++
	cb.lastFailure[toolName] = time.Now()
}

// RecordSuccess records a success for a tool (resets failures)
func (cb *CircuitBreaker) RecordSuccess(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName] = 0
}

// IsOpen checks if the circuit is open (blocked) for a tool
func (cb *CircuitBreaker) IsOpen(toolName string) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	failCount, exists := cb.failures[toolName]
	if !exists || failCount < cb.failLimit {
		return false
	}

	// Check if recovery time has passed
	if lastFail, ok := cb.lastFailure[toolName]; ok {
		if time.Since(lastFail) > cb.recoveryTime {
			return false // Allow retry after recovery time
		}
	}

	return true
}

// GetRecoveryTime returns seconds until circuit closes (for UI)
func (cb *CircuitBreaker) GetRecoveryTime(toolName string) int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if lastFail, ok := cb.lastFailure[toolName]; ok {
		remaining := cb.recoveryTime - time.Since(lastFail)
		if remaining > 0 {
			return int(remaining.Seconds())
		}
	}
	return 0
}

// Reset clears all circuit breaker state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = make(map[string]int)
	cb.lastFailure = make(map[string]time.Time)
}

// Tool represents a registered tool that the agent can call.
type Tool struct {
	Name        string
	Description string
	Parameters  []Parameter
	Execute     func(args map[string]string) (Result, error)
}

// Parameter describes a tool parameter.
type Parameter struct {
	Name        string
	Description string
	Required    bool
}

// Result is the output of a tool execution.
type Result struct {
	Output   string         `json:"output"`
	Error    string         `json:"error,omitempty"`
	Success  bool           `json:"success"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Registry holds all registered tools.
type Registry struct {
	mu             sync.RWMutex
	tools          map[string]*Tool
	circuitBreaker *CircuitBreaker
	scanContextID  string // ID of the ScanContext this registry belongs to
}

// NewRegistry creates a new tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools:          make(map[string]*Tool),
		circuitBreaker: NewCircuitBreaker(5, 60), // 5 failures, 60s recovery
	}
}

// SetScanContextID associates this registry with a ScanContext.
// Tools can then use scanctx.Get(id) to access session-scoped state.
func (r *Registry) SetScanContextID(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanContextID = id
}

// GetScanContextID returns the associated ScanContext ID.
func (r *Registry) GetScanContextID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scanContextID
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns all registered tool names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// Execute runs a tool by name with the given arguments.
func (r *Registry) Execute(name string, args map[string]string) (Result, error) {
	// Check circuit breaker
	if r.circuitBreaker.IsOpen(name) {
		recoveryTime := r.circuitBreaker.GetRecoveryTime(name)
		return Result{
			Error:   fmt.Sprintf("Circuit breaker OPEN for '%s' — too many failures. Try again in %d seconds.", name, recoveryTime),
			Success: false,
		}, nil
	}

	tool, ok := r.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("unknown tool: %s", name)
	}

	// Map _raw fallback to first required parameter if needed
	if raw, hasRaw := args["_raw"]; hasRaw {
		for _, p := range tool.Parameters {
			if p.Required {
				if _, exists := args[p.Name]; !exists {
					args[p.Name] = raw
				}
			}
		}
		delete(args, "_raw")
	}

	// Validate required parameters
	for _, p := range tool.Parameters {
		if p.Required {
			if v, exists := args[p.Name]; !exists || strings.TrimSpace(v) == "" {
				return Result{}, fmt.Errorf("missing required parameter '%s' for tool '%s'", p.Name, name)
			}
		}
	}

	result, err := tool.Execute(args)
	if err != nil {
		// Record failure in circuit breaker
		r.circuitBreaker.RecordFailure(name)
		return Result{
			Output:  "",
			Error:   err.Error(),
			Success: false,
		}, nil
	}

	// Record success - reset failure count
	r.circuitBreaker.RecordSuccess(name)
	result.Success = true
	return result, nil
}

// GetCircuitBreaker returns the circuit breaker for external access
func (r *Registry) GetCircuitBreaker() *CircuitBreaker {
	return r.circuitBreaker
}

// SchemaXML generates XML schema for all tools (for the system prompt).
func (r *Registry) SchemaXML() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	xml := "<tools>\n"
	for _, t := range r.tools {
		xml += fmt.Sprintf("  <tool name=\"%s\">\n", t.Name)
		xml += fmt.Sprintf("    <description>%s</description>\n", t.Description)
		if len(t.Parameters) > 0 {
			xml += "    <parameters>\n"
			for _, p := range t.Parameters {
				req := ""
				if p.Required {
					req = " required=\"true\""
				}
				xml += fmt.Sprintf("      <parameter name=\"%s\"%s>%s</parameter>\n",
					p.Name, req, p.Description)
			}
			xml += "    </parameters>\n"
		}
		xml += "  </tool>\n"
	}
	xml += "</tools>\n"
	return xml
}
