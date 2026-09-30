package scanner

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// repoCheckout is one repository target's prepared working tree, or why it
// could not be prepared. Each target is cloned once per assessment run and
// shared by all of its source scanners.
type repoCheckout struct {
	dir    string
	reason string
}

func repositoryCheckoutDir(scanDir, targetID string) string {
	return filepath.Join(scanDir, "source", stableJobPath(targetID), "checkout")
}

// prepareRepositoryCheckout returns the local path a repository target's
// source scanners read, cloning it on first use. The returned reason is
// operator-facing and never contains the token.
func prepareRepositoryCheckout(ctx context.Context, scanDir, targetID, repoURL string, cred RepoCredential, cache map[string]repoCheckout) (string, string) {
	if c, ok := cache[targetID]; ok {
		return c.dir, c.reason
	}
	dir, reason := cloneRepositoryTarget(ctx, repositoryCheckoutDir(scanDir, targetID), repoURL, cred)
	cache[targetID] = repoCheckout{dir: dir, reason: reason}
	return dir, reason
}

// cloneRepositoryTarget shallow-clones one HTTPS repository. A token is handed
// to git as an Authorization header scoped to the repository host through
// GIT_CONFIG_* environment variables, so it never appears in argv, the remote
// URL, the checkout's .git/config, or scanner output.
func cloneRepositoryTarget(ctx context.Context, dir, repoURL string, cred RepoCredential) (string, string) {
	raw := strings.TrimSpace(repoURL)
	u, err := url.Parse(raw)
	if err != nil || strings.ContainsAny(raw, " \t\r\n,") || strings.ToLower(u.Scheme) != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "repository must be a single HTTPS clone URL"
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return dir, "" // resumed assessment: reuse the earlier checkout
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return "", "repository checkout directory could not be created"
	}
	_ = os.RemoveAll(dir) // drop a partial clone left by an interrupted run
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--", u.String(), dir)
	// Never block on an interactive username/password prompt.
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never")
	token := strings.TrimSpace(cred.Token)
	if token != "" {
		user := strings.TrimSpace(cred.Username)
		if user == "" {
			user = "x-access-token"
		}
		basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http."+strings.ToLower(u.Scheme)+"://"+u.Host+"/.extraheader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
		)
	}
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	if err := cmd.Run(); err != nil {
		_ = os.RemoveAll(dir)
		return "", cloneFailureReason(stderr.String(), token != "", cctx.Err())
	}
	return dir, ""
}

// cloneFailureReason maps git's stderr to a fixed, secret-free explanation.
func cloneFailureReason(stderr string, hadToken bool, ctxErr error) string {
	if ctxErr != nil {
		return "repository clone timed out"
	}
	low := strings.ToLower(stderr)
	switch {
	case strings.Contains(low, "repository not found"), strings.Contains(low, "could not read username"),
		strings.Contains(low, "authentication failed"), strings.Contains(low, "invalid username or token"),
		strings.Contains(low, "returned error: 401"), strings.Contains(low, "returned error: 403"):
		if hadToken {
			return "repository clone was refused: the access token cannot read this repository (check its scope and repository access)"
		}
		return "repository clone was refused: the repository is private or does not exist; add a read-only access token"
	case strings.Contains(low, "could not resolve host"), strings.Contains(low, "unable to access"):
		return "repository host is unreachable from the scanner"
	}
	return "repository clone failed"
}

// limitedWriter keeps the first n bytes and discards the rest, so a noisy
// clone cannot grow memory without bound.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		chunk := p
		if len(chunk) > l.n {
			chunk = chunk[:l.n]
		}
		written, err := l.w.Write(chunk)
		l.n -= written
		if err != nil {
			return len(p), nil
		}
	}
	return len(p), nil
}
