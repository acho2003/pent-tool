package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthMonitorPreservesInterruptedExecution(t *testing.T) {
	for _, mode := range []string{"deadline", "finished", "active-error", "active-rotation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan struct{})
			result := make(chan error, 1)
			canceled := false
			req := Request{TargetAuth: "Authorization: initial", AuthRefresh: func(context.Context, []string) ([]string, error) {
				close(entered)
				<-release
				if mode == "active-rotation" {
					return []string{"Authorization: rotated"}, nil
				}
				return nil, errors.New("verification interrupted")
			}}
			go monitorCommandAuthWithInterval(ctx, req, func() { canceled = true }, done, result, time.Millisecond)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("verifier did not start")
			}
			switch mode {
			case "deadline":
				stop()
			case "finished":
				close(done)
			}
			close(release)
			select {
			case err := <-result:
				interrupted := mode == "deadline" || mode == "finished"
				if interrupted && (err != nil || canceled) {
					t.Fatalf("interrupted verifier became auth failure: %v canceled=%v", err, canceled)
				}
				if !interrupted && (err == nil || !canceled) {
					t.Fatalf("active auth failure was ignored: %v canceled=%v", err, canceled)
				}
			case <-time.After(time.Second):
				t.Fatal("monitor did not stop")
			}
		})
	}
}
