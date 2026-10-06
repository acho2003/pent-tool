//go:build !unix

package scanner

import "fmt"

func lockWriteJournal(path string) (func(), error) {
	return nil, fmt.Errorf("durable API write locking is unavailable on this platform")
}
