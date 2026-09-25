// internal/scanner/classify_test.go
package scanner

import (
	"reflect"
	"slices"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		ev   HostEvidence
		want []Track
	}{
		{"live url only", HostEvidence{LiveURLs: []string{"http://x"}}, []Track{TrackWeb}},
		{"tls flag", HostEvidence{TLS: true}, []Track{TrackWeb}},
		{"std web port", HostEvidence{OpenPorts: []Port{{Number: 443, Service: "https"}}}, []Track{TrackWeb}},
		{"http on nonstandard port", HostEvidence{OpenPorts: []Port{{Number: 3000, Service: "http"}}}, []Track{TrackWeb}},
		{"ssh only", HostEvidence{OpenPorts: []Port{{Number: 22, Service: "ssh"}}}, []Track{TrackServer}},
		{"web plus ssh", HostEvidence{OpenPorts: []Port{{Number: 80, Service: "http"}, {Number: 22, Service: "ssh"}}}, []Track{TrackWeb, TrackServer}},
		{"live url plus db", HostEvidence{LiveURLs: []string{"http://x"}, OpenPorts: []Port{{Number: 5432, Service: "postgresql"}}}, []Track{TrackWeb, TrackServer}},
		{"nothing", HostEvidence{}, nil},
	}
	for _, c := range cases {
		if got := Classify(c.ev); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Classify = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEffectiveTracksFailsOpen(t *testing.T) {
	if got := EffectiveTracks(HostEvidence{}); !slices.Equal(got, []Track{TrackWeb, TrackServer}) {
		t.Fatalf("no evidence must fail open to both tracks, got %v", got)
	}
	ev := HostEvidence{OpenPorts: []Port{{Number: 22, Protocol: "tcp", Service: "ssh"}}}
	if got := EffectiveTracks(ev); !slices.Equal(got, []Track{TrackServer}) {
		t.Fatalf("classified evidence must pass through, got %v", got)
	}
}
