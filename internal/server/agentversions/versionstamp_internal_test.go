package agentversions

import (
	"bytes"
	"strings"
	"testing"
)

// containsVersion reads in chunks, so the interesting case is a version string
// that straddles the boundary between two of them: a scan that forgot to carry
// the tail of one chunk into the next would miss it and reject a build that
// was stamped perfectly well. It gets a direct test because Upload's own tests
// can only ever feed it bodies far shorter than one chunk.
func TestContainsVersion(t *testing.T) {
	cases := map[string]struct {
		body    []byte
		version string
		want    bool
	}{
		"stamped": {
			body: []byte("\x00\x00some rodata 1.2.3 and more"), version: "1.2.3", want: true,
		},
		"not stamped": {
			body: []byte("a binary that was built without the stamp"), version: "1.2.3", want: false,
		},
		"empty body": {
			body: nil, version: "1.2.3", want: false,
		},
		"straddling a chunk boundary": {
			body:    append(bytes.Repeat([]byte("x"), scanChunk-2), []byte("1.2.3 trailing")...),
			version: "1.2.3", want: true,
		},
		"at the very end": {
			body: []byte("padding then 1.2.3"), version: "1.2.3", want: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := containsVersion(bytes.NewReader(tc.body), tc.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("containsVersion = %v, want %v", got, tc.want)
			}
		})
	}
}

// A version longer than a chunk would make the overlap arithmetic nonsense.
// Nothing can produce one -- the column is far shorter -- but the scan should
// not quietly answer "not stamped" if something ever did.
func TestContainsVersionWithAnAbsurdlyLongVersion(t *testing.T) {
	version := strings.Repeat("9", scanChunk+1)
	got, err := containsVersion(strings.NewReader("anything"), version)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Error("a version that cannot fit in a chunk cannot be found in one")
	}
}
