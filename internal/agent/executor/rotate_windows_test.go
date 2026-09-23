//go:build windows

package executor

import (
	"context"
	"testing"
)

// TestBuiltinAdminOnThisMachine only looks the account up; it changes
// nothing.
func TestBuiltinAdminOnThisMachine(t *testing.T) {
	name, err := LocalAccounts{}.BuiltinAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		t.Fatal("no name for RID 500")
	}
	t.Logf("the built-in Administrator is %q", name)
}
