package agentversions

import (
	"errors"
	"fmt"
	"testing"

	"retune/internal/server/store"
)

// uploadError is what stands between the transaction inside Upload and the
// error a caller sees. Upload's own tests can only reach it through the
// pre-check's own duplicate detection, which would pass even if this
// function's branch were wrong or inverted — so it gets a direct,
// no-database test instead.
func TestUploadErrorMapsStoreDuplicateToVersionTaken(t *testing.T) {
	if got := uploadError(store.ErrDuplicate); !errors.Is(got, ErrVersionTaken) {
		t.Errorf("uploadError(store.ErrDuplicate) = %v, want ErrVersionTaken", got)
	}

	wrapped := fmt.Errorf("insert failed: %w", store.ErrDuplicate)
	if got := uploadError(wrapped); !errors.Is(got, ErrVersionTaken) {
		t.Errorf("uploadError(wrapped ErrDuplicate) = %v, want ErrVersionTaken", got)
	}

	other := errors.New("connection reset")
	if got := uploadError(other); got != other {
		t.Errorf("uploadError(unrelated) = %v, want the same error unchanged", got)
	}
}
