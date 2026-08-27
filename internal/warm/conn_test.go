package warm

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// TestIsCallerTimeout pins the second, independent classification the pool
// needs alongside the Classifier's Kind: whether a failed Execute was driven
// by a caller context error. A context error (bare or wrapped to any depth)
// answers true; anything else answers false. It moved here with isCallerTimeout
// when the retry/reap machinery was hoisted out of transport/winrm into warm —
// warm now owns the function, so it owns its coverage.
func TestIsCallerTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare context.DeadlineExceeded", context.DeadlineExceeded, true},
		{"bare context.Canceled", context.Canceled, true},
		{"wrapped deadline (prepare pipeline: %w)", fmt.Errorf("prepare pipeline: %w", context.DeadlineExceeded), true},
		{"wrapped cancellation (prepare pipeline: %w)", fmt.Errorf("prepare pipeline: %w", context.Canceled), true},
		{"unrelated error", errors.New("nope"), false},
	}
	for _, tc := range cases {
		if got := isCallerTimeout(tc.err); got != tc.want {
			t.Errorf("%s: isCallerTimeout = %v, want %v", tc.name, got, tc.want)
		}
	}
}
