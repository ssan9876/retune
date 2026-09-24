//go:build !windows && !darwin

package facts

import "runtime"

func osVersion() string    { return runtime.GOOS }
func uptimeSeconds() int64 { return 0 }
