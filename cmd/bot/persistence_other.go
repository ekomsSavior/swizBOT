//go:build !windows

package main

import "errors"

// ensurePersistence is a no-op on non-Windows builds.
func ensurePersistence() error { return errors.New("persistence is Windows-only") }

func removePersistence() {}
