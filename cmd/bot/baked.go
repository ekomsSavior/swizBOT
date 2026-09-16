package main

import (
	"os"

	"github.com/saviorSEC/swizBOT/internal/bakepack"
)

// bakedBundle is injected at build time by cmd/build as a single opaque
// token (see internal/bakepack). It is empty in a plain `go build`.
var bakedBundle string

// baked holds the decoded baked config values. It is always non-nil so
// callers can index it without a nil check; empty when nothing was baked.
var baked map[string]string

// bakedNote carries a human-readable decode status for main to log once the
// logger is up (a sealed bundle with a missing/wrong SWIZ_UNLOCK must not be
// a silent failure, and must not be fatal).
var bakedNote string

func init() {
	baked = map[string]string{}
	if bakedBundle == "" {
		return
	}
	vals, err := bakepack.Unpack(bakedBundle, os.Getenv("SWIZ_UNLOCK"))
	if err != nil {
		bakedNote = "baked config not loaded: " + err.Error()
		return
	}
	baked = vals
}

// bakedOf returns a baked value ("" when absent).
func bakedOf(key string) string { return baked[key] }
