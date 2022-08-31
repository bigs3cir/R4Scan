package main

import (
	"fmt"
	"runtime"
)

const VERSION = "1.0"

var (
	buildOS   string
	buildArch string
	buildTime string
)

func version() string {

	return fmt.Sprintf("r4scan v%s\n- os/arch: %s/%s\n- go version: %s\n- date: %s", VERSION, buildOS, buildArch, runtime.Version(), buildTime)
}
