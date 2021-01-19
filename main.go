package main

import (
	"os"
	"time"

	"github.com/imgk/mitm-proxy/mitm"
)

func main() {
	time.AfterFunc(time.Hour, func() { os.Exit(1) })
	mitm.Run()
}
