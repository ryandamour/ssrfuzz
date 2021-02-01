package cmd

import (
	"fmt"
	"os"
  "os/signal"
  "context"

	"github.com/spf13/cobra"
)

var mainContext context.Context

var rootCmd = &cobra.Command{
	Use:          "ssrfuzz",
	SilenceUsage: true,
}

func Execute() {
  var cancel context.CancelFunc
  mainContext, cancel = context.WithCancel(context.Background())
  defer cancel()

  signalChan := make(chan os.Signal, 1)
  signal.Notify(signalChan, os.Interrupt)
  defer func() {
    signal.Stop(signalChan)
    cancel()
  }()
  go func() {
    select {
    case <-signalChan:
      // caught CTRL+C
      fmt.Println("\n[!] Keyboard interrupt detected, terminating.")
      cancel()
      os.Exit(1)
    case <-mainContext.Done():
    }
  }()

  if err := rootCmd.Execute(); err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
}


func init() {
  fmt.Printf(`===============================================================
SSRFUZZ v1.0
by Ryan D'Amour @ryandamour 
===============================================================`)
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

